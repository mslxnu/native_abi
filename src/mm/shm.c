/*
 * System V shared memory.
 *
 * A segment is a file in the current IPC namespace's directory, not a Darwin
 * segment; include/sysv.h has the reasoning, of which the short form is that
 * Darwin gives the whole machine 32 segments of 4MB, in tables nabi cannot
 * scope to a namespace, and an attachment to one cannot survive nabi's fork.
 *
 * The last of those was not a limitation but a crash. A resumed child rebuilds
 * its address space from the checkpoint: an arena-backed region is copied and a
 * file-backed one is re-mapped from its descriptor, and a Darwin shmat region
 * was neither, so resume reached "region is neither arena-backed nor
 * file-backed" and panicked. Backing a segment with a file makes an attachment
 * an ordinary shared file mapping, which is the case that machinery was written
 * for - a forked child goes on sharing the segment with its parent, which is
 * the entire point of attaching one before forking.
 */
#include "common.h"
#include "noah.h"
#include "vmm.h"
#include "mm.h"
#include "x86/vm.h"     /* GUEST_MMAP_GRANULE is a page there, a stage-2 granule here */
#include "sysv.h"
#include "linux/common.h"
#include "linux/futex.h"
#include "linux/time.h"
#include "linux/ipc.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/*
 * Linux rounds a segment up to a page and reports the size that was asked for.
 * Here the rounding is to the stage-2 granule, because that is the unit the
 * guest's memory can be mapped in at all.
 */
static size_t
mapped_size(uint64_t segsz)
{
  return roundup(segsz ? segsz : 1, GUEST_MMAP_GRANULE);
}

DEFINE_SYSCALL(shmget, l_key_t, key, size_t, size, int, shmflg)
{
  struct sysv_obj o;
  int id = sysv_get(SYSV_SHM, key, size, shmflg, &o);
  if (id < 0)
    return id;
  sysv_close(&o);
  return id;
}

DEFINE_SYSCALL(shmat, int, shmid, gaddr_t, addr, int, shmflg)
{
  struct sysv_obj o;
  int r = sysv_open(SYSV_SHM, shmid, &o);
  if (r < 0)
    return r;

  bool ro = (shmflg & LINUX_SHM_RDONLY) != 0;
  if (!sysv_perm_ok(o.m, ro ? SYSV_R : (SYSV_R | SYSV_W))) {
    sysv_close(&o);
    return -LINUX_EACCES;
  }

  if (addr != 0) {
    if (shmflg & LINUX_SHM_RND)
      addr &= ~(gaddr_t) (GUEST_MMAP_GRANULE - 1);
    else if (addr & (GUEST_MMAP_GRANULE - 1)) {
      sysv_close(&o);
      return -LINUX_EINVAL;
    }
  }

  size_t len = mapped_size(o.m->size);

  /*
   * The descriptor stays open for as long as the attachment does. It is not
   * bookkeeping: the checkpoint records it, and a resumed child re-maps the
   * segment from that number, so closing it here would leave the child with a
   * region it cannot rebuild.
   */
  int fd = sysv_data_open(SYSV_SHM, shmid, O_RDWR);
  if (fd < 0) {
    sysv_close(&o);
    return fd;
  }

  /*
   * Mapped read-write on the host whatever the guest asked for, and the guest's
   * own permission carried in the stage-2 mapping instead - the same division
   * mmap makes, and for the same reason: the hypervisor will not take a
   * read-only host region, and a later mprotect must not have to re-establish
   * the mapping to grant write.
   */
  void *ptr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (ptr == MAP_FAILED) {
    int e = errno;
    close(fd);
    sysv_close(&o);
    return -darwin_to_linux_errno(e);
  }

  int l_prot = LINUX_PROT_READ | (ro ? 0 : LINUX_PROT_WRITE);

  pthread_rwlock_wrlock(&proc.mm->alloc_lock);
  if (addr == 0)
    addr = alloc_region(len);
  do_munmap(addr, len);
  struct mm_region *reg =
      record_region(proc.mm, ptr, addr, len, l_prot,
                    LINUX_MAP_SHARED | LINUX_MAP_FIXED, fd, 0);
  reg->shm_id = shmid;
  vmm_mmap(addr, len, linux_mprot_to_hv_mflag(l_prot), ptr);
  pthread_rwlock_unlock(&proc.mm->alloc_lock);

  o.m->nattch++;
  o.m->atime = (int64_t) time(NULL);
  o.m->lpid = getpid();
  sysv_close(&o);

  return (uint64_t) addr;
}

/*
 * Detaching does not consult a table of attachments, because the region list is
 * one: a shm attachment is exactly one region, and it carries the id it belongs
 * to. That is also what makes it survive a fork - the regions travel in the
 * checkpoint, so a child can detach what it inherited, which Linux allows and a
 * side table kept in this process could not have described.
 */
DEFINE_SYSCALL(shmdt, gaddr_t, addr)
{
  pthread_rwlock_wrlock(&proc.mm->alloc_lock);
  struct mm_region *reg = find_region(addr, proc.mm);
  if (!reg || reg->gaddr != addr || reg->shm_id < 0) {
    pthread_rwlock_unlock(&proc.mm->alloc_lock);
    return -LINUX_EINVAL;
  }
  int shmid = reg->shm_id;
  size_t len = reg->size;
  do_munmap(addr, len);
  pthread_rwlock_unlock(&proc.mm->alloc_lock);

  struct sysv_obj o;
  if (sysv_open(SYSV_SHM, shmid, &o) == 0) {
    if (o.m->nattch > 0)
      o.m->nattch--;
    o.m->dtime = (int64_t) time(NULL);
    o.m->lpid = getpid();
    sysv_close(&o);
  }
  return 0;
}

static void
fill_shmid_ds(struct l_shmid64_ds *ds, const struct sysv_obj *o)
{
  memset(ds, 0, sizeof *ds);
  ds->shm_perm.key  = o->m->key;
  ds->shm_perm.uid  = o->m->uid;
  ds->shm_perm.gid  = o->m->gid;
  ds->shm_perm.cuid = o->m->cuid;
  ds->shm_perm.cgid = o->m->cgid;
  ds->shm_perm.mode = o->m->mode | (o->m->removed ? LINUX_SHM_DEST : 0);
  ds->shm_segsz     = o->m->size;
  ds->shm_atime     = o->m->atime;
  ds->shm_dtime     = o->m->dtime;
  ds->shm_ctime     = o->m->ctime;
  ds->shm_cpid      = o->m->cpid;
  ds->shm_lpid      = o->m->lpid;
  ds->shm_nattch    = (uint64_t) (o->m->nattch < 0 ? 0 : o->m->nattch);
}

DEFINE_SYSCALL(shmctl, int, shmid, int, cmd, gaddr_t, buf_ptr)
{
  struct sysv_obj o;
  struct l_shmid64_ds ds;
  int r;

  /* The version bit is noise to everything below; glibc always sets it. */
  cmd &= ~LINUX_IPC_64;

  switch (cmd) {
  case LINUX_IPC_INFO: {
    /*
     * The limits a guest is told about are Linux's, because they are now true:
     * a segment is a file, so what bounds it is the filesystem rather than
     * Darwin's 32 slots of 4MB.
     */
    struct l_shminfo64 info;
    memset(&info, 0, sizeof info);
    info.shmmax = (uint64_t) 1 << 40;
    info.shmmin = 1;
    info.shmmni = SYSV_MAX_ID;
    info.shmseg = SYSV_MAX_ID;
    info.shmall = (uint64_t) 1 << 28;
    if (copy_to_user(buf_ptr, &info, sizeof info))
      return -LINUX_EFAULT;
    return SYSV_MAX_ID - 1;
  }

  case LINUX_SHM_INFO: {
    struct l_shm_info info;
    int used, high;
    uint64_t total;
    memset(&info, 0, sizeof info);
    sysv_count(SYSV_SHM, &used, &high, &total);
    info.used_ids = used;
    info.shm_tot  = total / GUEST_MMAP_GRANULE;
    info.shm_rss  = info.shm_tot;
    if (copy_to_user(buf_ptr, &info, sizeof info))
      return -LINUX_EFAULT;
    return high;
  }

  case LINUX_SHM_STAT:
  case LINUX_SHM_STAT_ANY:
    /* ipcs walks indices rather than ids; here they are the same number. */
    if ((r = sysv_open(SYSV_SHM, shmid, &o)) < 0)
      return r;
    if (cmd == LINUX_SHM_STAT && !sysv_perm_ok(o.m, SYSV_R)) {
      sysv_close(&o);
      return -LINUX_EACCES;
    }
    fill_shmid_ds(&ds, &o);
    sysv_close(&o);
    if (copy_to_user(buf_ptr, &ds, sizeof ds))
      return -LINUX_EFAULT;
    return shmid;

  case LINUX_IPC_STAT:
    if ((r = sysv_open(SYSV_SHM, shmid, &o)) < 0)
      return r;
    if (!sysv_perm_ok(o.m, SYSV_R)) {
      sysv_close(&o);
      return -LINUX_EACCES;
    }
    fill_shmid_ds(&ds, &o);
    sysv_close(&o);
    if (copy_to_user(buf_ptr, &ds, sizeof ds))
      return -LINUX_EFAULT;
    return 0;

  case LINUX_IPC_SET:
    if (copy_from_user(&ds, buf_ptr, sizeof ds))
      return -LINUX_EFAULT;
    if ((r = sysv_open(SYSV_SHM, shmid, &o)) < 0)
      return r;
    if (!sysv_owner_ok(o.m)) {
      sysv_close(&o);
      return -LINUX_EPERM;
    }
    o.m->uid   = ds.shm_perm.uid;
    o.m->gid   = ds.shm_perm.gid;
    o.m->mode  = ds.shm_perm.mode & 0777;
    o.m->ctime = (int64_t) time(NULL);
    sysv_close(&o);
    return 0;

  case LINUX_IPC_RMID:
    if ((r = sysv_open(SYSV_SHM, shmid, &o)) < 0)
      return r;
    if (!sysv_owner_ok(o.m)) {
      sysv_close(&o);
      return -LINUX_EPERM;
    }
    r = sysv_remove(SYSV_SHM, shmid, &o);
    sysv_close(&o);
    return r;

  case LINUX_SHM_LOCK:
  case LINUX_SHM_UNLOCK:
    /* There is no swap to lock against here; saying so is the honest no-op. */
    return 0;

  default:
    warnk("shmctl: unimplemented cmd = %d\n", cmd);
    return -LINUX_EINVAL;
  }
}
