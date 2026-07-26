/*
 * Writing and reading a guest handover. See include/checkpoint.h for why this
 * exists and what shape it takes.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "vmm.h"
#include "mm.h"
#include "checkpoint.h"

/* From src/mm/pt_arm64.c and lib/vmm_arm64.c. */
size_t pt_snapshot(uint64_t *ipa_brk_out, uint64_t *l1_ipa_out,
                   struct checkpoint_pt_chunk *out, size_t max);
size_t vmm_arm64_s2_snapshot(struct checkpoint_s2 *out, size_t max);
/* From src/fs/fs.c, where the descriptor tables' internals live. */
size_t fdtable_snapshot(struct checkpoint_fd *out, size_t max,
                        struct checkpoint_header *hdr);

/* write(2) that does not give up early. A short write on a pipe is normal. */
static int
write_all(int fd, const void *buf, size_t len)
{
  const char *p = buf;
  while (len > 0) {
    ssize_t n = write(fd, p, len);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    p += n;
    len -= (size_t) n;
  }
  return 0;
}

static int
read_all(int fd, void *buf, size_t len)
{
  char *p = buf;
  while (len > 0) {
    ssize_t n = read(fd, p, len);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (n == 0) {                 /* truncated checkpoint */
      errno = EPROTO;
      return -1;
    }
    p += n;
    len -= (size_t) n;
  }
  return 0;
}

static size_t
count_regions(void)
{
  size_t n = 0;
  struct list_head *l;
  list_for_each (l, &proc.mm->mm_regions)
    n++;
  return n;
}

int
checkpoint_write(int fd)
{
  size_t nr_regions = count_regions();

  /*
   * Ask the two snapshot sources how much they hold before allocating: both
   * report their true count even when handed a smaller buffer, so a single
   * probe-then-fill avoids guessing a bound.
   */
  size_t nr_s2 = vmm_arm64_s2_snapshot(NULL, 0);
  size_t nr_chunks = pt_snapshot(NULL, NULL, NULL, 0);
  size_t nr_fds = fdtable_snapshot(NULL, 0, NULL);

  struct checkpoint_region *regions = calloc(nr_regions ? nr_regions : 1,
                                             sizeof *regions);
  struct checkpoint_s2 *s2 = calloc(nr_s2 ? nr_s2 : 1, sizeof *s2);
  struct checkpoint_pt_chunk *chunks = calloc(nr_chunks ? nr_chunks : 1,
                                              sizeof *chunks);
  struct checkpoint_fd *fds = calloc(nr_fds ? nr_fds : 1, sizeof *fds);
  if (!regions || !s2 || !chunks || !fds) {
    free(regions); free(s2); free(chunks); free(fds);
    errno = ENOMEM;
    return -1;
  }

  struct checkpoint_header hdr;
  memset(&hdr, 0, sizeof hdr);
  hdr.magic   = CHECKPOINT_MAGIC;
  hdr.version = CHECKPOINT_VERSION;

  vmm_snapshot_vcpu(&hdr.vcpu);

  /*
   * Credentials are NABI's own, not the host's: it tracks a guest uid/euid/suid
   * that Darwin will not let it set freely (see struct cred), so they have to be
   * carried across rather than re-read from the process.
   */
  hdr.uid  = proc.cred.uid;
  hdr.euid = proc.cred.euid;
  hdr.suid = proc.cred.suid;

  hdr.tid             = task.tid;
  hdr.set_child_tid   = task.set_child_tid;
  hdr.clear_child_tid = task.clear_child_tid;
  hdr.robust_list     = task.robust_list;
  hdr.sigmask         = task.sigmask.__mask;
  hdr.sigpending      = atomic_load(&task.sigpending);
  hdr.sas_sp          = task.sas.ss_sp;
  hdr.sas_size        = task.sas.ss_size;
  hdr.sas_flags       = task.sas.ss_flags;

  hdr.start_brk        = proc.mm->start_brk;
  hdr.current_brk      = proc.mm->current_brk;
  hdr.current_mmap_top = proc.mm->current_mmap_top;

  size_t i = 0;
  struct list_head *l;
  list_for_each (l, &proc.mm->mm_regions) {
    struct mm_region *r = list_entry(l, struct mm_region, list);
    regions[i++] = (struct checkpoint_region){
      .gaddr     = r->gaddr,
      .size      = r->size,
      .arena_off = r->arena_off,
      .prot      = r->prot,
      .mm_flags  = r->mm_flags,
      .mm_fd     = r->mm_fd,
      .pgoff     = r->pgoff,
    };
  }

  vmm_arm64_s2_snapshot(s2, nr_s2);
  pt_snapshot(&hdr.ipa_brk, &hdr.l1_ipa, chunks, nr_chunks);
  fdtable_snapshot(fds, nr_fds, &hdr);

  hdr.nr_regions    = (uint32_t) nr_regions;
  hdr.nr_s2         = (uint32_t) nr_s2;
  hdr.nr_pt_chunks  = (uint32_t) nr_chunks;
  hdr.nr_fds        = (uint32_t) nr_fds;
  hdr.nr_sigactions = LINUX_NSIG;

  int rc = -1;
  if (write_all(fd, &hdr, sizeof hdr) == 0 &&
      write_all(fd, regions, nr_regions * sizeof *regions) == 0 &&
      write_all(fd, s2, nr_s2 * sizeof *s2) == 0 &&
      write_all(fd, chunks, nr_chunks * sizeof *chunks) == 0 &&
      write_all(fd, fds, nr_fds * sizeof *fds) == 0 &&
      /* The dispositions are plain data - a handler address in the guest, flags
       * and a mask - so the whole table goes as it stands. */
      write_all(fd, proc.sigaction, LINUX_NSIG * sizeof proc.sigaction[0]) == 0)
    rc = 0;

  free(regions); free(s2); free(chunks); free(fds);
  return rc;
}

int
checkpoint_read(int fd, struct checkpoint_header *hdr,
                struct checkpoint_region **regions_out,
                struct checkpoint_s2 **s2_out,
                struct checkpoint_pt_chunk **chunks_out,
                struct checkpoint_fd **fds_out,
                l_sigaction_t **sigactions_out)
{
  if (read_all(fd, hdr, sizeof *hdr) < 0)
    return -1;

  if (hdr->magic != CHECKPOINT_MAGIC || hdr->version != CHECKPOINT_VERSION) {
    /* Refuse rather than resume a guest from state we may be misreading. */
    errno = EPROTO;
    return -1;
  }

  struct checkpoint_region *regions = calloc(hdr->nr_regions ? hdr->nr_regions : 1,
                                             sizeof *regions);
  struct checkpoint_s2 *s2 = calloc(hdr->nr_s2 ? hdr->nr_s2 : 1, sizeof *s2);
  struct checkpoint_pt_chunk *chunks = calloc(hdr->nr_pt_chunks ? hdr->nr_pt_chunks : 1,
                                              sizeof *chunks);
  struct checkpoint_fd *fds = calloc(hdr->nr_fds ? hdr->nr_fds : 1, sizeof *fds);
  l_sigaction_t *sigactions = calloc(hdr->nr_sigactions ? hdr->nr_sigactions : 1,
                                     sizeof *sigactions);
  if (!regions || !s2 || !chunks || !fds || !sigactions) {
    free(regions); free(s2); free(chunks); free(fds); free(sigactions);
    errno = ENOMEM;
    return -1;
  }

  if (read_all(fd, regions, hdr->nr_regions * sizeof *regions) < 0 ||
      read_all(fd, s2, hdr->nr_s2 * sizeof *s2) < 0 ||
      read_all(fd, chunks, hdr->nr_pt_chunks * sizeof *chunks) < 0 ||
      read_all(fd, fds, hdr->nr_fds * sizeof *fds) < 0 ||
      read_all(fd, sigactions, hdr->nr_sigactions * sizeof *sigactions) < 0) {
    free(regions); free(s2); free(chunks); free(fds); free(sigactions);
    return -1;
  }

  *regions_out = regions;
  *s2_out = s2;
  *chunks_out = chunks;
  *fds_out = fds;
  *sigactions_out = sigactions;
  return 0;
}
