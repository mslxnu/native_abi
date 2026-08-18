/*
 * Adopting a checkpoint - the far side of a handover.
 *
 * Split from checkpoint.c on purpose: that file is the wire format, which is
 * data and can be tested on its own, while this is the machinery that rebuilds a
 * live machine out of it and necessarily reaches into the mm, fs and backend
 * layers.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "vmm.h"
#include "mm.h"
#include <sys/mman.h>

#include "arm64/vm.h"
#include "checkpoint.h"

void fdtable_restore(const struct checkpoint_fd *fds, size_t n,
                     const struct checkpoint_header *hdr);
void pt_restore(uint64_t ipa_brk, uint64_t l1_ipa,
                const struct checkpoint_pt_chunk *saved, size_t n);
void vmm_arm64_s2_restore(const struct checkpoint_s2 *saved, size_t n);
gaddr_t pt_ipa_of(gaddr_t va);

/*
 * Adopt a checkpoint: become the guest it describes.
 *
 * Runs in a process that has just exec'd, so it starts from nothing - no VM, no
 * mappings, no tables - and the only things it has are the two descriptors. The
 * order matters and is not arbitrary:
 *
 *   1. the arena, so offsets can become addresses at all;
 *   2. the mappings, taken privately - the resumed guest diverges from the
 *      snapshot exactly as a forked child diverges from its parent;
 *   3. the VM, before anything is mapped into it;
 *   4. stage 2, then the stage-1 allocator that indexes it;
 *   5. the process's own bookkeeping;
 *   6. the vCPU last, because restoring it turns translation on and the tables
 *      it points at have to already be there.
 */
void
checkpoint_restore(int ckpt_fd, int arena_fd)
{
  struct checkpoint_header hdr;
  struct checkpoint_region *regions;
  struct checkpoint_s2 *s2;
  struct checkpoint_pt_chunk *pt_chunks;
  struct checkpoint_fd *fds;
  l_sigaction_t *sigactions;

  arena_adopt(arena_fd);

  char *exe = NULL, *cmdline = NULL;
  if (checkpoint_read(ckpt_fd, &hdr, &regions, &s2, &pt_chunks, &fds,
                      &sigactions, &exe, &cmdline) < 0)
    panic("could not read the checkpoint: %s", strerror(errno));
  close(ckpt_fd);

  /* Guest memory, privately: the bytes the parent flushed, diverging from here. */
  void **region_hva = calloc(hdr.nr_regions ? hdr.nr_regions : 1,
                             sizeof *region_hva);
  for (uint32_t i = 0; i < hdr.nr_regions; i++) {
    if (regions[i].arena_off >= 0) {
      region_hva[i] = arena_map_private(regions[i].arena_off, regions[i].size);
      continue;
    }
    /*
     * Not in the arena: a shared file mapping, whose bytes belong to the file.
     * Re-map it from the descriptor - which came through the exec with
     * everything else - so the resumed guest goes on sharing the file with
     * whoever else has it, which is what MAP_SHARED means and what fork owes a
     * shared mapping.
     */
    /*
     * Neither the arena nor a file: an address-space reservation, which has
     * nothing behind it to re-establish. It needs no host memory and no
     * stage-2 block on this side either - see mm_region::reserved - so it is
     * simply left unbacked, and the mm bookkeeping below marks it as such.
     *
     * The two existing fields already say this without a new one: a region
     * that is neither arena-backed nor file-backed can only be a reservation,
     * which is why this used to be a panic.
     */
    if (regions[i].mm_fd < 0) {
      region_hva[i] = NULL;
      continue;
    }
    region_hva[i] = mmap(NULL, regions[i].size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, regions[i].mm_fd, regions[i].pgoff);
    if (region_hva[i] == MAP_FAILED)
      panic("could not re-map shared file region 0x%llx: %s",
            (unsigned long long) regions[i].gaddr, strerror(errno));
  }
  for (uint32_t i = 0; i < hdr.nr_pt_chunks; i++)
    (void) arena_map_private(pt_chunks[i].arena_off, 1);

  vmm_create();

  vmm_arm64_s2_restore(s2, hdr.nr_s2);
  pt_restore(hdr.ipa_brk, hdr.l1_ipa, pt_chunks, hdr.nr_pt_chunks);

  /*
   * Shared file mappings, now that stage 1 is back and can say which IPA each
   * one was given. Their memory came from the file rather than the arena, so
   * stage 2 could not be replayed for them along with the rest.
   */
  for (uint32_t i = 0; i < hdr.nr_regions; i++) {
    if (regions[i].arena_off >= 0 || region_hva[i] == NULL)
      continue;                /* arena-backed, or a reservation backing nothing */
    /*
     * A page at a time, because a region is no longer one stage-2 block's
     * worth of anything. A block belongs to a host page and is shared by
     * whatever guest pages land in it, so a region's span covers several
     * blocks and may share the ones at its ends with its neighbours. Mapping
     * the whole span in one call asks hv_vm_map for a range that overlaps
     * blocks already established for other regions, and it refuses the lot
     * with a bare HV_ERROR - which killed every resumed child before it had
     * opened a trace sink to say so.
     *
     * The IPA is taken from stage 1 rather than recomputed: the parent
     * decided where each page lives and those descriptors came across intact.
     */
    gaddr_t last_base = (gaddr_t) -1;
    for (size_t off = 0; off < regions[i].size; off += PAGE_SIZEOF(PAGE_4KB)) {
      gaddr_t ipa = pt_ipa_of(regions[i].gaddr + off);
      if (ipa == 0) {
        if (off == 0)
          panic("resuming shared region 0x%llx: no stage-1 mapping",
                (unsigned long long) regions[i].gaddr);
        continue;              /* a hole the guest unmapped; nothing to remap */
      }
      gaddr_t base = ipa & ~(gaddr_t)(STAGE2_GRANULE - 1);
      if (base == last_base)
        continue;
      last_base = base;
      char *hp = (char *) region_hva[i] + off;
      char *block = (char *) ((uintptr_t) hp & ~(uintptr_t)(STAGE2_GRANULE - 1));
      vmm_arm64_map_stage2(base, STAGE2_GRANULE,
                           linux_mprot_to_hv_mflag(regions[i].prot), block);
    }
  }

  /* The mm layer's own view of the same memory. */
  proc.mm = malloc(sizeof *proc.mm);
  init_mm(proc.mm);
  proc.mm->start_brk        = hdr.start_brk;
  proc.mm->current_brk      = hdr.current_brk;
  proc.mm->current_mmap_top = hdr.current_mmap_top;
  for (uint32_t i = 0; i < hdr.nr_regions; i++) {
    struct mm_region *r = record_region(proc.mm, region_hva[i], regions[i].gaddr,
                                        regions[i].size, regions[i].prot,
                                        regions[i].mm_flags, regions[i].mm_fd,
                                        regions[i].pgoff);
    r->arena_off = regions[i].arena_off;
    r->reserved = regions[i].arena_off < 0 && regions[i].mm_fd < 0;
    r->shm_id = regions[i].shm_id;
    r->sealed = regions[i].sealed != 0;
  }
  free(region_hva);

  /* Process bookkeeping. */
  proc.nr_tasks = 1;
  INIT_LIST_HEAD(&proc.tasks);
  list_add(&task.head, &proc.tasks);
  proc.cred.uid = hdr.uid;
  proc.cred.euid = hdr.euid;
  proc.cred.suid = hdr.suid;
  proc.cred.gid = hdr.gid;
  proc.cred.egid = hdr.egid;
  proc.cred.sgid = hdr.sgid;
  proc.cred.fsuid = hdr.fsuid;
  proc.cred.fsgid = hdr.fsgid;
  /* A resumed child is a new host pid wearing its parent's credentials, and
   * nothing else will publish them for it. */
  cred_publish(proc.cred.euid, proc.cred.egid);
  /* The parent-death signal is not inherited; see pdeathsig_clear. */
  pdeathsig_clear();
  memcpy(proc.sigaction, sigactions,
         hdr.nr_sigactions * sizeof proc.sigaction[0]);
  proc.pfutex = kh_init(pfutex);
  pthread_mutex_init(&proc.futex_mutex, NULL);

  task.tid             = hdr.tid;
  task.set_child_tid   = hdr.set_child_tid;
  task.clear_child_tid = hdr.clear_child_tid;
  task.robust_list     = hdr.robust_list;
  task.sigmask.__mask  = hdr.sigmask;
  task.sas.ss_sp       = hdr.sas_sp;
  task.sas.ss_size     = hdr.sas_size;
  task.sas.ss_flags    = hdr.sas_flags;
  INIT_SIGBIT(&task.sigpending);

  fdtable_restore(fds, hdr.nr_fds, &hdr);

  /* The guest's identity, which only this checkpoint could carry: from outside
   * this is a fresh `nabi --resume`, and its own argv says exactly that. */
  proc.ident.exe         = exe;
  proc.ident.cmdline     = cmdline;
  proc.ident.cmdline_len = hdr.cmdline_len;
  /* Host-derived, so it is probed here rather than carried in the checkpoint -
   * but it must be probed, because this process never ran init_fileinfo. */
  init_host_passthrough();
  /* The signalfd table is a static array that starts all-fd-0, and a free slot
   * is fd < 0: without this, init_fileinfo's invalidate never runs here, every
   * slot still names fd 0, and the guest's real stdin is misread as a
   * signalfd. */
  signalfds_init();

  vmm_restore_vcpu(&hdr.vcpu);

  free(regions); free(s2); free(pt_chunks); free(fds); free(sigactions);
}
