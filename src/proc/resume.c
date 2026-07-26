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
#include "checkpoint.h"

void fdtable_restore(const struct checkpoint_fd *fds, size_t n,
                     const struct checkpoint_header *hdr);
void pt_restore(uint64_t ipa_brk, uint64_t l1_ipa,
                const struct checkpoint_pt_chunk *saved, size_t n);
void vmm_arm64_s2_restore(const struct checkpoint_s2 *saved, size_t n);

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

  if (checkpoint_read(ckpt_fd, &hdr, &regions, &s2, &pt_chunks, &fds,
                      &sigactions) < 0)
    panic("could not read the checkpoint: %s", strerror(errno));
  close(ckpt_fd);

  /* Guest memory, privately: the bytes the parent flushed, diverging from here. */
  void **region_hva = calloc(hdr.nr_regions ? hdr.nr_regions : 1,
                             sizeof *region_hva);
  for (uint32_t i = 0; i < hdr.nr_regions; i++) {
    if (regions[i].arena_off < 0)
      panic("region 0x%llx was never in the arena and cannot be resumed",
            (unsigned long long) regions[i].gaddr);
    region_hva[i] = arena_map_private(regions[i].arena_off, regions[i].size);
  }
  for (uint32_t i = 0; i < hdr.nr_pt_chunks; i++)
    (void) arena_map_private(pt_chunks[i].arena_off, 1);

  vmm_create();

  vmm_arm64_s2_restore(s2, hdr.nr_s2);
  pt_restore(hdr.ipa_brk, hdr.l1_ipa, pt_chunks, hdr.nr_pt_chunks);

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
  }
  free(region_hva);

  /* Process bookkeeping. */
  proc.nr_tasks = 1;
  INIT_LIST_HEAD(&proc.tasks);
  list_add(&task.head, &proc.tasks);
  proc.cred.uid = hdr.uid;
  proc.cred.euid = hdr.euid;
  proc.cred.suid = hdr.suid;
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

  vmm_restore_vcpu(&hdr.vcpu);

  free(regions); free(s2); free(pt_chunks); free(fds); free(sigactions);
}
