/*
 * The guest handover format (src/proc/checkpoint.c).
 *
 * A checkpoint is written by one process and read by another that has just
 * exec'd, so the only thing that can carry state across is what got written to
 * the descriptor. This drives a real fd and checks the reader gets back exactly
 * what the writer put in - and, just as importantly, that a checkpoint which is
 * truncated or from the wrong version is refused rather than half-believed.
 *
 * It fakes the live machine rather than creating a VM: the writer pulls from
 * proc.mm, vmm_snapshot_vcpu and the two snapshot accessors, all of which are
 * stubbed here, so the format itself is what is under test.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
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

static int failures, checks;
#define CHECK(cond, ...)                                                       \
  do {                                                                         \
    checks++;                                                                  \
    if (!(cond)) {                                                             \
      failures++;                                                              \
      printf("  FAIL: "); printf(__VA_ARGS__);                                 \
      printf("\n        (%s:%d: %s)\n", __FILE__, __LINE__, #cond);            \
    }                                                                          \
  } while (0)

void printk(const char *fmt, ...) { (void) fmt; }
void warnk(const char *fmt, ...) { (void) fmt; }
void
panic(const char *fmt, ...)
{
  va_list ap; va_start(ap, fmt);
  printf("  PANIC: "); vprintf(fmt, ap); printf("\n");
  va_end(ap); exit(2);
}

/* ---- the live machine, faked ---- */

struct proc proc;
_Thread_local struct task task;

#define FAKE_S2     3
#define FAKE_CHUNKS 2

void
vmm_snapshot_vcpu(struct vcpu_snapshot *s)
{
  memset(s, 0, sizeof *s);
  for (int i = 0; i <= 30; i++)
    s->x[i] = 0x1000 + i;
  s->sp = 0x7fbfff0000; s->pc = 0x400abc; s->pstate = 0x3c0;
  s->elr_el1 = 0x400def; s->tpidr_el0 = 0xfeed0000;
  s->ttbr0_el1 = 0x40000000;
  s->v[7][3] = 0xEE;
}

size_t
vmm_arm64_s2_snapshot(struct checkpoint_s2 *out, size_t max)
{
  for (size_t i = 0; i < FAKE_S2 && i < max; i++)
    out[i] = (struct checkpoint_s2){ .ipa = 0x40000000 + i * 0x4000,
                                     .arena_off = (int64_t) i * 0x4000,
                                     .prot = 7 };
  return FAKE_S2;
}

size_t
pt_snapshot(uint64_t *ipa_brk_out, uint64_t *l1_ipa_out,
            struct checkpoint_pt_chunk *out, size_t max)
{
  if (ipa_brk_out) *ipa_brk_out = 0x40100000;
  if (l1_ipa_out)  *l1_ipa_out  = 0x40000000;
  for (size_t i = 0; i < FAKE_CHUNKS && i < max; i++)
    out[i] = (struct checkpoint_pt_chunk){ .ipa = 0x40000000 + i * 0x4000,
                                           .arena_off = (int64_t) i * 0x4000,
                                           .used = (uint32_t) i + 1 };
  return FAKE_CHUNKS;
}

#define FAKE_FDS 3

size_t
fdtable_snapshot(struct checkpoint_fd *out, size_t max,
                 struct checkpoint_header *hdr)
{
  if (hdr) {
    hdr->rootfd = 61000;
    hdr->user_start = 0;  hdr->user_size = 64;
    hdr->vkern_start = 61376; hdr->vkern_size = 64;
  }
  /* fd 0 plain, fd 5 close-on-exec, and one vkernel descriptor. */
  struct checkpoint_fd want[FAKE_FDS] = {
    { .table = 0, .index = 0, .host_fd = 0,     .cloexec = 0 },
    { .table = 0, .index = 5, .host_fd = 9,     .cloexec = 1 },
    { .table = 1, .index = 61376, .host_fd = 61000, .cloexec = 0 },
  };
  for (size_t i = 0; i < FAKE_FDS && i < max; i++)
    out[i] = want[i];
  return FAKE_FDS;
}

/* mm.c pieces the writer walks. */
int mm_region_cmp(struct mm_region *a, struct mm_region *b)
{ return a->gaddr < b->gaddr ? -1 : a->gaddr > b->gaddr ? 1 : 0; }
RB_GENERATE(mm_region_tree, mm_region, tree, mm_region_cmp)

int
main(void)
{
  printf("== guest handover format ==\n\n");

  static struct mm mm;
  proc.mm = &mm;
  INIT_LIST_HEAD(&mm.mm_regions);
  RB_INIT(&mm.mm_region_tree);
  mm.start_brk = 0x500000;
  mm.current_brk = 0x510000;
  mm.current_mmap_top = 0xc0400000;

  proc.cred.uid = 501; proc.cred.euid = 0; proc.cred.suid = 0;
  task.tid = 4242;
  task.set_child_tid = 0xc0ffee; task.clear_child_tid = 0xdeadbe;
  task.robust_list = 0xb0b; task.sigmask.__mask = 0x8000000000000042ULL;
  task.sas.ss_sp = 0x7fb0000000; task.sas.ss_size = 0x4000; task.sas.ss_flags = 1;
  /* A handler for SIGUSR1, default elsewhere - the distinction a resumed guest
   * must keep, or a signal is delivered to the wrong place. */
  proc.sigaction[9].lsa_handler = 0x401234;
  proc.sigaction[9].lsa_flags = 0x4;
  proc.sigaction[9].lsa_mask.__mask = 0x11;

  static struct mm_region r[2];
  r[0] = (struct mm_region){ .gaddr = 0x400000, .size = 0x8000,
                             .arena_off = 0x0, .prot = 5, .mm_flags = 0x22,
                             .mm_fd = -1, .pgoff = 0 };
  r[1] = (struct mm_region){ .gaddr = 0xc0000000, .size = 0x10000,
                             .arena_off = 0x8000, .prot = 3, .mm_flags = 0x2,
                             .mm_fd = 7, .pgoff = 2 };
  list_add(&r[0].list, &mm.mm_regions);
  list_add(&r[1].list, &r[0].list);

  char path[] = "/tmp/nabi-ckpt-XXXXXX";
  int fd = mkstemp(path);
  unlink(path);
  CHECK(fd >= 0, "could not create a scratch checkpoint");

  CHECK(checkpoint_write(fd) == 0, "checkpoint_write failed: %s", strerror(errno));
  lseek(fd, 0, SEEK_SET);

  struct checkpoint_header hdr;
  struct checkpoint_region *regions = NULL;
  struct checkpoint_s2 *s2 = NULL;
  struct checkpoint_pt_chunk *chunks = NULL;
  struct checkpoint_fd *fds = NULL;
  l_sigaction_t *sigactions = NULL;
  CHECK(checkpoint_read(fd, &hdr, &regions, &s2, &chunks, &fds, &sigactions) == 0,
        "checkpoint_read failed: %s", strerror(errno));

  CHECK(hdr.magic == CHECKPOINT_MAGIC && hdr.version == CHECKPOINT_VERSION,
        "header magic/version did not survive");

  /* The vCPU: the registers a guest resumes on. */
  CHECK(hdr.vcpu.x[0] == 0x1000 && hdr.vcpu.x[30] == 0x1000 + 30,
        "general registers did not survive");
  CHECK(hdr.vcpu.pc == 0x400abc && hdr.vcpu.sp == 0x7fbfff0000,
        "pc/sp did not survive");
  CHECK(hdr.vcpu.elr_el1 == 0x400def,
        "the banked EL0 return address did not survive");
  CHECK(hdr.vcpu.ttbr0_el1 == 0x40000000,
        "the translation base did not survive");
  CHECK(hdr.vcpu.v[7][3] == 0xEE, "the FP/SIMD file did not survive");

  /* The mm scalars, which the region list does not imply. */
  CHECK(hdr.start_brk == 0x500000 && hdr.current_brk == 0x510000 &&
        hdr.current_mmap_top == 0xc0400000, "mm scalars did not survive");

  /* Regions, in full - a wrong prot or mm_fd resumes a guest with the wrong
   * permissions or the wrong file. */
  CHECK(hdr.nr_regions == 2, "wrote %u regions, want 2", hdr.nr_regions);
  if (hdr.nr_regions == 2) {
    bool found_exec = false, found_file = false;
    for (unsigned i = 0; i < 2; i++) {
      if (regions[i].gaddr == 0x400000)
        found_exec = regions[i].size == 0x8000 && regions[i].prot == 5 &&
                     regions[i].arena_off == 0 && regions[i].mm_fd == -1;
      if (regions[i].gaddr == 0xc0000000)
        found_file = regions[i].size == 0x10000 && regions[i].prot == 3 &&
                     regions[i].arena_off == 0x8000 && regions[i].mm_fd == 7 &&
                     regions[i].pgoff == 2;
    }
    CHECK(found_exec, "the executable region did not survive intact");
    CHECK(found_file, "the file-backed region did not survive intact");
  }

  /* Stage-2 and the stage-1 allocator. */
  CHECK(hdr.nr_s2 == FAKE_S2, "wrote %u stage-2 entries, want %d",
        hdr.nr_s2, FAKE_S2);
  CHECK(hdr.nr_s2 == FAKE_S2 && s2[2].ipa == 0x40000000 + 2 * 0x4000 &&
        s2[2].arena_off == 2 * 0x4000, "stage-2 entries did not survive");
  CHECK(hdr.ipa_brk == 0x40100000 && hdr.l1_ipa == 0x40000000,
        "the stage-1 allocator's cursors did not survive");
  CHECK(hdr.nr_pt_chunks == FAKE_CHUNKS && chunks[1].used == 2,
        "page-table chunks did not survive");

  /* Credentials and task identity. */
  CHECK(hdr.uid == 501 && hdr.euid == 0 && hdr.suid == 0,
        "credentials did not survive");
  CHECK(hdr.tid == 4242 && hdr.set_child_tid == 0xc0ffee &&
        hdr.clear_child_tid == 0xdeadbe, "task identity did not survive");
  CHECK(hdr.sigmask == 0x8000000000000042ULL, "the signal mask did not survive");
  CHECK(hdr.sas_sp == 0x7fb0000000 && hdr.sas_size == 0x4000 &&
        hdr.sas_flags == 1, "the alternate signal stack did not survive");

  /* Signal dispositions: a handler must stay a handler, and the rest default. */
  CHECK(hdr.nr_sigactions == LINUX_NSIG, "wrote %u sigactions, want %d",
        hdr.nr_sigactions, LINUX_NSIG);
  CHECK(sigactions[9].lsa_handler == 0x401234 && sigactions[9].lsa_flags == 0x4 &&
        sigactions[9].lsa_mask.__mask == 0x11,
        "an installed signal handler did not survive");
  CHECK(sigactions[10].lsa_handler == 0,
        "a default disposition came back as a handler");

  /* The descriptor table: guest number -> host descriptor, and cloexec. */
  CHECK(hdr.nr_fds == FAKE_FDS, "wrote %u fds, want %d", hdr.nr_fds, FAKE_FDS);
  CHECK(hdr.rootfd == 61000, "the root descriptor did not survive");
  if (hdr.nr_fds == FAKE_FDS) {
    CHECK(fds[1].table == 0 && fds[1].index == 5 && fds[1].host_fd == 9 &&
          fds[1].cloexec == 1,
          "a close-on-exec guest descriptor did not survive intact");
    CHECK(fds[2].table == 1 && fds[2].host_fd == 61000,
          "a vkernel descriptor did not survive intact");
  }

  free(regions); free(s2); free(chunks); free(fds); free(sigactions);

  /* A truncated checkpoint must be refused, not half-read. */
  lseek(fd, 0, SEEK_SET);
  ftruncate(fd, (off_t) sizeof hdr - 8);
  lseek(fd, 0, SEEK_SET);
  CHECK(checkpoint_read(fd, &hdr, &regions, &s2, &chunks, &fds, &sigactions) < 0,
        "a truncated checkpoint was accepted");

  /* So must one whose version we do not speak. */
  struct checkpoint_header bad;
  memset(&bad, 0, sizeof bad);
  bad.magic = CHECKPOINT_MAGIC;
  bad.version = CHECKPOINT_VERSION + 1;
  lseek(fd, 0, SEEK_SET);
  ftruncate(fd, 0);
  (void) !write(fd, &bad, sizeof bad);
  lseek(fd, 0, SEEK_SET);
  CHECK(checkpoint_read(fd, &hdr, &regions, &s2, &chunks, &fds, &sigactions) < 0,
        "a checkpoint from another version was accepted");

  close(fd);

  printf("\n%d checks, %d failures\n%s\n", checks, failures,
         failures == 0 ? "PASS" : "FAIL");
  return failures != 0;
}
