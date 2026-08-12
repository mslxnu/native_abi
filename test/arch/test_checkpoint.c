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
#include "namespace.h"
#include "cgroup.h"

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

/*
 * The guest's supplementary groups live in process.c, which this test does not
 * link - the point is to exercise the format, not the credential model. A tiny
 * stub stands in, and it is a real one rather than an empty shell so the round
 * trip below actually checks that the list travels.
 */
static l_gid_t stub_groups[32];
static int stub_ngroups;
int guest_groups_get(l_gid_t *out)
{
  if (out && stub_ngroups > 0)
    memcpy(out, stub_groups, stub_ngroups * sizeof stub_groups[0]);
  return stub_ngroups;
}
const l_gid_t *guest_groups_ptr(void) { return stub_groups; }
void guest_groups_set(const l_gid_t *g, int n)
{
  if (n > 0)
    memcpy(stub_groups, g, n * sizeof stub_groups[0]);
  stub_ngroups = n;
}
/*
 * The same shape of stub for the seccomp chain, and real for the same reason:
 * the filters travel as a trailing blob, and a round trip that did not carry
 * them would leave a forked child unfiltered while its parent believed it was
 * confined. That is checked below rather than assumed.
 */
static unsigned char stub_seccomp[64];
static size_t stub_seccomp_len;
static int stub_seccomp_mode;
size_t seccomp_snapshot_size(void) { return stub_seccomp_len; }
int seccomp_snapshot(void *buf, size_t len, int *mode_out)
{
  *mode_out = stub_seccomp_mode;
  if (len > stub_seccomp_len) len = stub_seccomp_len;
  memcpy(buf, stub_seccomp, len);
  return 0;
}
void seccomp_restore(const void *buf, size_t len, int mode)
{
  stub_seccomp_mode = mode;
  stub_seccomp_len = len > sizeof stub_seccomp ? sizeof stub_seccomp : len;
  if (buf && stub_seccomp_len)
    memcpy(stub_seccomp, buf, stub_seccomp_len);
}

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

/*
 * The namespaces and the control group, which the header has carried since
 * versions 4 and 6.
 *
 * Stubbed like the rest of the live machine, and made to *participate*: the
 * writer is handed distinctive values and the reader's copy is checked against
 * them below. Stubs that merely satisfied the linker would have kept this test
 * building while saying nothing about the fields, which is how it came to be
 * broken in the first place - checkpoint.c grew two callers and the link went
 * with it, unnoticed because the failure was a build error in a target nobody
 * was reading the exit status of.
 */
#define FAKE_NS_INO_BASE 4026531900ULL
static char restored_cgroup[256];
static uint64_t restored_ns[8];
static struct uts_namespace restored_uts;

void
nsproxy_snapshot(uint64_t inos[8], struct uts_namespace *uts)
{
  for (int i = 0; i < 8; i++)
    inos[i] = FAKE_NS_INO_BASE + (unsigned) i;
  snprintf(uts->nodename, sizeof uts->nodename, "%s", "checkpoint-host");
  snprintf(uts->domainname, sizeof uts->domainname, "%s", "checkpoint-dom");
}

void
nsproxy_restore(const uint64_t inos[8], const struct uts_namespace *uts)
{
  for (int i = 0; i < 8; i++)
    restored_ns[i] = inos[i];
  restored_uts = *uts;
}

const char *cgroup_current(void) { return "/work/inner"; }
void cgroup_set_current(const char *p)
{ snprintf(restored_cgroup, sizeof restored_cgroup, "%s", p ? p : ""); }

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
  /* The gids and the group list travel too, since version 3. They did not
   * before, and because a fork on arm64 is a fork plus an exec that meant
   * every child came back with gid 0 and no groups at all. */
  proc.cred.gid = 1000; proc.cred.egid = 1001; proc.cred.sgid = 1002;
  { l_gid_t g[] = { 4, 27, 100 }; guest_groups_set(g, 3); }
  proc.cred.fsuid = 1234; proc.cred.fsgid = 5678;
  /* A filter chain to carry, with contents that could not arise by accident. */
  { unsigned char f[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04 };
    seccomp_restore(f, sizeof f, 2 /* SECCOMP_MODE_FILTER */); }
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

  /* The guest's identity. Only NABI knows it - from the outside this process
   * is a nabi - so if it does not travel here, a forked child cannot report it
   * at all. Set directly rather than through proc_set_ident to keep this test
   * to the wire format. */
  static char ident_exe[] = "/bin/guest";
  static char ident_cmd[] = "/bin/guest\0-x\0arg";   /* NUL-separated argv */
  proc.ident.exe = ident_exe;
  proc.ident.cmdline = ident_cmd;
  proc.ident.cmdline_len = sizeof ident_cmd - 1;

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
  char *exe = NULL, *cmdline = NULL;
  memset(stub_seccomp, 0, sizeof stub_seccomp);
  stub_seccomp_len = 0; stub_seccomp_mode = 0;
  CHECK(checkpoint_read(fd, &hdr, &regions, &s2, &chunks, &fds, &sigactions,
                        &exe, &cmdline) == 0,
        "checkpoint_read failed: %s", strerror(errno));

  CHECK(hdr.magic == CHECKPOINT_MAGIC && hdr.version == CHECKPOINT_VERSION,
        "header magic/version did not survive");

  /* The identity, which is the whole reason a child can answer /proc for
   * itself. cmdline is compared with memcmp: it has NULs inside it. */
  CHECK(hdr.exe_len == sizeof ident_exe && exe && strcmp(exe, ident_exe) == 0,
        "the executable path did not survive");
  CHECK(hdr.cmdline_len == sizeof ident_cmd - 1 && cmdline &&
        memcmp(cmdline, ident_cmd, sizeof ident_cmd - 1) == 0,
        "the command line did not survive");

  /*
   * The namespaces and the control group. Both are per-process state that a
   * fork here has no other way to hand over - a child that did not inherit the
   * uts identity would compare as being in a different namespace from its
   * parent, and one that did not inherit the cgroup would fall back to the root
   * the moment it forked.
   */
  for (int i = 0; i < 8; i++)
    CHECK(hdr.ns_ino[i] == FAKE_NS_INO_BASE + (unsigned) i,
          "namespace inode %d did not survive", i);
  CHECK(strcmp(hdr.uts_nodename, "checkpoint-host") == 0 &&
        strcmp(hdr.uts_domainname, "checkpoint-dom") == 0,
        "the uts names did not survive");
  CHECK(strcmp(hdr.cgroup, "/work/inner") == 0,
        "the control group did not survive");

  /* And the reader handed them on, rather than merely carrying them. */
  CHECK(restored_ns[0] == FAKE_NS_INO_BASE &&
        restored_ns[7] == FAKE_NS_INO_BASE + 7,
        "the reader did not restore the namespaces");
  CHECK(strcmp(restored_uts.nodename, "checkpoint-host") == 0,
        "the reader did not restore the hostname");
  CHECK(strcmp(restored_cgroup, "/work/inner") == 0,
        "the reader did not restore the control group");

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
  CHECK(hdr.gid == 1000 && hdr.egid == 1001 && hdr.sgid == 1002,
        "gids did not survive: %u/%u/%u", hdr.gid, hdr.egid, hdr.sgid);
  CHECK(hdr.nr_groups == 3, "group count did not survive: %u", hdr.nr_groups);
  {
    /* checkpoint_read applies the list rather than handing it back, so it is
     * read out of the stub - which is exactly where a resumed guest gets it. */
    l_gid_t g[8] = { 0 };
    int n = guest_groups_get(g);
    CHECK(stub_seccomp_mode == 2 && stub_seccomp_len == 8 &&
          stub_seccomp[0] == 0xaa && stub_seccomp[7] == 0x04,
          "the seccomp chain did not come back: mode %d, %zu bytes",
          stub_seccomp_mode, stub_seccomp_len);
    CHECK(n == 3 && g[0] == 4 && g[1] == 27 && g[2] == 100,
          "group list did not survive: n=%d %u,%u,%u", n, g[0], g[1], g[2]);
  }
  CHECK(hdr.fsuid == 1234 && hdr.fsgid == 5678,
        "the filesystem ids did not survive: %u/%u", hdr.fsuid, hdr.fsgid);
  /*
   * The seccomp chain. Cleared before reading so that "it survived" cannot be
   * satisfied by the value that was already there - the same trap a round-trip
   * check falls into whenever the source and the destination are one variable.
   */
  CHECK(hdr.seccomp_mode == 2 && hdr.seccomp_bytes == 8,
        "the seccomp header did not survive: mode %u, %u bytes",
        hdr.seccomp_mode, hdr.seccomp_bytes);
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
  CHECK(checkpoint_read(fd, &hdr, &regions, &s2, &chunks, &fds, &sigactions,
                        &exe, &cmdline) < 0,
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
  CHECK(checkpoint_read(fd, &hdr, &regions, &s2, &chunks, &fds, &sigactions,
                        &exe, &cmdline) < 0,
        "a checkpoint from another version was accepted");

  close(fd);

  printf("\n%d checks, %d failures\n%s\n", checks, failures,
         failures == 0 ? "PASS" : "FAIL");
  return failures != 0;
}
