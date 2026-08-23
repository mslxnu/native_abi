#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include "noah.h"
#include "vmm.h"
#include "mm.h"
#include "x86/vm.h"
#if defined(__arm64__)
#include "arm64/vm.h"
#endif
#include "elf.h"

/*
 * What to report as AT_PAGESZ. The truth unless an image is known to need
 * otherwise; see the note at the call site.
 */
static uint64_t
guest_pagesz(void)
{
#if defined(__arm64__)
  uint64_t real = STAGE2_GRANULE;
#else
  uint64_t real = PAGE_SIZEOF(PAGE_4KB);
#endif
  const char *o = getenv("NABI_AT_PAGESZ");
  if (o == NULL || *o == '\0')
    return real;
  char *end;
  unsigned long v = strtoul(o, &end, 0);
  /* A power of two, and never larger than the granule mappings really use: a
   * guest told its pages are *bigger* than they are would round its own
   * allocations past the end of them. */
  if (*end != '\0' || v == 0 || (v & (v - 1)) != 0 || v > real) {
    warnk("NABI_AT_PAGESZ=%s ignored; reporting %llu\n", o,
          (unsigned long long) real);
    return real;
  }
  if (v != real)
    warnk("NABI_AT_PAGESZ=%lu: the guest is being told a page size mmap does "
          "not use (%llu); its allocator may corrupt itself\n",
          v, (unsigned long long) real);
  return v;
}


/*
 * The page granule ELF segments are aligned to when loaded. Must match the
 * guest's AT_PAGESZ and the mmap granule (src/mm/mmap.c): 16KiB on Apple
 * Silicon, so a segment never shares a 16KiB stage-2 block with its neighbour
 * (which vmm_munmap cannot split), 4KiB on x86.
 */
#if defined(__arm64__)
#define LOAD_GRANULE STAGE2_GRANULE
#else
#define LOAD_GRANULE PAGE_SIZEOF(PAGE_4KB)
#endif

/* The ELF e_machine the guest must be. The whole point of the port: flip this
 * from EM_X86_64 to EM_AARCH64 and the loader accepts aarch64 binaries. */
#ifdef __x86_64__
#define GUEST_EM_MACHINE EM_X86_64
#else
#define GUEST_EM_MACHINE EM_AARCH64
#endif

#include "linux/common.h"
#include "linux/mman.h"

/*
 * mprotect(2), used by the ELF loader to union the permissions of two segments
 * that share a granule-aligned page. Defined in src/mm/mmap.c; declared here
 * because the loader is not a syscall path.
 */
uint64_t sys_mprotect(gaddr_t addr, size_t len, int prot);
#include "linux/misc.h"
#include "linux/time.h"
#include "linux/fs.h"

void init_userstack(int argc, char *argv[], char **envp, uint64_t exe_base,
               const Elf64_Ehdr *ehdr, uint64_t global_offset,
               uint64_t interp_base, bool secure, const char *execfn);

int
load_elf_interp(const char *path, ulong load_addr)
{
  char *data;
  Elf64_Ehdr *h;
  uint64_t map_top = 0;
  int fd;
  struct stat st;

  if ((fd = vkern_open_exec(path)) < 0) {
    fprintf(stderr, "load_elf_interp, could not open file: %s\n", path);
    return -1;
  }

  fstat(fd, &st);

  /* The host only reads this mapping - to check the magic and copy segments
   * into guest memory - so PROT_READ is enough. PROT_EXEC additionally fails on
   * Apple Silicon, which refuses to map an arbitrary (unsigned) file
   * executable, and the result was used unchecked. */
  data = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (data == MAP_FAILED) {
    vkern_close(fd);
    return -LINUX_ENOEXEC;
  }

  vkern_close(fd);

  h = (Elf64_Ehdr *)data;

  assert(IS_ELF(*h));

  if (! (h->e_type == ET_EXEC || h->e_type == ET_DYN)) {
    return -LINUX_ENOEXEC;
  }
  if (h->e_machine != GUEST_EM_MACHINE) {
    return -LINUX_ENOEXEC;
  }

  Elf64_Phdr *p = (Elf64_Phdr *)(data + h->e_phoff);

  ulong last_end = 0;
  int prev_prot = 0;
  for (int i = 0; i < h->e_phnum; i++) {
    if (p[i].p_type != PT_LOAD) {
      continue;
    }

    ulong p_vaddr = p[i].p_vaddr + load_addr;

    ulong mask = LOAD_GRANULE - 1;
    ulong vaddr = p_vaddr & ~mask;
    ulong size = roundup(p[i].p_memsz + p_vaddr - vaddr, LOAD_GRANULE);

    int prot = 0;
    if (p[i].p_flags & PF_X) prot |= LINUX_PROT_EXEC;
    if (p[i].p_flags & PF_W) prot |= LINUX_PROT_WRITE;
    if (p[i].p_flags & PF_R) prot |= LINUX_PROT_READ;

    /*
     * A segment that is not granule-aligned has its base rounded down to the
     * granule, and when the segments are closer together than a granule that
     * puts the next base inside the previous mapping. Replacing it with
     * do_mmap's do_munmap would delete the previous segment's bytes and
     * permissions on the page they share, so instead the mapping starts where
     * the previous one ends. glibc's segments happen to be granule-aligned,
     * which is why this only shows up on bionic's 4KiB-aligned layouts.
     */
    ulong map_vaddr = vaddr;
    ulong map_size = size;
    if (last_end > vaddr) {
      map_vaddr = last_end;
      map_size = roundup(p_vaddr + p[i].p_memsz - last_end, LOAD_GRANULE);
      /*
       * The shared page carries the earlier segment's tail and the later
       * segment's head, so it has to answer to both: the tail is executed
       * (bionic keeps code in it), the head is written (it is .data). Linux
       * unions the two segments' permissions on the page; so does this, and
       * the union accumulates across segments that all land on one granule
       * (prot is what prev_prot picks up at the end of the loop).
       */
      sys_mprotect(vaddr, last_end - vaddr, prev_prot | prot);
      prot = prev_prot | prot;
    }

    assert(map_vaddr != 0);
    if (map_size != 0)
      do_mmap(map_vaddr, map_size, PROT_READ | PROT_WRITE, prot, LINUX_MAP_PRIVATE | LINUX_MAP_FIXED | LINUX_MAP_ANONYMOUS, -1, 0);

    copy_to_user(p_vaddr, data + p[i].p_offset, p[i].p_filesz);

    /* An executable segment the host just wrote is not visible to the guest's
     * instruction fetch on arm64 until the caches are reconciled; no-op on x86. */
    if (prot & LINUX_PROT_EXEC)
      vmm_sync_guest_code(p_vaddr, p[i].p_filesz);

    map_top = MAX(map_top, map_vaddr + map_size);
    last_end = map_vaddr + map_size;
    prev_prot = prot;
  }

  vmm_set_reg(VREG_PC, load_addr + h->e_entry);
  /* Rounded to the mapping granule, not merely to a page.
   *
   * brk maps from here in granule-sized pieces, and do_mmap rounds a length up
   * to the granule while accepting any 4KiB-aligned address. Starting the break
   * part-way into a block meant the first mapping reached past the new break,
   * and the next brk then mapped from inside a region that already existed -
   * record_region panicking with "recording overlapping regions", from a guest
   * that had only called malloc. */
  proc.mm->start_brk = roundup(map_top, GUEST_MMAP_GRANULE);

  munmap(data, st.st_size);

  return 0;
}

int
load_elf(Elf64_Ehdr *ehdr, int argc, char *argv[], char **envp, bool secure,
         const char *execfn)
{
  uint64_t map_top = 0;

  assert(IS_ELF(*ehdr));

  if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
    fprintf(stderr, "not an executable file");
    fflush(stderr);
    return -LINUX_ENOEXEC;
  }
  if (ehdr->e_machine != GUEST_EM_MACHINE) {
    fprintf(stderr, "not an executable for this machine");
    fflush(stderr);
    return -LINUX_ENOEXEC;
  }

  Elf64_Phdr *p = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);

  uint64_t load_base = 0;
  bool load_base_set = false;

  ulong global_offset = 0;
  if (ehdr->e_type == ET_DYN) {
    /* NB: Program headers in elf files of ET_DYN can have 0 as their own p_vaddr. */
    global_offset = 0x400000;   /* default base address */
  }

  ulong last_end = 0;
  int prev_prot = 0;
  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (p[i].p_type != PT_LOAD) {
      continue;
    }

    ulong p_vaddr = p[i].p_vaddr + global_offset;

    ulong mask = LOAD_GRANULE - 1;
    ulong vaddr = p_vaddr & ~mask;
    ulong size = roundup(p[i].p_memsz + p_vaddr - vaddr, LOAD_GRANULE);

    int prot = 0;
    if (p[i].p_flags & PF_X) prot |= LINUX_PROT_EXEC;
    if (p[i].p_flags & PF_W) prot |= LINUX_PROT_WRITE;
    if (p[i].p_flags & PF_R) prot |= LINUX_PROT_READ;

    /*
     * A segment that is not granule-aligned has its base rounded down to the
     * granule, and when the segments are closer together than a granule that
     * puts the next base inside the previous mapping. Replacing it with
     * do_mmap's do_munmap would delete the previous segment's bytes and
     * permissions on the page they share, so instead the mapping starts where
     * the previous one ends. glibc's segments happen to be granule-aligned,
     * which is why this only shows up on bionic's 4KiB-aligned layouts.
     */
    ulong map_vaddr = vaddr;
    ulong map_size = size;
    if (last_end > vaddr) {
      map_vaddr = last_end;
      map_size = roundup(p_vaddr + p[i].p_memsz - last_end, LOAD_GRANULE);
      /*
       * The shared page carries the earlier segment's tail and the later
       * segment's head, so it has to answer to both: the tail is executed
       * (bionic keeps code in it), the head is written (it is .data). Linux
       * unions the two segments' permissions on the page; so does this, and
       * the union accumulates across segments that all land on one granule
       * (prot is what prev_prot picks up at the end of the loop).
       */
      sys_mprotect(vaddr, last_end - vaddr, prev_prot | prot);
      prot = prev_prot | prot;
    }

    assert(map_vaddr != 0);
    if (map_size != 0)
      do_mmap(map_vaddr, map_size, PROT_READ | PROT_WRITE, prot, LINUX_MAP_PRIVATE | LINUX_MAP_FIXED | LINUX_MAP_ANONYMOUS, -1, 0);

    copy_to_user(p_vaddr, (char *)ehdr + p[i].p_offset, p[i].p_filesz);

    /* See load_elf_interp: reconcile caches for host-written guest code. */
    if (prot & LINUX_PROT_EXEC)
      vmm_sync_guest_code(p_vaddr, p[i].p_filesz);

    if (! load_base_set) {
      load_base = p[i].p_vaddr - p[i].p_offset + global_offset;
      load_base_set = true;
    }
    map_top = MAX(map_top, map_vaddr + map_size);
    last_end = map_vaddr + map_size;
    prev_prot = prot;
  }

  assert(load_base_set);

  int i;
  bool interp = false;
  for (i = 0; i < ehdr->e_phnum; i++) {
    if (p[i].p_type == PT_INTERP) {
      interp = true;
      break;
    }
  }
  if (interp) {
    char interp_path[p[i].p_filesz + 1];
    memcpy(interp_path, (char *)ehdr + p[i].p_offset, p[i].p_filesz);
    interp_path[p[i].p_filesz] = 0;

    if (load_elf_interp(interp_path, map_top) < 0) {
      return -1;
    }
  }
  else {
    vmm_set_reg(VREG_PC, ehdr->e_entry + global_offset);
    /* Rounded to the mapping granule, not merely to a page.
   *
   * brk maps from here in granule-sized pieces, and do_mmap rounds a length up
   * to the granule while accepting any 4KiB-aligned address. Starting the break
   * part-way into a block meant the first mapping reached past the new break,
   * and the next brk then mapped from inside a region that already existed -
   * record_region panicking with "recording overlapping regions", from a guest
   * that had only called malloc. */
  proc.mm->start_brk = roundup(map_top, GUEST_MMAP_GRANULE);
  }

  init_userstack(argc, argv, envp, load_base, ehdr, global_offset,
                 interp ? map_top : 0, secure, execfn);

  return 1;
}

#define SB_ARGC_MAX 2

int
load_script(const char *script, size_t len, const char *elf_path, int argc, char *argv[], char **envp)
{
  const char *script_end = script + len;
  char sb_argv[SB_ARGC_MAX][LINUX_PATH_MAX];
  int sb_argc;
  size_t n;

  script += 2;                  /* skip shebang */

  for (sb_argc = 0; sb_argc < SB_ARGC_MAX; ++sb_argc) {
    while (isspace(*script) && *script != '\n') {
      if (script == script_end)
        goto parse_end;
      script++;
    }

    for (n = 0; ! isspace(script[n]); ++n) {
      if (script + n == script_end)
        goto parse_end;
    }
    if (n == 0) {
      goto parse_end;
    }
    if (n > LINUX_PATH_MAX - 1) {
      return -LINUX_ENAMETOOLONG;
    }
    strncpy(sb_argv[sb_argc], script, n);
    sb_argv[sb_argc][n] = 0;

    script += n;                /* skip interp */
  }

 parse_end:
  if (sb_argc == 0) {
    return -LINUX_EFAULT;
  }

  int newargc = sb_argc + argc;
  char *newargv[newargc];
  for (int i = 0; i < sb_argc; ++i) {
    newargv[i] = sb_argv[i];
  }
  /* Cast is safe: newargv is only ever read - do_exec passes it to execve(2),
   * which does not write through argv. The array cannot be declared const
   * because execve takes char *const argv[]. */
  newargv[sb_argc] = (char *) elf_path;
  memcpy(newargv + sb_argc + 1, argv + 1, (argc - 1) * sizeof(char *));

  do_exec(newargv[0], newargc, newargv, envp);

  return 0;
}

uint64_t
push(const void *data, size_t n)
{
  uint64_t size = roundup(n, 8);
  uint64_t rsp;

  assert(data != 0);

  vmm_get_reg(VREG_SP, &rsp);
  rsp -= size;
  vmm_set_reg(VREG_SP, rsp);

  copy_to_user(rsp, data, n);

  return rsp;
}

void
init_userstack(int argc, char *argv[], char **envp, uint64_t exe_base,
               const Elf64_Ehdr *ehdr, uint64_t global_offset,
               uint64_t interp_base, bool secure, const char *execfn)
{
  static const uint64_t zero = 0;

  do_mmap(STACK_TOP - STACK_SIZE, STACK_SIZE, PROT_READ | PROT_WRITE, LINUX_PROT_READ | LINUX_PROT_WRITE, LINUX_MAP_PRIVATE | LINUX_MAP_FIXED | LINUX_MAP_ANONYMOUS, -1, 0);

  vmm_set_reg(VREG_SP, STACK_TOP);
#ifdef __x86_64__
  /* RBP=STACK_TOP is an x86 nicety; the aarch64 process-start ABI puts no
   * requirement on x29, and crt0 establishes its own frame either way. */
  vmm_write_register(HV_X86_RBP, STACK_TOP);
#endif

  /*
   * The sixteen bytes AT_RANDOM points at, and they have to be random.
   *
   * This was an uninitialised array - whatever happened to be on nabi's own
   * stack at that moment - and what reads it is not a program asking politely
   * for entropy. glibc builds the *stack canary* out of these bytes, and the
   * pointer guard it mangles setjmp buffers and atexit handlers with. Leaving
   * them to chance leaves both to chance: the same nabi running the same
   * binary reaches this point by the same path, so the "random" value is
   * substantially repeatable, and a canary that can be predicted is a canary
   * that does not stop the overflow it exists to stop.
   *
   * arc4random_buf rather than the /dev/urandom read getrandom(2) does, because
   * the two are answering different questions. getrandom has to honour a
   * caller's choice of pool and its non-blocking flag, so it has to be a read
   * from the source the caller named. Nothing chose anything here; this needs
   * sixteen good bytes and has no way to report a failure - it is the middle of
   * building a process image - and arc4random_buf is the one that cannot fail.
   */
  char random[16];
  arc4random_buf(random, sizeof random);

  uint64_t rand_ptr = push(random, sizeof random);

  /*
   * The two auxv entries that are strings rather than numbers, pushed here so
   * they end up above the argument and environment arrays - push() moves the
   * stack pointer down, so what goes first sits highest, which is where Linux
   * puts them too.
   *
   * AT_EXECFN is the path execve was *given*, which is not argv[0]: a program
   * may pass whatever argv[0] it likes, and the two differing is the ordinary
   * case for a login shell spelled `-bash` and the whole basis of a multi-call
   * binary like busybox. Something re-executing itself reads this to find out
   * what to re-execute.
   */
  uint64_t execfn_ptr = push(execfn, strlen(execfn) + 1);

  /*
   * AT_PLATFORM names the instruction set, and glibc builds library search
   * directories out of it. It has to be the architecture the *guest* runs,
   * which is the one nabi was built for.
   */
#if defined(__arm64__)
  static const char platform[] = "aarch64";
#else
  static const char platform[] = "x86_64";
#endif
  uint64_t platform_ptr = push(platform, sizeof platform);

  char **renvp;
  for (renvp = envp; *renvp; ++renvp)
    ;

  uint64_t total = 0, args_total = 0;

  for (int i = 0; i < argc; ++i) {
    total += strlen(argv[i]) + 1;
  }
  args_total = total;
  for (char **e = envp; *e; ++e) {
    total += strlen(*e) + 1;
  }

  char buf[total];

  uint64_t off = 0;

  for (int i = 0; i < argc; ++i) {
    size_t len = strlen(argv[i]);
    memcpy(buf + off, argv[i], len + 1);
    off += len + 1;
  }
  for (char **e = envp; *e; ++e) {
    size_t len = strlen(*e);
    memcpy(buf + off, *e, len + 1);
    off += len + 1;
  }

  uint64_t args_start = push(buf, total);
  uint64_t args_end = args_start + args_total, env_end = args_start + total;

  /*
   * The auxiliary vector.
   *
   * What goes in it is not only a matter of what a program might find useful,
   * because of how it is read. getauxval() sets errno to ENOENT for an entry
   * that is absent, and callers do not all treat that as "no answer" - GLib's
   * g_check_setuid() asks for AT_SECURE and calls g_error() if errno is set,
   * which aborts. So a missing entry is not a feature a program does without;
   * it is a program that dies. That was dconf, and with it every GLib program:
   * the RPM scriptlet for dconf ended in a trap during a Fedora install.
   *
   * Linux supplies all of these on every exec, so this does too. The ids are
   * the guest's own rather than the host's, which is the whole point of them.
   */
  pthread_rwlock_rdlock(&proc.cred.lock);
  uint64_t a_uid = proc.cred.uid, a_euid = proc.cred.euid;
  uint64_t a_gid = proc.cred.gid, a_egid = proc.cred.egid;
  pthread_rwlock_unlock(&proc.cred.lock);

  Elf64_Auxv aux[] = {
    { AT_BASE, interp_base },
    { AT_ENTRY, ehdr->e_entry + global_offset },
    { AT_PHDR, exe_base + ehdr->e_phoff },
    { AT_PHENT, ehdr->e_phentsize },
    { AT_PHNUM, ehdr->e_phnum },
    /*
     * The granule mmap actually works in, which on Apple Silicon is 16KiB.
     *
     * This read 4096 for a while, on the reasoning that 16KiB is a hardware
     * detail of the host rather than the page size the guest runs under. It is
     * not a detail an allocator can be lied to about: glibc's malloc sizes and
     * releases its mmapped chunks in units of AT_PAGESZ, and nabi rounds every
     * mapping to GUEST_MMAP_GRANULE - so a guest told 4096 computes boundaries
     * the mm layer does not honour, releases ranges it did not allocate, and
     * walks into its own free lists. On a Fedora tree that showed as
     * `malloc(): unaligned fastbin chunk detected` from bash before the prompt,
     * and further back as an outright abort on `corrupted top size`.
     *
     * Making it true the other way round does not work: setting
     * GUEST_MMAP_GRANULE to 4096 as well leaves the corruption in place,
     * because the host page really is 16KiB and nothing underneath can hand
     * out a 4KiB mapping of its own.
     *
     * NABI_AT_PAGESZ exists for the Android work, where bionic's jemalloc
     * refuses to initialise on anything but 4096. It is a workaround rather
     * than a second opinion - a guest started with it has an allocator being
     * told something untrue - so it warns, and is meant for an image known to
     * need it.
     */
    { AT_PAGESZ, guest_pagesz() },
    { AT_RANDOM, rand_ptr },
    /*
     * Whether this exec crossed a privilege boundary. Nonzero tells the dynamic
     * linker to ignore LD_PRELOAD and the rest, so answering it wrongly in the
     * permissive direction would matter; it is computed from the file's setuid
     * bits by the caller rather than guessed at here.
     */
    { AT_SECURE, secure ? 1 : 0 },
    { AT_UID, a_uid },
    { AT_EUID, a_euid },
    { AT_GID, a_gid },
    { AT_EGID, a_egid },
    /* Jiffies per second, which is what sysconf(_SC_CLK_TCK) reports. glibc
     * falls back to 100 when this is absent, and 100 is the answer, so this
     * changes nothing except that asking for it no longer sets errno. */
    { AT_CLKTCK, 100 },
    /*
     * No optional CPU features claimed. That is the conservative direction:
     * glibc dispatches its string routines on these, so an over-claim selects
     * an implementation the guest may fault on, where an under-claim only
     * selects a slower one that always works.
     */
    { AT_HWCAP, 0 },
    { AT_HWCAP2, 0 },
    { AT_EXECFN, execfn_ptr },
    { AT_PLATFORM, platform_ptr },
    { AT_NULL, 0 },
  };

  /*
   * Land the finished stack on a 16-byte boundary.
   *
   * Both ABIs require SP to be 16-byte aligned when the process starts, and
   * push() rounds to 8 - so the string block, whose length is whatever argv and
   * envp happen to add up to, leaves the stack 8-aligned half the time. Every
   * push after this one is a multiple of 8, so the parity is decided here and
   * never recovers.
   *
   * The symptom is not a fault. The guest starts, runs for thousands of
   * syscalls, and then glibc reports "free(): invalid pointer" from somewhere
   * unrelated - because a 16-byte-aligned allocator handed a stack-derived
   * value that is 8 off produces a heap that is subtly wrong rather than
   * obviously broken. It showed up as sqv, the OpenPGP verifier apt runs,
   * aborting for some user names and not others: the name travels in the
   * environment, the environment sets the length of the string block, and the
   * length decided the alignment. Eight bytes of padding in the environment
   * flipped it either way.
   *
   * Everything below pushes 8-byte slots and one auxv array, so the distance
   * from here to the final SP is known exactly and the correction is at most
   * one slot.
   */
  {
    size_t nslots = (size_t) argc + (size_t) (renvp - envp) + 3;
    size_t after = sizeof aux + 8 * nslots;   /* argv NUL, envp NUL, argc */
    uint64_t sp_now;
    vmm_get_reg(VREG_SP, &sp_now);
    if ((sp_now - after) % 16 != 0)
      push(&zero, sizeof zero);
  }

  push(aux, sizeof aux);

  push(&zero, sizeof zero);

  uint64_t ptr = env_end;
  for (char **e = renvp - 1; e >= envp; --e) {
    ptr -= strlen(*e) + 1;
    push(&ptr, sizeof ptr);
    assert(strcmp(buf + (ptr - args_start), *e) == 0);
  }

  push(&zero, sizeof zero);

  ptr = args_end;
  for (int i = argc - 1; i >= 0; --i) {
    ptr -= strlen(argv[i]) + 1;
    push(&ptr, sizeof ptr);
    assert(strcmp(buf + (ptr - args_start), argv[i]) == 0);
  }

  uint64_t argc64 = argc;
  push(&argc64, sizeof argc64);
}

static void
init_reg_state(void)
{
  /* The post-exec register state is arch-specific - which registers exist,
   * segments-or-not, the FPU layout - so it lives in the backend. */
  vmm_reset_regs();
}

static void
prepare_newproc(void)
{
  /* Reinitialize proc and task structures */
  /* Not handling locks seriously now because multi-thread execve is not implemented yet */
  proc.nr_tasks = 1;
  destroy_mm(proc.mm); // munlock is also done by unmapping mm
  init_mm(proc.mm);
  init_reg_state();
  reset_signal_state();
  // TODO: destroy LDT if it is implemented

  /* task.tid = getpid(); */
  task.clear_child_tid = task.set_child_tid = 0;
  task.robust_list = 0;
  close_cloexec();
}

/*
 * Whether this file is something the guest can be replaced *with*, asked before
 * anything is torn down.
 *
 * execve has a point of no return - the old program is gone and there is
 * nothing to give an error back to - and Linux puts it after the format has
 * been accepted, so a binary the kernel cannot run comes back as ENOEXEC with
 * the caller still standing. nabi tore the address space down first and only
 * then looked at the file, so ENOEXEC returned into a process that no longer
 * had a program: the caller took SIGSEGV instead of an error.
 *
 * Android's init exec_starts /vendor/bin/boringssl_self_test32, which is an
 * EM_ARM ELF32 - a machine Apple Silicon cannot execute a single instruction
 * of. The service died of a segmentation fault where it should have failed to
 * start, which says nothing about the actual reason.
 *
 * The class is checked as well as the machine. An ELF32 header is shorter than
 * an ELF64 one, so reading e_machine out of it only works by the accident that
 * the two layouts agree that far, and everything past e_version does not.
 */
static int
exec_format_ok(const char *data, size_t size)
{
  if (4 <= size && memcmp(data, ELFMAG, 4) == 0) {
    if (size < sizeof(Elf64_Ehdr))
      return -LINUX_ENOEXEC;
    const Elf64_Ehdr *e = (const Elf64_Ehdr *) data;
    if (e->e_ident[EI_CLASS] != ELFCLASS64)
      return -LINUX_ENOEXEC;
    if (e->e_type != ET_EXEC && e->e_type != ET_DYN)
      return -LINUX_ENOEXEC;
    if (e->e_machine != GUEST_EM_MACHINE)
      return -LINUX_ENOEXEC;
    return 0;
  }
  if (2 <= size && data[0] == '#' && data[1] == '!')
    return 0;
  return -LINUX_ENOEXEC;                  /* nothing here knows how to run it */
}

int
do_exec(const char *elf_path, int argc, char *argv[], char **envp)
{
  int err;
  int fd;
  struct stat st;
  char *data;
  
  if ((err = do_access(elf_path, X_OK)) < 0) {
    return err;
  }
  if ((fd = vkern_open_exec(elf_path)) < 0) {
    return fd;
  }
  /*
   * execve replaces the program, so every other thread has to be gone first -
   * they are running code that is about to stop existing. Doing this before the
   * image is touched means a failure here leaves the caller's program intact.
   */
  if (!stop_other_tasks()) {
    warnk("execve: could not stop the other threads\n");
    return -LINUX_EAGAIN;
  }

  /* Now do exec */
  /* Checked, unlike before: an unchecked fstat leaves st full of stack, the
   * S_ISREG below then fails, and execve reports EACCES for a file that is
   * perfectly executable. That is how a bad descriptor used to present. */
  if (fstat(fd, &st) < 0) {
    warnk("execve: fstat(%s) failed: %s\n", elf_path, strerror(errno));
    vkern_close(fd);
    return -LINUX_EACCES;
  }
  if (!S_ISREG(st.st_mode)) {
    vkern_close(fd);
    return -LINUX_EACCES;
  }

  /* Taken while the descriptor is still open, since the setuid check below
   * happens after it is closed - and taken from the guest's view rather than
   * the host's, which carries neither the recorded owner nor the setuid bit. */
  uint32_t g_uid = 0, g_gid = 0, g_mode = st.st_mode;
  guest_view_of_fd(fd, &g_uid, &g_gid, &g_mode);

  /* The host only reads this mapping - to check the magic and copy segments
   * into guest memory - so PROT_READ is enough. PROT_EXEC additionally fails on
   * Apple Silicon, which refuses to map an arbitrary (unsigned) file
   * executable, and the result was used unchecked. */
  data = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (data == MAP_FAILED) {
    vkern_close(fd);
    return -LINUX_ENOEXEC;
  }

  vkern_close(fd);

  /* Before the point of no return, so a file that cannot be run is an error
   * the caller lives to see. */
  if ((err = exec_format_ok(data, (size_t) st.st_size)) < 0) {
    munmap(data, st.st_size);
    return err;
  }

  prepare_newproc();

  drop_privilege();

  if (4 <= st.st_size && memcmp(data, ELFMAG, 4) == 0) {
    /*
     * Whether this exec crosses a privilege boundary, which is what AT_SECURE
     * reports. Decided here because it is where the file's mode is known - the
     * elevation itself happens below, after the image is loaded.
     */
    bool secure = (g_mode & (S_ISUID | S_ISGID)) != 0;
    if ((err = load_elf((Elf64_Ehdr *) data, argc, argv, envp, secure,
                        elf_path)) < 0)
      return err;
    /*
     * Recorded here rather than where do_exec returns, because a `#!` script
     * comes back through this function: load_script re-enters do_exec with the
     * interpreter, and the outer call would then overwrite the interpreter's
     * identity with the script's. Linux reports the interpreter as exe and its
     * rewritten argv as cmdline, which is exactly the inner call.
     */
    proc_set_ident(elf_path, argc, argv);
    if (g_mode & (S_ISUID | S_ISGID)) {
      elevate_privilege(g_uid, g_gid, g_mode);
    }
  }
  else if (2 <= st.st_size && data[0] == '#' && data[1] == '!') {
    if ((err = load_script(data, st.st_size, elf_path, argc, argv, envp)) < 0)
      return err;
  }
  /*else if (4 <= st.st_size && memcmp(data, "\xcf\xfa\xed\xfe", 4) == 0) {
    // Mach-O
    return syswrap(execve(elf_path, argv, envp));
  }*/
  else {
    return -LINUX_ENOEXEC;                  /* unsupported file type */
  }

  munmap(data, st.st_size);
  proc.mm->current_brk = proc.mm->start_brk;

  return 0;
}

/*
 * The body of execve, taking the program as a string rather than as a guest
 * pointer - so that execveat, which has to build the path, can use it without a
 * second copy of the argument marshalling.
 */
static int
do_execve(const char *elf_path, gaddr_t gargv, gaddr_t genvp)
{
  int err;

  size_t argv_rsrv = 1024;
  char **argv = malloc(sizeof(char *) * argv_rsrv);
  size_t argc = 0;
  while (true) {
    size_t i = argc;
    gaddr_t addr;
    if (copy_from_user(&addr, gargv + sizeof(gaddr_t) * i, sizeof addr)) {
      err = -LINUX_EFAULT;
      goto faile_copy_argv;
    }
    if (addr == 0)
      break;
    argc++;
    if (argc + 1 > LINUX_MAX_ARG_STRINGS) {
      err = -LINUX_E2BIG;
      goto faile_copy_argv;
    }
    if (argc + 1 > argv_rsrv) {
      argv_rsrv *= 2;
      argv = realloc(argv, sizeof(char *) * argv_rsrv);
    }
    int size = strnlen_user(addr, LINUX_MAX_ARG_STRLEN);
    if (size == 0) {
      err = -LINUX_EFAULT;
      goto faile_copy_argv;
    }
    if (size > LINUX_MAX_ARG_STRLEN) {
      err = -LINUX_E2BIG;
      goto faile_copy_argv;
    }
    argv[i] = alloca(size);
    copy_from_user(argv[i], addr, size); /* always success */
  }
  argv[argc] = NULL;

  size_t envp_rsrv = 1024;
  char **envp = malloc(sizeof(char *) * envp_rsrv);
  size_t envc = 0;
  while (true) {
    size_t i = envc;
    gaddr_t addr;
    if (copy_from_user(&addr, genvp + sizeof(gaddr_t) * i, sizeof addr)) {
      err = -LINUX_EFAULT;
      goto fail_copy_envp;
    }
    if (addr == 0)
      break;
    envc++;
    if (envc + 1 > LINUX_MAX_ARG_STRINGS) {
      err = -LINUX_E2BIG;
      goto fail_copy_envp;
    }
    if (envc + 1 > envp_rsrv) {
      envp_rsrv *= 2;
      envp = realloc(envp, sizeof(char *) * envp_rsrv);
    }
    int size = strnlen_user(addr, LINUX_MAX_ARG_STRLEN);
    if (size == 0) {
      err = -LINUX_EFAULT;
      goto fail_copy_envp;
    }
    if (size > LINUX_MAX_ARG_STRLEN) {
      err = -LINUX_E2BIG;
      goto fail_copy_envp;
    }
    envp[i] = alloca(size);
    copy_from_user(envp[i], addr, size); /* always success */
  }
  envp[envc] = NULL;

  err = do_exec(elf_path, argc, argv, envp);
  if (err < 0) {
    goto fail_copy_envp;
  }

  /* do_exec set VREG_PC to the new entry point. main_loop will apply
   * vmm_syscall_return after this handler, so undo that advance now to land on
   * the entry exactly. Arch-neutral: a no-op on aarch64. */
  vmm_syscall_unadvance();

 fail_copy_envp:
  free(envp);
 faile_copy_argv:
  free(argv);
  return err;
}

/*
 * execveat: exec a program named relative to a descriptor.
 *
 * Two things it does that execve cannot. A directory descriptor plus a relative
 * name is immune to the directory being moved or replaced between the lookup
 * and the exec, which is what makes it safe to run something out of a tree
 * another process can rename. And AT_EMPTY_PATH executes the descriptor itself,
 * which is fexecve - running a file that may have no name at all, because it
 * was created with O_TMPFILE or unlinked after opening.
 *
 * A descriptor has no *guest* path here, and nabi has no reverse mapping from a
 * host path to a guest one. But it does not need one: /proc/self/fd/<n> is that
 * mapping expressed in the guest's own namespace, procfs serves it, and it is
 * exactly what glibc's fexecve falls back to when execveat is missing. So a
 * descriptor becomes a path the ordinary machinery can resolve, rather than a
 * special case running alongside it.
 */
DEFINE_SYSCALL(execve, gstr_t, gelf_path, gaddr_t, gargv, gaddr_t, genvp)
{
  char elf_path[LINUX_PATH_MAX];
  if (strncpy_from_user(elf_path, gelf_path, sizeof elf_path) < 0)
    return -LINUX_EFAULT;
  return do_execve(elf_path, gargv, genvp);
}

DEFINE_SYSCALL(execveat, int, dirfd, gstr_t, gpath, gaddr_t, gargv,
               gaddr_t, genvp, int, flags)
{
  if (flags & ~(LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW))
    return -LINUX_EINVAL;

  char path[LINUX_PATH_MAX];
  if (strncpy_from_user(path, gpath, sizeof path) < 0)
    return -LINUX_EFAULT;

  if (path[0] == '\0') {
    if (!(flags & LINUX_AT_EMPTY_PATH))
      return -LINUX_ENOENT;
    if (dirfd == LINUX_AT_FDCWD)
      return -LINUX_ENOENT;     /* the cwd is not a program */
    snprintf(path, sizeof path, "/proc/self/fd/%d", dirfd);
  } else if (path[0] != '/' && dirfd != LINUX_AT_FDCWD) {
    char rel[LINUX_PATH_MAX];
    snprintf(rel, sizeof rel, "%s", path);
    if ((size_t) snprintf(path, sizeof path, "/proc/self/fd/%d/%s", dirfd, rel)
        >= sizeof path)
      return -LINUX_ENAMETOOLONG;
  }
  /* An absolute path, or a relative one against the working directory, is what
   * execve already takes. */
  return do_execve(path, gargv, genvp);
}
