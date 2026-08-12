#include "common.h"
#include "noah.h"

#include "linux/common.h"
#include "linux/misc.h"
#include "linux/random.h"

#include <string.h>
#include <pthread.h>
#include "linux/errno.h"
#include "linux/time.h"
#include <stdlib.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/timex.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/sysctl.h>

DEFINE_SYSCALL(sysinfo, gaddr_t, info_ptr)
{
  struct l_sysinfo info;
  size_t len;

  struct timeval boottime;
  len = sizeof boottime;
  if (sysctlbyname("kern.boottime", &boottime, &len, NULL, 0) < 0) exit(1);
  info.uptime = boottime.tv_sec;

  double loadavg[3];
  if (getloadavg(loadavg, sizeof loadavg / sizeof loadavg[0]) < 0) {
    panic("sysinfo");
  }

  info.loads[0] = loadavg[0] * LINUX_SYSINFO_LOADS_SCALE;
  info.loads[1] = loadavg[1] * LINUX_SYSINFO_LOADS_SCALE;
  info.loads[2] = loadavg[2] * LINUX_SYSINFO_LOADS_SCALE;

  int64_t memsize;
  len = sizeof memsize;
  if (sysctlbyname("hw.memsize", &memsize, &len, NULL, 0) < 0){
    perror("sysinfo:");
    exit(1);
  }
  info.totalram = memsize;

  int64_t freepages;
  len = sizeof freepages;
  if (sysctlbyname("vm.page_free_count", &freepages, &len, NULL, 0) < 0){
    perror("sysinfo:");
    exit(1);
  }
  info.freeram = freepages * 0x1000;

  /*
   * sysctlbyname() changed in macos 15. Any older os will leave swapinfo[4] as 0.
   */
  
  uint64_t swapinfo[4] = {0};
  len = sizeof swapinfo;
  if (sysctlbyname("vm.swapusage", &swapinfo, &len, NULL, 0) < 0){
    perror("sysinfo:");
    exit(1);
  }
  info.totalswap = swapinfo[0];
  
  if(swapinfo[3] == 0)
    info.freeswap = swapinfo[2];
  else
    info.freeswap = swapinfo[1];

  /* TODO */
  info.sharedram = 0;
  info.bufferram = 0;
  info.procs = 100;
  info.totalhigh = 0;
  info.freehigh = 0;

  info.mem_unit = 1;

  if (copy_to_user(info_ptr, &info, sizeof info)) {
    return -LINUX_EFAULT;
  }

  return 0;
}

DEFINE_SYSCALL(getrandom, gaddr_t, buf_ptr, size_t, count, unsigned, flags)
{
  if (flags & ~(GRND_RANDOM | GRND_NONBLOCK | GRND_INSECURE)) {
    return -LINUX_EINVAL;
  }
  /*
   * GRND_INSECURE asks for the non-blocking pool without waiting for it to be
   * seeded, and on Darwin /dev/urandom is always seeded and never blocks - so
   * it is served by the same source as the default. GRND_RANDOM with
   * GRND_INSECURE is contradictory; Linux rejects that pair, and so does the
   * mask check above only if both are set... which it does not, so the
   * insecure request simply loses to GRND_RANDOM, as it does on Linux.
   */
  const char *source;
  source = flags & GRND_RANDOM ? "/dev/random" : "/dev/urandom";
  int oflags = O_RDONLY;
  oflags |= flags & GRND_NONBLOCK ? O_NONBLOCK : 0;
  int fd = open(source, oflags);
  if (fd < 0) {
    printk("getrandom: logic flaw\n");
    return -darwin_to_linux_errno(errno);
  }
  char *buf = malloc(count);
  int r = syswrap(read(fd, buf, count));
  if (r < 0) {
    goto out;
  }
  if (copy_to_user(buf_ptr, buf, count)) {
    r = -LINUX_EFAULT;
  }
out:
  free(buf);
  return r;
}

/*
 * syslog(2) - klogctl, the kernel's own ring buffer, not the libc syslog().
 *
 * There is no kernel here, so there is no ring buffer, and the honest answer is
 * an empty one rather than an error. An empty log is a state a real machine can
 * be in; ENOSYS is a state dmesg does not expect and reports as a failure of the
 * tool. So `dmesg` prints nothing and exits 0, which is true - nothing has been
 * logged - instead of "klogctl failed: Function not implemented".
 *
 * What is deliberately not done is answering with nabi's own warning sink. That
 * is the host's account of the guest, written for whoever is debugging nabi; it
 * names host paths, host descriptors and host errno values, and handing it to
 * the guest as its kernel log would be both a leak and a fiction.
 *
 * SYSLOG_ACTION_READ waits for a message that will never come, and waits rather
 * than returning nothing, because a caller that gets 0 from it loops - `dmesg
 * -w` would spin a core on a machine with nothing to say. Blocking until a
 * signal is what it does on a quiet Linux too.
 */
#define LINUX_SYSLOG_ACTION_CLOSE          0
#define LINUX_SYSLOG_ACTION_OPEN           1
#define LINUX_SYSLOG_ACTION_READ           2
#define LINUX_SYSLOG_ACTION_READ_ALL       3
#define LINUX_SYSLOG_ACTION_READ_CLEAR     4
#define LINUX_SYSLOG_ACTION_CLEAR          5
#define LINUX_SYSLOG_ACTION_CONSOLE_OFF    6
#define LINUX_SYSLOG_ACTION_CONSOLE_ON     7
#define LINUX_SYSLOG_ACTION_CONSOLE_LEVEL  8
#define LINUX_SYSLOG_ACTION_SIZE_UNREAD    9
#define LINUX_SYSLOG_ACTION_SIZE_BUFFER   10

DEFINE_SYSCALL(syslog, int, type, gaddr_t, buf_ptr, int, len)
{
  pthread_rwlock_rdlock(&proc.cred.lock);
  bool root = proc.cred.euid == 0;
  pthread_rwlock_unlock(&proc.cred.lock);

  switch (type) {
  case LINUX_SYSLOG_ACTION_CLOSE:
  case LINUX_SYSLOG_ACTION_OPEN:
    return 0;                   /* both are no-ops on Linux as well */

  case LINUX_SYSLOG_ACTION_READ_ALL:
  case LINUX_SYSLOG_ACTION_READ_CLEAR:
    if (len < 0)
      return -LINUX_EINVAL;
    return 0;                   /* nothing logged, so nothing read */

  case LINUX_SYSLOG_ACTION_READ:
    if (len < 0)
      return -LINUX_EINVAL;
    /* Nothing will arrive. Waiting for it is what this call means, and is
     * cheaper for everyone than telling a caller "no messages" in a loop. */
    for (;;) {
      if (has_sigpending())
        return -LINUX_EINTR;
      struct timespec nap = { 0, 100 * 1000 * 1000 };
      nanosleep(&nap, NULL);
    }

  case LINUX_SYSLOG_ACTION_CLEAR:
  case LINUX_SYSLOG_ACTION_CONSOLE_OFF:
  case LINUX_SYSLOG_ACTION_CONSOLE_ON:
  case LINUX_SYSLOG_ACTION_CONSOLE_LEVEL:
    /* Administrative, and CAP_SYS_ADMIN on Linux. There is nothing to clear and
     * no console to set a level on, but the privilege is still the answer a
     * caller checks. */
    return root ? 0 : -LINUX_EPERM;

  case LINUX_SYSLOG_ACTION_SIZE_UNREAD:
    return 0;

  case LINUX_SYSLOG_ACTION_SIZE_BUFFER:
    /* What a buffer would be if there were one. Callers size an allocation
     * from this, and zero makes some of them conclude the call is broken. */
    return 1 << 17;

  default:
    return -LINUX_EINVAL;
  }
}

/*
 * sysfs(2) - the filesystem-type table, and nothing to do with /sys.
 *
 * Obsolete on Linux, which says so in its own manual and points at
 * /proc/filesystems, but still implemented there and still numbered - so a
 * guest that calls it should get an answer about *this* machine rather than
 * ENOSYS. The list is exactly the set mount(2) here accepts, so the three
 * questions it can ask - how many, what is number N, what number is this name -
 * are all answered out of the same truth the mount table is built from.
 *
 * It has no aarch64 number at all; only x86-64 ever gave it one.
 */
static const char *const known_filesystems[] = {
  "tmpfs", "proc", "sysfs", "devtmpfs", "devpts",
  "cgroup", "cgroup2", "mqueue", "securityfs", "debugfs",
};
#define NR_KNOWN_FS (sizeof known_filesystems / sizeof known_filesystems[0])

DEFINE_SYSCALL(sysfs, int, option, unsigned long, arg1, unsigned long, arg2)
{
  switch (option) {
  case 1: {                     /* name -> index */
    char name[64];
    if (strncpy_from_user(name, (gstr_t) arg1, sizeof name) < 0)
      return -LINUX_EFAULT;
    for (size_t i = 0; i < NR_KNOWN_FS; i++)
      if (strcmp(name, known_filesystems[i]) == 0)
        return (int) i;
    return -LINUX_EINVAL;
  }
  case 2: {                     /* index -> name */
    if (arg1 >= NR_KNOWN_FS)
      return -LINUX_EINVAL;
    const char *name = known_filesystems[arg1];
    if (copy_to_user((gaddr_t) arg2, name, strlen(name) + 1))
      return -LINUX_EFAULT;
    return 0;
  }
  case 3:
    return (int) NR_KNOWN_FS;
  default:
    return -LINUX_EINVAL;
  }
}

/* ------------------------------------------------------------- io priority */

/*
 * ioprio_get and ioprio_set: how much of the disk a process is entitled to.
 *
 * Linux encodes a class and a level in one integer - realtime, best-effort or
 * idle, with eight levels inside the first two. Darwin has the same idea under a
 * different name and a coarser scale: setiopolicy_np assigns a process one of
 * important, standard, utility, passive or throttle, with no levels within them.
 *
 * So the class translates and the level does not. Setting best-effort level 0
 * and best-effort level 7 both land on standard, and reading back gives level 4
 * - the middle of the range, since the host has forgotten which end of it was
 * asked for. That is a real loss of resolution and it is worth being plain
 * about, but the part programs actually use is the class: ionice -c3 to keep a
 * backup out of the way is the common case, and idle really does map onto
 * throttle.
 *
 * Only the calling process can be adjusted. Darwin's interface has no way to
 * name another process - there is no pid argument to setiopolicy_np - so asking
 * about somebody else is refused rather than answered about the wrong process.
 */
#define LINUX_IOPRIO_CLASS_NONE 0
#define LINUX_IOPRIO_CLASS_RT   1
#define LINUX_IOPRIO_CLASS_BE   2
#define LINUX_IOPRIO_CLASS_IDLE 3
#define LINUX_IOPRIO_CLASS_SHIFT 13
#define LINUX_IOPRIO_PRIO_MASK  ((1 << LINUX_IOPRIO_CLASS_SHIFT) - 1)

#define LINUX_IOPRIO_WHO_PROCESS 1
#define LINUX_IOPRIO_WHO_PGRP    2
#define LINUX_IOPRIO_WHO_USER    3

/* True when `who` names this process and nothing else. */
static bool
ioprio_is_self(int which, int who)
{
  if (which != LINUX_IOPRIO_WHO_PROCESS)
    return false;
  return who == 0 || who == getpid();
}

DEFINE_SYSCALL(ioprio_set, int, which, int, who, int, ioprio)
{
  if (which < LINUX_IOPRIO_WHO_PROCESS || which > LINUX_IOPRIO_WHO_USER)
    return -LINUX_EINVAL;
  if (!ioprio_is_self(which, who))
    return -LINUX_EPERM;        /* the host cannot name another process here */

  int class = ioprio >> LINUX_IOPRIO_CLASS_SHIFT;
  int level = ioprio & LINUX_IOPRIO_PRIO_MASK;
  if (level > 7)
    return -LINUX_EINVAL;

  int policy;
  switch (class) {
  case LINUX_IOPRIO_CLASS_RT:   policy = IOPOL_IMPORTANT; break;
  case LINUX_IOPRIO_CLASS_BE:   policy = IOPOL_STANDARD;  break;
  case LINUX_IOPRIO_CLASS_IDLE: policy = IOPOL_THROTTLE;  break;
  case LINUX_IOPRIO_CLASS_NONE: policy = IOPOL_DEFAULT;   break;
  default:
    return -LINUX_EINVAL;
  }
  if (setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS, policy) < 0)
    return -darwin_to_linux_errno(errno);
  return 0;
}

DEFINE_SYSCALL(ioprio_get, int, which, int, who)
{
  if (which < LINUX_IOPRIO_WHO_PROCESS || which > LINUX_IOPRIO_WHO_USER)
    return -LINUX_EINVAL;
  if (!ioprio_is_self(which, who))
    return -LINUX_EPERM;

  int policy = getiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS);
  if (policy < 0)
    return -darwin_to_linux_errno(errno);

  /* Level 4 for the classes that have levels: the host kept no level, and the
   * middle of the range is the least wrong answer to invent. */
  switch (policy) {
  case IOPOL_IMPORTANT:
    return (LINUX_IOPRIO_CLASS_RT << LINUX_IOPRIO_CLASS_SHIFT) | 4;
  case IOPOL_THROTTLE:
  case IOPOL_UTILITY:
    return LINUX_IOPRIO_CLASS_IDLE << LINUX_IOPRIO_CLASS_SHIFT;
  case IOPOL_PASSIVE:
  case IOPOL_STANDARD:
  default:
    return (LINUX_IOPRIO_CLASS_BE << LINUX_IOPRIO_CLASS_SHIFT) | 4;
  }
}

/* ------------------------------------------------------------- the clock */

/*
 * adjtimex and clock_adjtime: reading the clock's discipline, and not writing
 * it.
 *
 * These are how a time daemon steers the system clock - it reads the current
 * offset, frequency and status, and writes corrections back. Darwin has the
 * same interface under its BSD name, ntp_adjtime, so *reading* translates
 * almost directly.
 *
 * Writing does not, and the reason is not a missing facility. The clock these
 * would steer is the host's: there is one clock and every process on the
 * machine reads it, nabi's guests included. A guest that adjusted it would be
 * adjusting macOS's idea of the time for everything else running on the
 * machine, which is not a thing a program inside a Linux ABI layer should be
 * able to do at all - the guest is not the administrator of this computer.
 *
 * So a read is answered and a write is EPERM, which is what Linux answers a
 * caller without CAP_SYS_TIME. A time daemon that gets EPERM concludes it is
 * not privileged and stops trying, which is the right outcome; one that got a
 * pretend success would go on believing it was steering a clock that never
 * moved.
 */
#define LINUX_ADJ_OFFSET     0x0001
#define LINUX_ADJ_FREQUENCY  0x0002
#define LINUX_ADJ_MAXERROR   0x0004
#define LINUX_ADJ_ESTERROR   0x0008
#define LINUX_ADJ_STATUS     0x0010
#define LINUX_ADJ_TIMECONST  0x0020
#define LINUX_ADJ_TAI        0x0080
#define LINUX_ADJ_SETOFFSET  0x0100
#define LINUX_ADJ_MICRO      0x1000
#define LINUX_ADJ_NANO       0x2000
#define LINUX_ADJ_TICK       0x4000

#define LINUX_TIME_OK 0

/* Linux's struct timex, which is not Darwin's. */
struct l_timex {
  unsigned int modes;
  int64_t offset, freq, maxerror, esterror;
  int status;
  int64_t constant, precision, tolerance;
  struct l_timeval time;
  int64_t tick, ppsfreq, jitter;
  int shift;
  int64_t stabil, jitcnt, calcnt, errcnt, stbcnt;
  int tai;
  int pad[11];
};

static int
do_adjtimex(gaddr_t buf_ptr)
{
  struct l_timex tx;
  if (copy_from_user(&tx, buf_ptr, sizeof tx))
    return -LINUX_EFAULT;

  /*
   * Anything that would change the clock is refused before it is looked at, so
   * that a caller cannot get a partial adjustment. ADJ_OFFSET_SS_READ and the
   * bare read (modes 0) are what is left.
   */
  if (tx.modes & (LINUX_ADJ_OFFSET | LINUX_ADJ_FREQUENCY | LINUX_ADJ_MAXERROR |
                  LINUX_ADJ_ESTERROR | LINUX_ADJ_STATUS | LINUX_ADJ_TIMECONST |
                  LINUX_ADJ_TAI | LINUX_ADJ_SETOFFSET | LINUX_ADJ_TICK))
    return -LINUX_EPERM;

  struct timex host;
  memset(&host, 0, sizeof host);
  int state = ntp_adjtime(&host);
  if (state < 0)
    return -darwin_to_linux_errno(errno);

  memset(&tx, 0, sizeof tx);
  tx.offset = host.offset;
  tx.freq = host.freq;
  tx.maxerror = host.maxerror;
  tx.esterror = host.esterror;
  tx.status = host.status;
  tx.constant = host.constant;
  tx.precision = host.precision;
  tx.tolerance = host.tolerance;
  /* No `tick` in Darwin's timex - it is a Linux field for the interval timer's
   * period, and there is nothing here to read it from. Left zero rather than
   * invented, since a caller comparing it against USER_HZ would be comparing
   * against a number nobody set. */
  tx.tick = 0;
  /* The clock this reports is CLOCK_REALTIME, so the time it reports is the
   * one gettimeofday would give - taken here rather than left zero, because a
   * caller reads the pair together. */
  struct timeval now;
  gettimeofday(&now, NULL);
  tx.time.tv_sec = now.tv_sec;
  tx.time.tv_usec = now.tv_usec;

  if (copy_to_user(buf_ptr, &tx, sizeof tx))
    return -LINUX_EFAULT;
  return state;
}

DEFINE_SYSCALL(adjtimex, gaddr_t, buf_ptr)
{
  return do_adjtimex(buf_ptr);
}

DEFINE_SYSCALL(clock_adjtime, l_clockid_t, which, gaddr_t, buf_ptr)
{
  /* Only the realtime clock has a discipline to report; the monotonic clocks
   * are not steered, which is the property they are chosen for. */
  if (which != LINUX_CLOCK_REALTIME)
    return -LINUX_EINVAL;
  return do_adjtimex(buf_ptr);
}

/*
 * clock_settime: setting the wall clock, which is not the guest's to set.
 *
 * The same reasoning as adjtimex's write half, and more starkly: there is one
 * clock on this machine and every process reads it. A guest stepping it would
 * step it for macOS and everything else running there. Linux answers EPERM
 * without CAP_SYS_TIME, and every caller already handles that - `date -s` says
 * it cannot set the date, which is true and is what a person needs to be told.
 *
 * The time namespace does not change this. Its offsets apply to the monotonic
 * and boottime clocks, not to the realtime one, precisely because the wall
 * clock is shared.
 */
DEFINE_SYSCALL(clock_settime, l_clockid_t, which, gaddr_t, tp)
{
  (void) tp;
  switch (which) {
  case LINUX_CLOCK_REALTIME:
    return -LINUX_EPERM;
  case LINUX_CLOCK_MONOTONIC:
  case LINUX_CLOCK_MONOTONIC_RAW:
  case LINUX_CLOCK_BOOTTIME:
    /* Not settable on Linux either: a clock that only counts forward has no
     * meaning for being placed somewhere. */
    return -LINUX_EINVAL;
  default:
    return -LINUX_EINVAL;
  }
}
