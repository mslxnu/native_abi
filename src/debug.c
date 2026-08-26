#include <stdlib.h>
#include <stdio.h>
#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <execinfo.h>
#include <stdnoreturn.h>
#include <errno.h>
#include <string.h>

#include "noah.h"
#include "vmm.h"
#include "linux/time.h"
#include "linux/fs.h"

static FILE *printk_sink, *warnk_sink;
pthread_mutex_t printk_sync = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t warnk_sync = PTHREAD_MUTEX_INITIALIZER;

void
init_sink(const char *fn, FILE **sinkp, const char *name)
{
  if (! fn) {
    fn = "/dev/null";
  }
  int fd = open(fn, O_RDWR | O_CREAT, 0644);
  if (fd < 0) {
    fprintf(stderr, "could not open %s log %s: %s\n", name, fn, strerror(errno));
    return;
  }
  *sinkp = fdopen(vkern_dup_fd(fd, false), "w");
  close(fd);

  /*
   * Line buffered, because the interesting end of a log is the end.
   *
   * A FILE on a file is fully buffered by default, so the last few kilobytes
   * are still in the buffer when a process dies abruptly - killed, or exiting
   * through a path that does not flush. That is precisely the moment a trace is
   * being read for, and it is silently missing: the log appears to stop at the
   * last call that *returned*, which reads as a process still blocked in the
   * next one. waydroid's container was diagnosed three different ways off that
   * illusion.
   */
  if (*sinkp != NULL)
    setvbuf(*sinkp, NULL, _IOLBF, 0);

  /* Everything that writes to a sink already treats NULL as "not enabled", so
   * losing the log is survivable; writing the banner to a NULL FILE is not. */
  if (*sinkp == NULL) {
    fprintf(stderr, "could not open %s log %s: %s\n", name, fn, strerror(errno));
    return;
  }

  char buf[1000];
  time_t now = time(0);
  struct tm tm = *gmtime(&now);
  strftime(buf, sizeof buf, "%a, %d %b %Y %H:%M:%S %Z", &tm);
  fprintf(*sinkp, "\n//==================\n");
  fprintf(*sinkp, "%s log started: [%s]\n", name, buf);
  fflush(*sinkp);
}

void
print_to_sink(FILE *sink, pthread_mutex_t *sync, const char *mes)
{
  if (!sink) {
    return;
  }

  uint64_t tid;
  pthread_threadid_np(NULL, &tid);

  if (sync) {
    pthread_mutex_lock(sync);
  }
  fprintf(sink, "[%d:%lld] %s", getpid(), tid, mes);
  fflush(sink);
  if (sync) {
    pthread_mutex_unlock(sync);
  }
}

void
init_printk(const char *fn)
{
  init_sink(fn, &printk_sink, "printk");
}

void
printk(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  char *mes;

  if (!printk_sink) {
    va_end(ap);
    return;
  }

  vasprintf(&mes, fmt, ap);
  print_to_sink(printk_sink, &printk_sync, mes);

  free(mes);
  va_end(ap);
}

void
init_warnk(const char *fn)
{
  init_sink(fn, &warnk_sink, "warning");
}

void
warnk(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  char *mes;

  vasprintf(&mes, fmt, ap);

  printk("WARNING: %s", mes);
  print_to_sink(warnk_sink, &printk_sync, mes);

#ifndef NDEBUG
  //const char *magenda = "\x1b[35m", *reset = "\x1b[0m";
  //fprintf(stderr, "%sNoah WARNING: %s%s", magenda, mes, reset);
#endif

  free(mes);
  va_end(ap);
}

static void
printbt_to_sink(FILE *sink, pthread_mutex_t *sync)
{
  if (!sink) {
    return;
  }

  void *array[10];
  size_t size;
  char **strings;
  size_t i;
  uint64_t tid;

  pthread_threadid_np(NULL, &tid);
  size = backtrace(array, 10);
  strings = backtrace_symbols(array, size);

  if (sync) {
    pthread_mutex_lock(sync);
  }
  fprintf(sink, "[%d:%lld] Obtained %zd stack frames.\n", getpid(), tid, size);
  for(i = 0; i < size; i++)
    fprintf(sink, "%s\n", strings[i]);
  fflush(sink);
  if (sync) {
    pthread_mutex_unlock(sync);
  }

  free(strings);
}

noreturn void
panic(const char *fmt, ...)
{
  int err = errno;
  va_list ap, cp;
  va_start(ap, fmt);
  va_copy(cp, ap);
  char *given, *mes;

  vasprintf(&given, fmt, ap);
  asprintf(&mes, "!!PANIC!!\nperror is \"%s\" if it is valid\n%s\n", strerror(err), given);

  printk("!!PANIC!!%s", mes);
  printbt_to_sink(printk_sink, &printk_sync);

  print_to_sink(warnk_sink, &warnk_sync, mes);
  printbt_to_sink(warnk_sink, &warnk_sync);

  const char *magenda = "\x1b[35m", *reset = "\x1b[0m";
  fprintf(stderr, "%s%s", magenda, mes);
  printbt_to_sink(stderr, NULL);
  fprintf(stderr, "%s\n", reset);

  free(given);
  free(mes);

  /*
   * Said rather than asked.
   *
   * This used to offer to raise RLIMIT_CORE and read the answer with getchar,
   * which is a question a crashing emulator is in no position to ask. stdin
   * belongs to the guest: in a pipeline there is nobody to answer and the read
   * never returns, so a panic stopped being a crash and became a hang - no
   * message where the user was looking, no exit, nothing to see. That is what
   * `dnf update` looked like from the outside, and the keystroke the user did
   * type went to this prompt instead of to dnf.
   *
   * Raising the limit here would not have produced a core for *this* crash
   * anyway: the limit is read when the core is written, but a process that has
   * already faulted has nothing to gain from a limit set afterwards. The limit
   * has to be raised before the run, so that is what it says.
   */
  struct rlimit lim;
  getrlimit(RLIMIT_CORE, &lim);
  if (lim.rlim_cur == 0)
    fprintf(stderr, "%sno coredump: run with `ulimit -c unlimited` to get one%s\n",
            magenda, reset);

  
  fprintf(stderr, "%saborting..%s\n", magenda, reset);
  die_with_forcedsig(LINUX_SIGABRT);
}
