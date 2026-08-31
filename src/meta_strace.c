#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <pthread.h>
#include <stdlib.h>

#include "common.h"
#include "syscall.h"
#include "noah.h"

static FILE *strace_sink;
pthread_mutex_t strace_sync = PTHREAD_MUTEX_INITIALIZER;

/*
 * One line, built whole before any of it is written.
 *
 * A call and its result are printed at two different moments with the syscall
 * in between, and the lock used to be dropped for that. Any other thread could
 * take it and write its own line into the gap, so a multi-threaded guest
 * produced lines spliced out of two calls - a name and arguments from one
 * thread, a "): ret = ..." from another. Nothing marks them, and they read as
 * ordinary lines.
 *
 * That is the worst way for a tracer to be wrong, because the reader believes
 * it. Twice in one session it produced a bug that was not there: a write of 24
 * bytes appearing to return 62, and a write of 73 appearing to return 16 - both
 * of them another thread's return value, and one of them chased as far as
 * writing a test to reproduce a socket bug that did not exist.
 *
 * So the line is assembled in memory, per thread, and reaches the sink in a
 * single write once the result is known.
 */
static _Thread_local FILE  *line_fp;
static _Thread_local char  *line_buf;
static _Thread_local size_t line_len;

/* Where the formatters print: the pending line, or the sink if none is open. */
static FILE *
strace_out(void)
{
  return line_fp ? line_fp : strace_sink;
}

/* Finish the pending line and put it out as one write. */
static void
line_emit(void)
{
  if (line_fp == NULL)
    return;
  fclose(line_fp);
  line_fp = NULL;
  if (line_buf != NULL) {
    /* A line emitted without its result - exit_group, execve - has no closing
     * newline, and the next line would run into it. The truncation is the
     * point and is kept; the newline is what makes it readable. */
    bool ends = line_len > 0 && line_buf[line_len - 1] == '\n';
    pthread_mutex_lock(&strace_sync);
    fwrite(line_buf, 1, line_len, strace_sink);
    if (!ends)
      fputc('\n', strace_sink);
    fflush(strace_sink);
    pthread_mutex_unlock(&strace_sync);
    free(line_buf);
    line_buf = NULL;
  }
}

/*
 * A call that may never come back, and so would never be emitted. The trace
 * ending mid-call is worth keeping - it is how a guest that stopped inside a
 * syscall says so - and these are the calls that do it.
 */
static bool
never_returns(const char *name)
{
  return strcmp(name, "exit") == 0 || strcmp(name, "exit_group") == 0 ||
         strcmp(name, "execve") == 0 || strcmp(name, "execveat") == 0 ||
         strcmp(name, "rt_sigreturn") == 0;
}

void
init_meta_strace(const char *path)
{
  init_sink(path, &strace_sink, "strace");
}

typedef void meta_strace_hook(int syscall_num, int argc, char *argnames[6], char *typenames[6], uint64_t vals[6], uint64_t ret);

meta_strace_hook *strace_pre_hooks[NR_SYSCALLS];
meta_strace_hook *strace_post_hooks[NR_SYSCALLS];

/*
 * A guest string, for the log.
 *
 * Copied in rather than dereferenced. This walked guest memory directly -
 * *(char *)guest_to_host(str + i) - which is fine for a pointer that is a
 * string and fatal for one that is not: an unmapped address, or an argument
 * that only *looks* like a string in the table, faults inside the formatter and
 * kills the process being traced.
 *
 * That is the worst way for a tracer to fail, because it removes the evidence
 * of itself: the log ends at the call before the one that crashed, and the
 * guest looks like it stopped there on its own. waydroid's container was
 * diagnosed four different ways off this - hang, kill, spin, unexplained exit -
 * before the fault turned out to be here, in the instrument, on fsconfig's
 * arguments. Nothing that only observes may ever be able to do that.
 */
/* How much of a read's or write's buffer to show; see print_arg. */
#define STRACE_BUF_MAX 256

void
print_gstr(gstr_t str, int maxlen)
{
  if (str == 0) {
    fprintf(strace_out(), "NULL");
    return;
  }
  if (maxlen < 0)
    maxlen = 0;
  if (maxlen > 4096)
    maxlen = 4096;

  char buf[4097];
  if (strncpy_from_user(buf, str, (size_t) maxlen + 1) < 0) {
    /* Not readable: say where it pointed rather than dying of it. */
    fprintf(strace_out(), "<unreadable %#llx>", (unsigned long long) str);
    return;
  }
  buf[maxlen] = '\0';

  fprintf(strace_out(), "\"");
  for (int i = 0; i < maxlen; i++) {
    char c = buf[i];
    if (c == '\0') {
      break;
    } else if (c == '\n') {
      fprintf(strace_out(), "\\n");
    } else if (!isprint((unsigned char) c)) {
      fprintf(strace_out(), "\\x%02x", (unsigned char) c);
    } else {
      fprintf(strace_out(), "%c", c);
    }
  }
  fprintf(strace_out(), "\"");
}

void
print_arg(int syscall_num, int arg_idx, const char *arg_name, const char *type_name, uint64_t val)
{
    fprintf(strace_out(), "%s: ", arg_name);

    if (strcmp(type_name, "gstr_t") == 0) {
      /*
       * 256 rather than 50, because a guest's own diagnostics arrive here as
       * the buffer of a write() and fifty characters cuts every one of them
       * mid-sentence. Android's init logs to /dev/kmsg, which nothing can read
       * back, so the trace is the only place its messages exist at all - and
       * "Service 'apexd-bootstrap' (pid 45775) rec" is not enough to say what
       * happened to it. Paths longer than fifty characters were being cut in
       * half too.
       */
      print_gstr(val, 256);

    } else if (strcmp(type_name, "gaddr_t") == 0) {
      fprintf(strace_out(), "0x%016llx [host: 0x%016llx]", val, (uint64_t)guest_to_host(val));

    } else if (strcmp(type_name, "int") == 0) {
      fprintf(strace_out(), "%lld", val);

    } else {
      fprintf(strace_out(), "0x%llx", val);
    }
}

void
print_args(int syscall_num, int argc, char *argnames[6], char *typenames[6], uint64_t vals[6], uint64_t ret)
{
  for (int i = 0; i < argc; i++) {
    if (i > 0) {
      fprintf(strace_out(), ", ");
    }
    print_arg(syscall_num, i, argnames[i], typenames[i], vals[i]);
  }
}

void
print_ret(int syscall_num, int argc, char *argnames[6], char *typenames[6], uint64_t vals[6], uint64_t ret)
{
  fprintf(strace_out(), "): ret = 0x%llx", ret);
  if ((int64_t)ret < 0) {
    fprintf(strace_out(), "[%s]", linux_errno_str(-ret));
  }
  fprintf(strace_out(), "\n");
}

void
do_meta_strace(int syscall_num, char *syscall_name, meta_strace_hook def, meta_strace_hook **hooks, uint64_t ret,  va_list ap)
{
  int argc = 0;
  char *argnames[6];
  char *typenames[6];
  uint64_t vals[6];
  for (int i = 0; i < 6; i++) {
    typenames[i] = va_arg(ap, char*);
    argnames[i] = va_arg(ap, char*);
    vals[i] = va_arg(ap, uint64_t);

    if (typenames[i][0] == '0') {
      break;
    }
    argc++;
  }

  if (strcmp(syscall_name, "unimplemented") == 0) {
    fprintf(strace_out(), "<unimplemented systemcall>");
    def(-1, argc, argnames, typenames, vals, ret);
    return;
  }

  if (hooks[syscall_num]) {
    hooks[syscall_num](syscall_num, argc, argnames, typenames, vals, ret);
  } else {
    def(syscall_num, argc, argnames, typenames, vals, ret);
  }
}

void
meta_strace_info(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  char *mes;

  vasprintf(&mes, fmt, ap);

  fprintf(strace_out(), "INFO: %s", mes);

  free(mes);
  va_end(ap);
}

/*
 * Called before systemcall.
 * Most systemcalls are traced here,
 * but result values stored in argument pointers cannot be traced. (such as read)
 */
void
meta_strace_pre(int syscall_num, char *syscall_name, ...)
{
  va_list ap;
  va_start(ap, syscall_name);

  if (!strace_sink) {
    va_end(ap);
    return;
  }

  uint64_t tid;
  pthread_threadid_np(NULL, &tid);

  line_emit();                  /* a previous line with no result; do not lose it */
  line_fp = open_memstream(&line_buf, &line_len);
  fprintf(strace_out(), "[%d:%lld] %s(", getpid(), tid, syscall_name);

  do_meta_strace(syscall_num, syscall_name, print_args, strace_pre_hooks, 0, ap);

  /* Emitted now if there will be no result to wait for. */
  if (never_returns(syscall_name))
    line_emit();

  va_end(ap);
}

// Called after systemcall.
void
meta_strace_post(int syscall_num, char *syscall_name, uint64_t ret, ...)
{
  va_list ap;
  va_start(ap, ret);

  if (!strace_sink) {
    va_end(ap);
    return;
  }

  do_meta_strace(syscall_num, syscall_name, print_ret, strace_post_hooks, ret, ap);
  line_emit();

  va_end(ap);
}

void
meta_strace_sigdeliver(int signum)
{
  if (!strace_sink) {
    return;
  }

  uint64_t tid;
  pthread_threadid_np(NULL, &tid);

  /* The call this thread is inside, first: a signal arriving mid-syscall is
   * exactly when the pending line matters most. */
  line_emit();

  pthread_mutex_lock(&strace_sync);
  fprintf(strace_sink, "[%d:%lld] --- %s ---\n", getpid(), tid, linux_signum_str(signum));
  fflush(strace_sink);
  pthread_mutex_unlock(&strace_sync);
}

void
trace_read_pre(int syscall_num, int argc, char *argnames[6], char *typenames[6], uint64_t vals[6], uint64_t ret)
{
  // Print nothing
}

/* Print buf after syscall in order to show what stinrg is actually read */
void
trace_read_post(int syscall_num, int argc, char *argnames[6], char *typenames[6], uint64_t vals[6], uint64_t ret)
{
  for (int i = 0; i < argc; i++) {
    if (i > 0) {
      fprintf(strace_out(), ", ");
    }
    if (i == 1) {
      fprintf(strace_out(), "%s: ", argnames[1]);
      print_gstr(vals[1], MIN(STRACE_BUF_MAX, ret)); // Print buf as string
    } else {
      print_arg(syscall_num, i, argnames[i], typenames[i], vals[i]);
    }
  }

  print_ret(syscall_num, argc, argnames, typenames, vals, ret);
}

void
trace_write_pre(int syscall_num, int argc, char *argnames[6], char *typenames[6], uint64_t vals[6], uint64_t ret)
{
  for (int i = 0; i < argc; i++) {
    if (i > 0) {
      fprintf(strace_out(), ", ");
    }
    if (i == 1) {
      fprintf(strace_out(), "%s: ", argnames[1]);
      print_gstr(vals[1], MIN(STRACE_BUF_MAX, vals[2])); // Print buf as string
    } else {
      print_arg(syscall_num, i, argnames[i], typenames[i], vals[i]);
    }
  }
}

void
trace_recvfrom_pre(int syscall_num, int argc, char *argnames[6], char *typenames[6], uint64_t vals[6], uint64_t ret)
{
  // Print nothing
}

/* Print buf after syscall in order to show what stinrg is actually recvfrom */
void
trace_recvfrom_post(int syscall_num, int argc, char *argnames[6], char *typenames[6], uint64_t vals[6], uint64_t ret)
{
  for (int i = 0; i < argc; i++) {
    if (i > 0) {
      fprintf(strace_out(), ", ");
    }
    if (i == 1) {
      fprintf(strace_out(), "%s: ", argnames[1]);
      print_gstr(vals[1], MIN(STRACE_BUF_MAX, ret)); // Print buf as string
    } else {
      print_arg(syscall_num, i, argnames[i], typenames[i], vals[i]);
    }
  }

  print_ret(syscall_num, argc, argnames, typenames, vals, ret);
}

void
trace_sendto_pre(int syscall_num, int argc, char *argnames[6], char *typenames[6], uint64_t vals[6], uint64_t ret)
{
  for (int i = 0; i < argc; i++) {
    if (i > 0) {
      fprintf(strace_out(), ", ");
    }
    if (i == 1) {
      fprintf(strace_out(), "%s: ", argnames[1]);
      print_gstr(vals[1], MIN(STRACE_BUF_MAX, vals[2])); // Print buf as string
    } else {
      print_arg(syscall_num, i, argnames[i], typenames[i], vals[i]);
    }
  }
}

void
trace_execve_pre(int syscall_num, int argc, char *argnames[6], char *typenames[6], uint64_t vals[6], uint64_t ret)
{
  int exec_argc = 0;
  gaddr_t gargv = vals[1];

  while (((gaddr_t*)guest_to_host(gargv))[exec_argc] != 0) exec_argc++;
  char *dargv[exec_argc];
  for (int i = 0; i < exec_argc; i++) {
    dargv[i] = (char*)guest_to_host(((gaddr_t*)guest_to_host(gargv))[i]);
  }

  print_arg(syscall_num, 0, argnames[0], typenames[0], vals[0]); // path
  /* argc */
  fprintf(strace_out(), ", [");
  for (int i = 0; i < exec_argc; i++) {
    fprintf(strace_out(), "\"%s\", ", dargv[i]);
  }
  fprintf(strace_out(), "], ");
  print_arg(syscall_num, 2, argnames[2], typenames[2], vals[2]); // envp
}

static void
print_sigset(l_sigset_t *sigset)
{
  fprintf(strace_out(), "[");
  for (int i = 1; i < LINUX_SIGRTMIN; i++) {
    if (LINUX_SIGISMEMBER(sigset, i)) {
      fprintf(strace_out(), "%s, ", linux_signum_str(i));
    }
  }
  fprintf(strace_out(), "]");
}

void
trace_rt_sigprocmask_pre(int syscall_num, int argc, char *argnames[6], char *typenames[6], uint64_t vals[6], uint64_t ret)
{
}

void
trace_rt_sigprocmask_post(int syscall_num, int argc, char *argnames[6], char *typenames[6], uint64_t vals[6], uint64_t ret)
{
  for (int i = 0; i < argc; i++) {
    if (i > 0) {
      fprintf(strace_out(), ", ");
    }
    if (i == 0) {
      // how
      fprintf(strace_out(), "%s: ", argnames[1]);
      switch  (vals[i]) {
        case LINUX_SIG_BLOCK:
          fprintf(strace_out(), "BLOCK");
          break;
        case LINUX_SIG_UNBLOCK:
          fprintf(strace_out(), "UNBLOCK");
          break;
        case LINUX_SIG_SETMASK:
          fprintf(strace_out(), "SETMASK");
          break;
        default:
          fprintf(strace_out(), "UNKNOWN_HOW");
          break;
      }
    } else if (i == 1 || i == 2) {
      if (vals[i] == 0) {
        fprintf(strace_out(), "NULL (");
        print_sigset(&task.sigmask);
        fprintf(strace_out(), ")");
        continue;
      }
      l_sigset_t lset;
      if (copy_from_user(&lset, vals[i], sizeof(l_sigset_t)))  {
        fprintf(strace_out(), "FAULT...");
        continue;
      }
      print_sigset(&lset);
    } else {
      print_arg(syscall_num, i, argnames[i], typenames[i], vals[i]);
    }
  }

  print_ret(syscall_num, argc, argnames, typenames, vals, ret);
}

meta_strace_hook *strace_pre_hooks[NR_SYSCALLS] = {
  [LSYS_read] = trace_read_pre,
  [LSYS_recvfrom] = trace_recvfrom_pre,
  [LSYS_write] = trace_write_pre,
  [LSYS_sendto] = trace_sendto_pre,
  [LSYS_execve] = trace_execve_pre,
  [LSYS_rt_sigprocmask] = trace_rt_sigprocmask_post,
};
meta_strace_hook *strace_post_hooks[NR_SYSCALLS] = {
  [LSYS_read] = trace_read_post,
  [LSYS_recvfrom] = trace_recvfrom_post,
  [LSYS_rt_sigprocmask] = trace_rt_sigprocmask_pre,
};

