/* Zygote premise test:
 *   Z (this process) never touches HVF. Z forks R.
 *   R creates a VM + vCPU and keeps them live (like a running guest).
 *   R then asks Z to fork clean children C; each C creates a VM + vCPU.
 * Question: do the C's succeed reliably while R holds a live VM? */
#include <Hypervisor/Hypervisor.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>

#define N 25

static int mkvm_vcpu(void){
  if (hv_vm_create(NULL) != HV_SUCCESS) return 0;
  hv_vcpu_t id; hv_vcpu_exit_t *ex;
  if (hv_vcpu_create(&id,&ex,NULL) != HV_SUCCESS) return 0;
  return 1;
}

int main(void){
  int req[2], rep[2];
  if (pipe(req) || pipe(rep)) return 1;

  pid_t r = fork();
  if (r == 0) {
    /* ---- R: the runner. Live VM + vCPU, like a guest mid-execution. ---- */
    close(req[0]); close(rep[1]);
    if (!mkvm_vcpu()) { fprintf(stderr,"R: could not create VM+vcpu\n"); _exit(1); }
    int bad = 0;
    for (int i = 0; i < N; i++) {
      char c = 'f';
      if (write(req[1], &c, 1) != 1) break;      /* ask Z for a clean child */
      int st = 0;
      if (read(rep[0], &st, sizeof st) != sizeof st) break;
      if (st != 0) bad++;                        /* child failed */
    }
    fprintf(stderr, "  zygote children that failed: %d/%d\n", bad, N);
    _exit(bad ? 1 : 0);
  }

  /* ---- Z: the zygote. Never calls into HVF. Forks children on request. ---- */
  close(req[1]); close(rep[0]);
  char c;
  while (read(req[0], &c, 1) == 1) {
    pid_t ch = fork();
    if (ch == 0) {                                /* C: clean lineage */
      _exit(mkvm_vcpu() ? 0 : 3);
    }
    int st; waitpid(ch, &st, 0);
    int failed = WIFSIGNALED(st) ? 128 + WTERMSIG(st) : WEXITSTATUS(st);
    if (write(rep[1], &failed, sizeof failed) != sizeof failed) break;
  }
  int rst; waitpid(r, &rst, 0);
  return WIFSIGNALED(rst) ? 128 + WTERMSIG(rst) : WEXITSTATUS(rst);
}
