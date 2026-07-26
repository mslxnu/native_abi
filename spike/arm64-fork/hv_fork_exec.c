/* Does exec() clear the poisoning? Parent has VM+vCPU, forks, child execs a
 * helper that creates a VM+vCPU. If clean, a fork+exec child works - and unlike
 * a zygote child it still inherits fds. */
#include <Hypervisor/Hypervisor.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
static int mkvm_vcpu(void){
  if (hv_vm_create(NULL)!=HV_SUCCESS) return 0;
  hv_vcpu_t id; hv_vcpu_exit_t *ex;
  return hv_vcpu_create(&id,&ex,NULL)==HV_SUCCESS;
}
int main(int argc,char**argv){
  if (argc>1 && !strcmp(argv[1],"--helper")) return mkvm_vcpu()?0:3;
  if (!mkvm_vcpu()) return 1;            /* poison this process */
  hv_vm_destroy();
  int bad=0;
  for (int i=0;i<25;i++){
    pid_t p=fork();
    if(p==0){ execl(argv[0],argv[0],"--helper",(char*)0); _exit(9); }
    int st; waitpid(p,&st,0);
    if (WIFSIGNALED(st)||WEXITSTATUS(st)!=0) bad++;
  }
  fprintf(stderr,"  fork+exec children that failed: %d/25\n",bad);
  return bad?1:0;
}
