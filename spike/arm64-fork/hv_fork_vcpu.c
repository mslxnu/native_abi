/* Which pre-fork HVF activity poisons the child? */
#include <Hypervisor/Hypervisor.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
static int mkvcpu(void){ hv_vcpu_t id; hv_vcpu_exit_t *ex;
  hv_return_t r=hv_vcpu_create(&id,&ex,NULL); if(r==HV_SUCCESS) hv_vcpu_destroy(id); return r==HV_SUCCESS; }
int main(int argc,char**argv){
  int mode = atoi(argv[1]);   /* 0=nothing 1=vm only 2=vm+vcpu */
  if (mode>=1){ if(hv_vm_create(NULL)!=HV_SUCCESS) return 1; }
  if (mode>=2){ mkvcpu(); }
  if (mode>=1){ hv_vm_destroy(); }
  pid_t p=fork();
  if(p==0){ if(hv_vm_create(NULL)!=HV_SUCCESS)_exit(2); if(!mkvcpu())_exit(3); _exit(0); }
  if(hv_vm_create(NULL)==HV_SUCCESS){ mkvcpu(); }
  int st; waitpid(p,&st,0);
  return WIFSIGNALED(st)?128+WTERMSIG(st):WEXITSTATUS(st);
}
