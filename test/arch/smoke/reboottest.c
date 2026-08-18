/* freestanding: reboot(2), which has no firmware to hand control back to.
 *
 * There is no machine here to restart - nabi is a Linux ABI in a process on
 * macOS - so a restart cannot be a restart. What there is, and what the caller
 * is actually asking for, is that everything running under this kernel stop,
 * and nabi's guest is exactly that set. So the halting commands end the guest,
 * which is what reboot means to an init in a namespace of its own.
 *
 * Android's init calls this at the end of its shutdown path and reports what
 * came back - "reboot call returned: Function not implemented" was a visible
 * loose end even with the guest on its way out anyway.
 *
 * What is checked, without ever ending this process:
 *
 *   - the magic numbers are enforced. They are the whole of what stops a stray
 *     call from stopping the machine, which is what Linux has them for, so a
 *     wrong one must be EINVAL and not a shutdown. Both magics are checked,
 *     and all four accepted values of the second one.
 *   - CAD_ON and CAD_OFF succeed. There is no keyboard to press ctrl-alt-del
 *     on, so there is nothing to record, but a caller toggling it needs the
 *     call to work.
 *   - an unknown command is EINVAL rather than a shutdown, which is the same
 *     argument as the magic numbers.
 *   - kexec and software suspend are ENOSYS: both name a kernel image to be
 *     entered or written, and nothing here could enter or write one. ENOSYS
 *     rather than EPERM, so a caller does not retry as root forever.
 *
 * The halting commands are deliberately not exercised: a test that verified
 * them would have nothing left to report the result with. That they end the
 * guest is checked from the outside, by run.sh.
 */
static long sys6(long n, long a, long b, long c, long d, long e, long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_write     64
#define SYS_exit      93
#define SYS_reboot   142

#define MAGIC1     0xfee1dead
#define MAGIC2      672274793
#define MAGIC2A      85072278
#define MAGIC2B     369367448
#define MAGIC2C     537993216

#define CMD_RESTART    0x01234567
#define CMD_HALT       0xCDEF0123
#define CMD_CAD_ON     0x89ABCDEF
#define CMD_CAD_OFF    0x00000000
#define CMD_POWER_OFF  0x4321FEDC
#define CMD_SW_SUSPEND 0xD000FCE2
#define CMD_KEXEC      0x45584543

#define EINVAL 22
#define ENOSYS 38

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static void putd(long v){char b[24];int i=23;b[i--]=0;int g=v<0;if(g)v=-v;
  if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(g)b[i--]='-';put(b+i+1);}

static int fails;
static void want(const char *what, long got, long expect){
  if (got == expect) { put("  ok  "); put(what); put("\n"); return; }
  fails++;
  put("  FAIL "); put(what); put(": got "); putd(got); put(", want "); putd(expect); put("\n");
}

static long rb(unsigned m1, unsigned m2, unsigned cmd){
  return sys6(SYS_reboot, (long)(int)m1, (long)(int)m2, cmd, 0, 0, 0);
}

void _start(void)
{
  /* A wrong magic must not stop the machine. CAD_OFF is used as the command
   * throughout here because it is the one that does nothing even when it is
   * accepted - so a bug that ignored the magic check cannot end the test. */
  want("a wrong first magic is EINVAL",  rb(0xdeadbeef, MAGIC2, CMD_CAD_OFF), -EINVAL);
  want("a wrong second magic is EINVAL", rb(MAGIC1, 12345678, CMD_CAD_OFF), -EINVAL);

  /* All four second magics are accepted; Linux takes any of them. */
  want("MAGIC2 is accepted",  rb(MAGIC1, MAGIC2,  CMD_CAD_OFF), 0);
  want("MAGIC2A is accepted", rb(MAGIC1, MAGIC2A, CMD_CAD_OFF), 0);
  want("MAGIC2B is accepted", rb(MAGIC1, MAGIC2B, CMD_CAD_OFF), 0);
  want("MAGIC2C is accepted", rb(MAGIC1, MAGIC2C, CMD_CAD_OFF), 0);

  want("CAD_ON succeeds",  rb(MAGIC1, MAGIC2, CMD_CAD_ON), 0);
  want("CAD_OFF succeeds", rb(MAGIC1, MAGIC2, CMD_CAD_OFF), 0);

  want("an unknown command is EINVAL", rb(MAGIC1, MAGIC2, 0x0badc0de), -EINVAL);
  want("software suspend is ENOSYS",   rb(MAGIC1, MAGIC2, CMD_SW_SUSPEND), -ENOSYS);
  want("kexec is ENOSYS",              rb(MAGIC1, MAGIC2, CMD_KEXEC), -ENOSYS);

  put(fails ? "reboot FAILED\n" : "reboot ok\n");
  sys6(SYS_exit, fails ? 1 : 0, 0,0,0,0,0);
}
