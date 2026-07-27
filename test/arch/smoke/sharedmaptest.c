/* freestanding: MAP_SHARED writes must reach the file.
 *
 * Everything else file-backed is copied into guest memory here - the host
 * refuses a PROT_EXEC file map and wants a granule-aligned offset - but a copy
 * cannot give MAP_SHARED its meaning, which is that the writes are the file's.
 * So a shared mapping is mapped for real, and this checks it: write through the
 * mapping, then read the file back with read(2) and require the bytes to be
 * there. A private mapping is checked alongside, which must NOT write back. */
static long sys6(long n,long a,long b,long c,long d,long e,long f){
  register long x8 asm("x8")=n; register long x0 asm("x0")=a; register long x1 asm("x1")=b;
  register long x2 asm("x2")=c; register long x3 asm("x3")=d; register long x4 asm("x4")=e; register long x5 asm("x5")=f;
  asm volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory"); return x0;
}
#define SYS_read   63
#define SYS_write  64
#define SYS_exit   93
#define SYS_openat 56
#define SYS_lseek  62
#define SYS_mmap   222
#define SYS_munmap 215
#define SYS_ftruncate 46
#define SYS_clone  220
#define SYS_wait4  260
#define AT_FDCWD -100
#define O_RDWR   2
#define O_CREAT  0100
#define O_TRUNC  01000
#define PROT_RW  3
#define MAP_SHARED  1
#define MAP_PRIVATE 2
#define SZ 16384

static void put(const char*m){int i=0;while(m[i])i++;sys6(SYS_write,1,(long)m,i,0,0,0);}
static int ok = 1;

int _open_tmp(void){
  return (int) sys6(SYS_openat, AT_FDCWD, (long)"/sharedmap.tmp",
                    O_RDWR|O_CREAT|O_TRUNC, 0600, 0, 0);
}

void _start(void){
  int fd = _open_tmp();
  if (fd < 0) { put("open FAIL\n"); sys6(SYS_exit,1,0,0,0,0,0); }
  if (sys6(SYS_ftruncate, fd, SZ, 0,0,0,0) < 0) { put("ftruncate FAIL\n"); sys6(SYS_exit,2,0,0,0,0,0); }

  /* shared: the write is the file's */
  long p = sys6(SYS_mmap, 0, SZ, PROT_RW, MAP_SHARED, fd, 0);
  if (p < 0) { put("mmap shared FAIL\n"); sys6(SYS_exit,3,0,0,0,0,0); }
  *(volatile long *)p = 0x511aeed;
  sys6(SYS_munmap, p, SZ, 0,0,0,0);

  long back = 0;
  sys6(SYS_lseek, fd, 0, 0 /*SEEK_SET*/, 0,0,0);
  if (sys6(SYS_read, fd, (long)&back, sizeof back, 0,0,0) != sizeof back) {
    put("read FAIL\n"); sys6(SYS_exit,4,0,0,0,0,0);
  }
  if (back != 0x511aeed) { put("shared write did NOT reach the file\n"); ok = 0; }

  /* private: the write is this process's alone */
  long q = sys6(SYS_mmap, 0, SZ, PROT_RW, MAP_PRIVATE, fd, 0);
  if (q < 0) { put("mmap private FAIL\n"); sys6(SYS_exit,5,0,0,0,0,0); }
  *(volatile long *)q = 0x0badbeef;
  sys6(SYS_munmap, q, SZ, 0,0,0,0);

  back = 0;
  sys6(SYS_lseek, fd, 0, 0, 0,0,0);
  sys6(SYS_read, fd, (long)&back, sizeof back, 0,0,0);
  if (back != 0x511aeed) { put("private write leaked to the file\n"); ok = 0; }

  /* shared across fork: the child's write must be visible here */
  long r = sys6(SYS_mmap, 0, SZ, PROT_RW, MAP_SHARED, fd, 0);
  if (r < 0) { put("mmap shared2 FAIL\n"); sys6(SYS_exit,7,0,0,0,0,0); }
  *(volatile long *)r = 1;
  long pid = sys6(SYS_clone, 17 /*SIGCHLD*/, 0,0,0,0,0);
  if (pid == 0) { *(volatile long *)r = 0xfeed; sys6(SYS_exit, 0, 0,0,0,0,0); }
  if (pid < 0) { put("fork FAIL\n"); sys6(SYS_exit,8,0,0,0,0,0); }
  long st = 0; sys6(SYS_wait4, -1, (long)&st, 0,0,0,0);
  if (*(volatile long *)r != 0xfeed) { put("not shared across fork\n"); ok = 0; }

  if (ok) put("shared map ok\n");
  sys6(SYS_exit, ok ? 0 : 6, 0,0,0,0,0);
}
