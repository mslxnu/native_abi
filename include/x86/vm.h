#ifndef NOAH_X86_VM_H
#define NOAH_X86_VM_H

#include <stdint.h>

/* Page geometry is shared with aarch64; only the descriptor bits below are
 * x86-specific. See include/page.h. */
#include "page.h"

/* pages */

#define PTE_P           0x001   // Present
#define PTE_W           0x002   // Writeable
#define PTE_U           0x004   // User
#define PTE_PS          0x080   // Page Size
#define PTE_NX          0x8000000000000000UL // No Execute

/* idt */
typedef unsigned uint;

struct gate_desc {
  uint64_t offset_low:16;
  uint64_t selector:16;
  uint64_t ist:3;
  uint64_t zero0:5;
  uint64_t type:4;
  uint64_t zero1:3;
  uint64_t dpl:2;
  uint64_t p:1;
  uint64_t offset_high:48;
  uint64_t zero2:32;
} __attribute__ ((packed));

/* VM parameter */
/*
 * The guest's main stack, mapped whole at exec. Shared with arm64, which
 * includes this header for it.
 *
 * Eight megabytes because that is Linux's default RLIMIT_STACK, and the number
 * a guest is told has to be the number it has. It was two, while
 * getrlimit(RLIMIT_STACK) passed the *host* process's limit through - so a guest
 * was promised eight megabytes of stack and given two. bionic believes the
 * limit: pthread_attr_getstack takes the top of the stack from /proc/self/maps
 * and subtracts rlim_cur, hands ART a range six megabytes of which was never
 * mapped, and the first deep call in the runtime's startup writes off the
 * bottom. zygote died of it with the fault address equal to the stack pointer.
 *
 * Linux grows the stack vma on demand up to the limit rather than mapping it
 * all at once; this maps it all at once. The guest cannot tell the two apart by
 * reading or writing - what it is told, and what it may touch, are the same
 * either way - only by reading /proc/<pid>/maps, where this shows the whole
 * reservation where Linux would show how far the stack has actually come down.
 * Untouched pages cost nothing in either arrangement: the arena is a sparse
 * file and a page is backed when it is first written.
 *
 * Growing on demand would mean extending a region downwards, and the arena
 * extends upwards only - so it would be a second region, and then the one
 * growsdown vma Linux reports would be two lines in maps with a seam in the
 * middle of the stack. Raising the number is the smaller lie.
 */
#define STACK_SIZE (8 << 20)
#define STACK_TOP  0x0000007fc0000000ULL

/* segments */
#define GSEL(s,r) (((s)<<3) | r)        /* a global selector */

#define DESC_UNUSABLE 0x00010000

#define SEG_NULL        0x0
#define SEG_CODE        0x1
#define SEG_DATA        0x2

#define SEG(type, base, lim, dpl)      \
  (struct segment_desc) {              \
    .limit_low = (lim) & 0xffff,       \
    .base_low = (base) & 0xffffff,     \
    .type = (type),                    \
    .dpl = (dpl),                      \
    .p = 1,                            \
    .limit_high = ((lim) >> 16) & 0xf, \
    .avl = 0,                          \
    .l = 1,                            \
    .db = 1,                           \
    .gran = 1,                         \
    .base_high = ((base) >> 24),       \
    .xx1 = 0,                          \
    .mbz = 0,                          \
    .xx2 = 0,                          \
  }

struct segment_desc {
  u_int64_t offset_low:16;	/* segment extent (lsb) */
  u_int64_t base_low:24;		/* segment base address (lsb) */
  u_int64_t type:5;		/* segment type */
  u_int64_t dpl:2;		/* segment descriptor priority level */
  u_int64_t p:1;			/* segment descriptor present */
  u_int64_t limit_high:4;		/* segment extent (msb) */
  u_int64_t avl:1;		/* unused */
  u_int64_t l:1;			/* unused */
  u_int64_t db:1;			/* unused */
  u_int64_t gran:1;		/* limit granularity (byte/page units)*/
  u_int64_t base_high:40 __attribute__ ((packed));/* segment base address  (msb) */
  u_int64_t xx1:8;
  u_int64_t mbz:5;		/* MUST be zero */
  u_int64_t xx2:19;
} __attribute__ ((packed));

#endif
