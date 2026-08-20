/*
 * userfaultfd: kernel-side definitions for the userfaultfd mechanism.
 *
 * Provides on-demand page resolution for PROT_NONE regions: a guest thread
 * that touches an unmaterialised page blocks until a resolver thread feeds
 * the page content through UFFDIO_COPY.  Android uses this for the ART GC's
 * concurrent compactor and for the app freezer's freeze/thaw cycle.
 *
 * The structs mirror the Linux UAPI layout exactly so that copy_from_user /
 * copy_to_user can move them between guest and host without translation.
 */

#ifndef _LINUX_USERFAULTFD_H
#define _LINUX_USERFAULTFD_H

#include "common.h"
#include <stdint.h>
#include <pthread.h>
#include "util/list.h"

/* ── UAPI struct layouts (must match the guest header byte-for-byte) ───── */

struct uffd_msg {
  uint8_t   event;
  uint8_t   reserved1;
  uint16_t  reserved2;
  uint32_t  reserved3;
  union {
    struct {
      uint64_t flags;
      uint64_t address;
    } pagefault;
    struct {
      uint64_t reserved1;
      uint64_t reserved2;
      uint64_t reserved3;
    } reserved;
  } arg;
} __attribute__((packed));

#define UFFD_EVENT_PAGEFAULT  0x12

/* flags for UFFD_EVENT_PAGEFAULT */
#define UFFD_PAGEFAULT_FLAG_WRITE  (1 << 0)

struct uffdio_api {
  uint64_t api;
  uint64_t features;
  uint64_t ioctls;
};

struct uffdio_range {
  uint64_t start;
  uint64_t len;
};

struct uffdio_register {
  struct uffdio_range range;
  uint64_t mode;
  uint64_t ioctls;    /* out: which range ioctls are available */
};

#define UFFDIO_REGISTER_MODE_MISSING  (1ULL << 0)

struct uffdio_copy {
  uint64_t dst;
  uint64_t src;
  uint64_t len;
  uint64_t mode;
  int64_t  copy;      /* out: bytes copied */
};

struct uffdio_zeropage {
  struct uffdio_range range;
  uint64_t mode;
  int64_t  zeropage;  /* out: bytes zeroed */
};

/* ── UFFDIO API version and feature flags ──────────────────────────────── */

#define UFFD_API  0x000000AAULL

/* ── ioctl command numbers (generic Linux encoding, same on arm64 & x86) ── */

#define UFFDIO          0xAA

#define _UFFDIO_REGISTER    0x00
#define _UFFDIO_UNREGISTER  0x01
#define _UFFDIO_WAKE        0x02
#define _UFFDIO_COPY        0x03
#define _UFFDIO_ZEROPAGE    0x04
#define _UFFDIO_API         0x3F

/* direction bits (same encoding as <asm-generic/ioctl.h>) */
#define _UFFDIOC_IN     0x40000000
#define _UFFDIOC_OUT    0x80000000
#define _UFFDIOC_INOUT  (_UFFDIOC_IN | _UFFDIOC_OUT)

#define _UFFDIOC_IOC(dir, type, nr, size) \
  ((dir) | ((uint64_t)(size) << 16) | ((type) << 8) | (nr))

#define UFFDIO_API        _UFFDIOC_IOC(_UFFDIOC_INOUT, UFFDIO, _UFFDIO_API,        24)
#define UFFDIO_REGISTER   _UFFDIOC_IOC(_UFFDIOC_INOUT, UFFDIO, _UFFDIO_REGISTER,   24)
#define UFFDIO_UNREGISTER _UFFDIOC_IOC(_UFFDIOC_OUT,   UFFDIO, _UFFDIO_UNREGISTER, 16)
#define UFFDIO_WAKE       _UFFDIOC_IOC(_UFFDIOC_OUT,   UFFDIO, _UFFDIO_WAKE,       16)
#define UFFDIO_COPY       _UFFDIOC_IOC(_UFFDIOC_INOUT, UFFDIO, _UFFDIO_COPY,       32)
#define UFFDIO_ZEROPAGE   _UFFDIOC_IOC(_UFFDIOC_INOUT, UFFDIO, _UFFDIO_ZEROPAGE,   32)

/* ── kernel-side per-uffd state ────────────────────────────────────────── */

#define UFFD_MAX_RANGES   256
#define UFFD_MAX_PENDING  128

struct uffd_range {
  uint64_t start;
  uint64_t len;
};

/*
 * One pending fault, tracked from the moment the faulting thread blocks
 * until the resolver calls UFFDIO_COPY (or the fault is otherwise cleared).
 *
 * Each pending fault has its own condvar so the faulting thread can sleep
 * independently of every other fault.  The resolver matches by address.
 */
struct uffd_pending_fault {
  struct list_head  list;
  int               uffd_idx;     /* index into uffds[] */
  uint64_t          addr;         /* faulting guest address */
  bool              resolved;     /* set by UFFDIO_COPY / UFFDIO_ZEROPAGE */
  pthread_mutex_t   lock;
  pthread_cond_t    cond;
};

/*
 * Per-descriptor state for a userfaultfd.  Indexed by the guest-visible fd;
 * the static array uffds[] is scanned linearly (UFFD_MAX is small).
 */
struct uffd_state {
  int               fd;           /* guest-visible fd (host socketpair end 0) */
  int               wr;           /* host socketpair end 1 — always nonblock  */
  bool              api_set;      /* UFFDIO_API has been called               */
  uint64_t          api;          /* negotiated API version                    */
  uint64_t          features;     /* negotiated features (currently 0)         */
  struct uffd_range ranges[UFFD_MAX_RANGES];
  int               nr_ranges;

  /* ring buffer of pending fault messages */
  struct uffd_msg   pending[UFFD_MAX_PENDING];
  int               nr_pending;
  int               head;         /* next slot to dequeue from                 */
  int               tail;         /* next slot to enqueue to                   */

  pthread_mutex_t   lock;
};

/* ── kernel-side API ───────────────────────────────────────────────────── */

void  userfaultfd_init(void);

/* Whether `fd` belongs to a userfaultfd. */
bool  userfaultfd_is(int fd);

/* Intercept read(2) on a uffd — returns true if handled. */
bool  userfaultfd_read(int fd, char *out, size_t size, int *ret);

/* Intercept ioctl(2) on a uffd — returns true if handled. */
bool  userfaultfd_ioctl(int fd, int cmd, uint64_t val0, int *ret);

/* Intercept close(2) on a uffd. */
void  userfaultfd_close(int fd);

/*
 * Called from the page-fault handler when addr_ok() fails.  Returns true
 * if the address is in a registered range and the fault has been queued
 * (the thread is blocked until the resolver calls UFFDIO_COPY).
 * Returns false if the address is not covered — caller should SIGSEGV.
 */
bool  userfaultfd_handle_fault(uint64_t addr, int fault_access);

#endif /* _LINUX_USERFAULTFD_H */
