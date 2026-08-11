#ifndef _LINUX_IO_URING_H_
#define _LINUX_IO_URING_H_

#include <stdint.h>

/*
 * io_uring's ABI is not its three syscalls, it is a memory layout.
 *
 * A guest asks for a ring, maps three regions of the returned descriptor, and
 * from then on submits work by writing structures into that shared memory and
 * bumping a counter. Everything here is therefore fixed by the kernel and not
 * ours to choose - except the offsets *within* each region, which the kernel
 * reports in io_uring_params and a guest is required to read from there rather
 * than assume. Those are the one degree of freedom, and src/fs/io_uring.c uses
 * it to keep the layout simple.
 */

/* The three mmap offsets. They are magic numbers, not real file offsets. */
#define LINUX_IORING_OFF_SQ_RING  0x0ULL
#define LINUX_IORING_OFF_CQ_RING  0x8000000ULL
#define LINUX_IORING_OFF_SQES     0x10000000ULL

/* io_uring_setup flags. */
#define LINUX_IORING_SETUP_IOPOLL     (1U << 0)
#define LINUX_IORING_SETUP_SQPOLL     (1U << 1)
#define LINUX_IORING_SETUP_SQ_AFF     (1U << 2)
#define LINUX_IORING_SETUP_CQSIZE     (1U << 3)
#define LINUX_IORING_SETUP_CLAMP      (1U << 4)
#define LINUX_IORING_SETUP_ATTACH_WQ  (1U << 5)

/* io_uring_enter flags. */
#define LINUX_IORING_ENTER_GETEVENTS  (1U << 0)
#define LINUX_IORING_ENTER_SQ_WAKEUP  (1U << 1)

/* Features reported back to the caller. Only ones that are true are set. */
#define LINUX_IORING_FEAT_SINGLE_MMAP   (1U << 0)
#define LINUX_IORING_FEAT_NODROP        (1U << 1)
#define LINUX_IORING_FEAT_SUBMIT_STABLE (1U << 2)

/* Operations. The ones this implements are marked in src/fs/io_uring.c. */
#define LINUX_IORING_OP_NOP             0
#define LINUX_IORING_OP_READV           1
#define LINUX_IORING_OP_WRITEV          2
#define LINUX_IORING_OP_FSYNC           3
#define LINUX_IORING_OP_POLL_ADD        6
#define LINUX_IORING_OP_POLL_REMOVE     7
#define LINUX_IORING_OP_SYNC_FILE_RANGE 8
#define LINUX_IORING_OP_TIMEOUT        11
#define LINUX_IORING_OP_TIMEOUT_REMOVE 12
#define LINUX_IORING_OP_OPENAT         18
#define LINUX_IORING_OP_CLOSE          19
#define LINUX_IORING_OP_STATX          21
#define LINUX_IORING_OP_READ           22
#define LINUX_IORING_OP_WRITE          23
#define LINUX_IORING_OP_FADVISE        24
#define LINUX_IORING_OP_SEND           26
#define LINUX_IORING_OP_RECV           27
#define LINUX_IORING_OP_FALLOCATE      33
#define LINUX_IORING_OP_UNLINKAT       36
#define LINUX_IORING_OP_MKDIRAT        37

/* io_uring_register opcodes. */
#define LINUX_IORING_REGISTER_BUFFERS      0
#define LINUX_IORING_UNREGISTER_BUFFERS    1
#define LINUX_IORING_REGISTER_FILES        2
#define LINUX_IORING_UNREGISTER_FILES      3
#define LINUX_IORING_REGISTER_EVENTFD      4
#define LINUX_IORING_UNREGISTER_EVENTFD    5
#define LINUX_IORING_REGISTER_FILES_UPDATE 6

/* fsync_flags */
#define LINUX_IORING_FSYNC_DATASYNC (1U << 0)

/* timeout_flags. UPDATE turns TIMEOUT_REMOVE from a cancellation into a change
 * of deadline, which is why it cannot simply be ignored: a caller asking to
 * extend a timeout would have it cancelled instead. */
#define LINUX_IORING_TIMEOUT_ABS    (1U << 0)
#define LINUX_IORING_TIMEOUT_UPDATE (1U << 1)

/*
 * A submission entry: 64 bytes, and the unions matter. A caller fills one of
 * the alternatives depending on the opcode, so the names below are the ones
 * this implementation reads rather than the full set the kernel documents.
 */
struct l_io_uring_sqe {
  uint8_t  opcode;
  uint8_t  flags;
  uint16_t ioprio;
  int32_t  fd;
  uint64_t off;                 /* or addr2 */
  uint64_t addr;                /* or splice_off_in */
  uint32_t len;
  uint32_t rw_flags;            /* or fsync_flags, open_flags, statx_flags... */
  uint64_t user_data;           /* returned in the completion, untouched */
  uint16_t buf_index;           /* or buf_group */
  uint16_t personality;
  int32_t  splice_fd_in;        /* or file_index */
  uint64_t addr3;
  uint64_t __pad2[1];
};

/* A completion entry: 16 bytes. */
struct l_io_uring_cqe {
  uint64_t user_data;
  int32_t  res;
  uint32_t flags;
};

/*
 * Where each field sits inside the mapped regions. The kernel fills these in
 * and the caller must use them; nothing about them is guessable, which is what
 * makes choosing a simple layout safe.
 */
struct l_io_sqring_offsets {
  uint32_t head, tail, ring_mask, ring_entries, flags, dropped, array, resv1;
  uint64_t resv2;
};

struct l_io_cqring_offsets {
  uint32_t head, tail, ring_mask, ring_entries, overflow, cqes, flags, resv1;
  uint64_t resv2;
};

struct l_io_uring_params {
  uint32_t sq_entries;
  uint32_t cq_entries;
  uint32_t flags;
  uint32_t sq_thread_cpu;
  uint32_t sq_thread_idle;
  uint32_t features;
  uint32_t wq_fd;
  uint32_t resv[3];
  struct l_io_sqring_offsets sq_off;
  struct l_io_cqring_offsets cq_off;
};

#endif
