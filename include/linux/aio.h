#ifndef _LINUX_AIO_H_
#define _LINUX_AIO_H_

#include <stdint.h>

/*
 * Linux's own asynchronous I/O - the io_setup family, not io_uring.
 *
 * The layouts are fixed ABI: a guest fills a struct iocb itself and hands over
 * an array of pointers to them, so every field here has to sit where the kernel
 * puts it. The two 32-bit fields spelled out below are one PADDED() macro in the
 * kernel header, which resolves this way round on every little-endian
 * architecture - and aarch64 and x86-64 are the only two that matter here.
 */
struct l_iocb {
  uint64_t aio_data;            /* returned in io_event.data, untouched */
  uint32_t aio_key;             /* PADDED(aio_key, aio_rw_flags) */
  uint32_t aio_rw_flags;
  uint16_t aio_lio_opcode;
  int16_t  aio_reqprio;
  uint32_t aio_fildes;
  uint64_t aio_buf;
  uint64_t aio_nbytes;
  int64_t  aio_offset;
  uint64_t aio_reserved2;
  uint32_t aio_flags;
  uint32_t aio_resfd;           /* an eventfd, if IOCB_FLAG_RESFD is set */
};

struct l_io_event {
  uint64_t data;                /* the iocb's aio_data, verbatim */
  uint64_t obj;                 /* the address of the iocb, verbatim */
  int64_t  res;                 /* what the operation returned */
  int64_t  res2;                /* always 0; historical */
};

#define LINUX_IOCB_CMD_PREAD    0
#define LINUX_IOCB_CMD_PWRITE   1
#define LINUX_IOCB_CMD_FSYNC    2
#define LINUX_IOCB_CMD_FDSYNC   3
#define LINUX_IOCB_CMD_POLL     5
#define LINUX_IOCB_CMD_NOOP     6
#define LINUX_IOCB_CMD_PREADV   7
#define LINUX_IOCB_CMD_PWRITEV  8

#define LINUX_IOCB_FLAG_RESFD   (1 << 0)
#define LINUX_IOCB_FLAG_IOPRIO  (1 << 1)

/*
 * The magic the kernel stamps on the ring it maps at the context address.
 *
 * It is here to be deliberately *not* written. libaio treats aio_context_t as
 * the address of that ring and reads this field before deciding whether it can
 * answer io_getevents without a syscall; anything other than this value sends it
 * down the syscall path, which is the only path that exists here. See
 * src/fs/aio.c for why the page is mapped at all.
 */
#define LINUX_AIO_RING_MAGIC 0xa10a10a1

#endif
