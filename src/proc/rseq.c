/*
 * rseq: registered, and deliberately refused.
 *
 * glibc 2.35 and later register a restartable-sequence area on every thread it
 * starts, so this arrives eight times before a guest has run any of its own
 * code. Left unregistered it was answered by the default arm and written to the
 * warning log as "unimplemented syscall: 293" - which is a false alarm about
 * something that is working correctly, and a false alarm is worse than silence
 * because somebody eventually goes and investigates it.
 *
 * The answer is ENOSYS, and that is the *right* answer rather than a placeholder
 * for a better one. Linux returns exactly this when built without CONFIG_RSEQ,
 * glibc handles it by setting __rseq_size to zero, and everything that would
 * have used a restartable sequence falls back to atomics. Nothing is lost but
 * some speed nobody here can measure.
 *
 * Accepting the registration would be the harmful thing to do. A restartable
 * sequence is a critical section the *kernel* promises to abort when the thread
 * is preempted or migrated, and there is no scheduler here to make that promise:
 * nabi's guest threads are host threads, scheduled by Darwin, with nothing
 * watching them. A program told its sequences were registered would run per-CPU
 * updates that are only safe because they are aborted, and they would not be.
 *
 * The obvious repair - hand each thread a cpu_id of its own, so that no two
 * threads share a per-CPU slot and no abort is ever needed - does not survive
 * contact with how the values are used. Per-CPU arrays are sized by the number
 * of CPUs the program believes exist, so an id beyond that count is an index
 * past the end of somebody's array. It is a correct idea that cannot be given
 * correct numbers here.
 */
#include "common.h"
#include "noah.h"
#include "linux/common.h"
#include "linux/errno.h"

DEFINE_SYSCALL(rseq, gaddr_t, rseq_ptr, uint32_t, rseq_len, int, flags,
               uint32_t, sig)
{
  return -LINUX_ENOSYS;
}
