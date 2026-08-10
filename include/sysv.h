/*
 * System V IPC objects, kept in a directory per IPC namespace.
 *
 * The obvious implementation - hand the guest's semget and shmget straight to
 * Darwin's, which exist - is the one that was here, and it cannot be made into
 * a namespace, because the objects are not nabi's to scope. They live in the
 * host Mac's global tables, shared with macOS itself and with every other
 * guest, so two guests that should be isolated collide on a key, and nothing
 * nabi does can separate them.
 *
 * Shared memory could not stay there for three further reasons, each on its own
 * sufficient:
 *
 *   - Darwin allows 32 segments for the whole machine (kern.sysv.shmmni), 8
 *     attachments per process, and 4MB each. Linux's defaults are 4096 and
 *     effectively unbounded. A guest that believes the second number and gets
 *     the first fails in ways that look like its own bug.
 *
 *   - A Darwin attachment cannot survive nabi's fork. fork here is fork plus
 *     exec, and a resumed child rebuilds its address space from the checkpoint:
 *     arena-backed regions are copied, file-backed ones are re-mapped from the
 *     descriptor, and a shmat region is neither, so resume panics outright.
 *     File-backed segments are re-mapped by the machinery that already exists.
 *
 *   - Anything left behind stays in the host's tables until the Mac reboots,
 *     out of only 32 slots. A guest leak became a host problem.
 *
 * So a segment is a file, and an IPC namespace is a directory of them. That
 * settles isolation (different directory, no shared key space), capacity (the
 * limits are the filesystem's), fork (a file-backed mapping is what the
 * checkpoint already knows how to rebuild), and destruction - IPC_RMID unlinks,
 * and an unlinked file's existing mappings stay valid, which is exactly Linux's
 * rule that a removed segment lives until the last attachment goes.
 *
 * Semaphores keep Darwin's tables underneath. Their capacity is not a problem
 * (semmni is 87381, not 32), blocking and the undo-on-exit that semop owes are
 * already correct there, and reimplementing a cross-process wait queue to gain
 * nothing would be the worse trade. What they take from here is the identity
 * and the scoping: the guest's key names a file in this namespace's directory,
 * and the Darwin key behind it is private to nabi, so two namespaces asking for
 * key 5 get two different semaphore arrays and neither one is the host's.
 *
 * Message queues are files too, and for the same reasons as shared memory
 * rather than the semaphores' - Darwin allows 40 queues for the whole machine,
 * 40 messages in it at once and 2048 bytes per queue, against Linux's 32000
 * queues of 16KiB. src/ipc/msg.c has the rest.
 */
#ifndef NABI_SYSV_H
#define NABI_SYSV_H

#include <stdint.h>
#include <stdbool.h>

enum sysv_kind { SYSV_SHM, SYSV_SEM, SYSV_MSG, SYSV_KINDS };

#define SYSV_MAGIC   0x76737973u        /* "sysv" */
#define SYSV_MAX_ID  4096               /* Linux's SHMMNI/SEMMNI default */

/*
 * The shared bookkeeping, mapped MAP_SHARED out of a file so that every process
 * in the namespace sees one copy. Everything IPC_STAT reports is here, because
 * Darwin's own numbers - where there are any - are about a different object.
 */
struct sysv_meta {
  uint32_t magic;
  uint32_t kind;
  int32_t  key;                 /* the guest's key, or IPC_PRIVATE */
  uint32_t mode;                /* permission bits only */
  uint32_t uid, gid, cuid, cgid;
  uint64_t size;                /* shm: bytes. sem: nsems. msg: qbytes. */
  int32_t  host_id;             /* sem: the Darwin semid. shm: -1 */
  int32_t  nattch;              /* shm only */
  int32_t  cpid, lpid;
  int32_t  removed;             /* IPC_RMID has been done */
  int64_t  atime, dtime, ctime, otime;
};

/* An open object: the meta file, mapped. Release with sysv_close. */
struct sysv_obj {
  int                id;
  int                meta_fd;
  struct sysv_meta  *m;
};

/* Which access a caller needs, in the low three bits of a mode. */
#define SYSV_R 4
#define SYSV_W 2

/*
 * semget/shmget's shared half: find the object named by `key`, creating it if
 * asked to. `size` is bytes for shm and nsems for sem. Returns the id, or a
 * negative Linux errno. On success `out` is open.
 */
int sysv_get(enum sysv_kind kind, int32_t key, uint64_t size, int l_flags,
             struct sysv_obj *out);

/* Open an existing object by id. -LINUX_EINVAL if there is none. */
int sysv_open(enum sysv_kind kind, int id, struct sysv_obj *out);
void sysv_close(struct sysv_obj *o);

/* The segment's data file, opened for the caller to mmap. shm only. */
int sysv_data_open(enum sysv_kind kind, int id, int flags);

/* IPC_RMID. Unlinks; existing mappings stay valid until they go. */
int sysv_remove(enum sysv_kind kind, int id, struct sysv_obj *o);

/* Whether the current guest credentials may have this access. */
bool sysv_perm_ok(const struct sysv_meta *m, int want);

/* Whether they may change or remove it: the owner, the creator, or root -
 * which is what Linux requires for IPC_SET and IPC_RMID. */
bool sysv_owner_ok(const struct sysv_meta *m);

/* The Darwin key standing in for a semaphore array of this namespace. */
int32_t sysv_host_key(uint64_t ino, int id);

/*
 * Every object of a kind in the current namespace, copied out. `host_id` holds
 * the guest-visible id rather than the Darwin one, since that is what a listing
 * has to show. Returns how many exist, which may exceed `max`.
 */
int sysv_list(enum sysv_kind kind, struct sysv_meta *out, int max);

/* What a message queue currently holds (src/ipc/msg.c owns the layout). */
void sysv_msg_stats(int id, uint64_t *qnum, uint64_t *cbytes);

/* How many objects of a kind exist, and the highest id in use; for IPC_INFO. */
void sysv_count(enum sysv_kind kind, int *used, int *high, uint64_t *total);

/* Record this process as the namespace's creator, so a later sweep can tell
 * whether anyone is still in it. */
void sysv_ns_claim(uint64_t ino);

/* Everything this namespace owns, gone. Called when the namespace is. */
void sysv_ns_destroy(uint64_t ino);

/* The same, but only if this process is the one that created it. */
void sysv_ns_release_owned(uint64_t ino);

/*
 * Remove the directories of namespaces that no longer have anyone in them, and
 * of boot sessions that have ended. Called once at startup.
 */
void sysv_sweep(void);

#endif
