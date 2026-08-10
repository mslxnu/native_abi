/*-
 * Copyright (c) 2016 Yuichi Nishiwaki
 * Copyright (c) 2000 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer 
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _LINUX_IPC_H_
#define _LINUX_IPC_H_

/*
 * SystemV IPC defines
 */
#define	LINUX_SEMOP		1
#define	LINUX_SEMGET		2
#define	LINUX_SEMCTL		3
#define	LINUX_MSGSND		11
#define	LINUX_MSGRCV		12
#define	LINUX_MSGGET		13
#define	LINUX_MSGCTL		14
#define	LINUX_SHMAT		21
#define	LINUX_SHMDT		22
#define	LINUX_SHMGET		23
#define	LINUX_SHMCTL		24

#define	LINUX_IPC_RMID		0
#define	LINUX_IPC_SET		1
#define	LINUX_IPC_STAT		2
#define	LINUX_IPC_INFO		3

#define	LINUX_MSG_INFO	12

#define	LINUX_SHM_LOCK		11
#define	LINUX_SHM_UNLOCK	12
#define	LINUX_SHM_STAT		13
#define	LINUX_SHM_INFO		14

#define	LINUX_SHM_RDONLY	0x1000
#define	LINUX_SHM_RND		0x2000
#define	LINUX_SHM_REMAP		0x4000

/* semctl commands */
#define	LINUX_GETPID		11
#define	LINUX_GETVAL		12
#define	LINUX_GETALL		13
#define	LINUX_GETNCNT		14
#define	LINUX_GETZCNT		15
#define	LINUX_SETVAL		16
#define	LINUX_SETALL		17
#define	LINUX_SEM_STAT		18
#define	LINUX_SEM_INFO		19

/*
 * Version flags for semctl, msgctl, and shmctl commands
 * These are passed as bitflags or-ed with the actual command
 */
#define	LINUX_IPC_OLD	0	/* Old version (no 32-bit UID support on many
				   architectures) */
#define	LINUX_IPC_64	0x0100	/* New version (support 32-bit UIDs, bigger
				   message sizes, etc. */


struct l_sembuf {
  ushort sem_num;
  short sem_op;
  short sem_flg;
};

union l_semun {
  l_int		val;
  l_uintptr_t	buf;
  l_uintptr_t	array;
  l_uintptr_t	__buf;
  l_uintptr_t	__pad;
};

/*
 * The 64-bit ipc structures, which are what a modern glibc passes for every
 * command (it sets IPC_64 unconditionally). Identical on x86-64 and arm64 -
 * both use the asm-generic layout - so one definition serves both.
 */
struct l_ipc64_perm {
  l_key_t   key;
  l_uid_t   uid;
  l_gid_t   gid;
  l_uid_t   cuid;
  l_gid_t   cgid;
  l_uint    mode;
  l_ushort  seq;
  l_ushort  __pad2;
  uint64_t  __unused1;
  uint64_t  __unused2;
};

struct l_shmid64_ds {
  struct l_ipc64_perm shm_perm;
  uint64_t  shm_segsz;
  int64_t   shm_atime;
  int64_t   shm_dtime;
  int64_t   shm_ctime;
  l_int     shm_cpid;
  l_int     shm_lpid;
  uint64_t  shm_nattch;
  uint64_t  __unused4;
  uint64_t  __unused5;
};

struct l_semid64_ds {
  struct l_ipc64_perm sem_perm;
  int64_t   sem_otime;
  int64_t   sem_ctime;
  uint64_t  sem_nsems;
  uint64_t  __unused3;
  uint64_t  __unused4;
};

struct l_msqid64_ds {
  struct l_ipc64_perm msg_perm;
  int64_t   msg_stime;
  int64_t   msg_rtime;
  int64_t   msg_ctime;
  uint64_t  msg_cbytes;
  uint64_t  msg_qnum;
  uint64_t  msg_qbytes;
  l_int     msg_lspid;
  l_int     msg_lrpid;
  uint64_t  __unused4;
  uint64_t  __unused5;
};

struct l_msginfo {
  l_int msgpool, msgmap, msgmax, msgmnb, msgmni;
  l_int msgssz, msgtql;
  l_ushort msgseg;
};

struct l_shminfo64 {
  uint64_t  shmmax, shmmin, shmmni, shmseg, shmall;
  uint64_t  __unused1, __unused2, __unused3, __unused4;
};

struct l_shm_info {
  l_int     used_ids;
  uint64_t  shm_tot, shm_rss, shm_swp;
  uint64_t  swap_attempts, swap_successes;
};

struct l_seminfo {
  l_int semmap, semmni, semmns, semmnu, semmsl;
  l_int semopm, semume, semusz, semvmx, semaem;
};

/* shm_perm.mode carries this once the segment has been IPC_RMID'd. */
#define LINUX_SHM_DEST      01000
#define LINUX_SHM_LOCKED    02000

/* msgrcv's own flags. */
#define LINUX_MSG_NOERROR   010000        /* trim rather than refuse */
#define LINUX_MSG_EXCEPT    020000        /* any type but this one */
#define LINUX_MSG_COPY      040000

#define LINUX_MSG_STAT      11
#define LINUX_MSG_STAT_ANY  13

/* The *_STAT_ANY forms skip the read check; ipcs uses them when it can. */
#define LINUX_SHM_STAT_ANY  15
#define LINUX_SEM_STAT_ANY  20

struct l_ipc_perm {
  l_key_t	key;
  l_uid_t	uid;
  l_gid_t	gid;
  l_uid_t	cuid;
  l_gid_t	cgid;
  l_ushort	mode;
  l_ushort	seq;
};

#define LINUX_IPC_PRIVATE 0

#define LINUX_IPC_CREAT  00001000
#define LINUX_IPC_EXCL   00002000
#define LINUX_IPC_NOWAIT 00004000

#define LINUX_SEM_UNDO 0x1000

#endif /* _LINUX_IPC_H_ */
