/*-
 * Copyright (c) 2016 Yuichi Nishiwaki, Takaya Saeki
 * Copyright (c) 2007 Roman Divacky
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _LINUX_FILE_H_
#define	_LINUX_FILE_H_

#include <fcntl.h>

#define LINUX_AT(_)\
  DECL_LINUX(_,AT_FDCWD,             -100)\
  DECL_LINUX(_,AT_SYMLINK_NOFOLLOW,  0x100)\
  /* You must treat E_ACCESS as E_REMOVEDIR in unlinkat */\
  DECL_LINUX(_,AT_EACCESS,           0x200)\
  DECL_ALIAS(_,AT_REMOVEDIR,         0x200)\
  DECL_LINUX(_,AT_SYMLINK_FOLLOW,    0x400)\
  DECL_LINUX(_,AT_NO_AUTOMOUNT,      0x800,\
                                     LINUX_SPECIFIC)\
  DECL_LINUX(_,AT_EMPTY_PATH,        0x1000,\
                                     LINUX_SPECIFIC)\

DECLARE_CENUM(at, LINUX_AT);

/*
 * posix_fadvise advice
 */
#define	LINUX_POSIX_FADV_NORMAL		0
#define	LINUX_POSIX_FADV_RANDOM		1
#define	LINUX_POSIX_FADV_SEQUENTIAL    	2
#define	LINUX_POSIX_FADV_WILLNEED      	3
#define	LINUX_POSIX_FADV_DONTNEED      	4
#define	LINUX_POSIX_FADV_NOREUSE       	5

/*
 * mount flags
 */
#define	LINUX_MS_RDONLY		0x0001
#define	LINUX_MS_NOSUID		0x0002
#define	LINUX_MS_NODEV		0x0004
#define	LINUX_MS_NOEXEC		0x0008
#define	LINUX_MS_REMOUNT	0x0020

/*
 * common open/fcntl flags
 */
#define	LINUX_O_RDONLY		00000000
#define	LINUX_O_WRONLY		00000001
#define	LINUX_O_RDWR		00000002
#define	LINUX_O_ACCMODE		00000003
#define	LINUX_O_CREAT		00000100
#define	LINUX_O_EXCL		00000200
#define	LINUX_O_NOCTTY		00000400
#define	LINUX_O_TRUNC		00001000
#define	LINUX_O_APPEND		00002000
#define	LINUX_O_NONBLOCK	00004000
#define	LINUX_O_NDELAY		LINUX_O_NONBLOCK
#define	LINUX_O_SYNC		00010000
#define	LINUX_FASYNC		00020000
/*
 * These four are not common. asm-generic/fcntl.h defines them, and x86 takes
 * the defaults, but arch/arm64/include/uapi/asm/fcntl.h overrides all four -
 * and not by shifting them, by permuting them:
 *
 *              x86-64     arm64
 *   O_DIRECT   00040000  0200000
 *   O_LARGEFILE 00100000 0400000
 *   O_DIRECTORY 00200000  040000
 *   O_NOFOLLOW 00400000  0100000
 *
 * So a single set of values is not merely imprecise on the other arch, it is
 * actively wrong: with the x86 numbers, an arm64 guest's O_DIRECTORY arrives
 * looking like O_DIRECT and its O_NOFOLLOW like O_LARGEFILE. Both of those are
 * hints NABI drops, so both requests are silently granted - open(O_DIRECTORY)
 * succeeds on a regular file, and open(O_NOFOLLOW) follows the symlink it was
 * asked to refuse.
 *
 * The first of those broke `mv a b` for every b that already existed, because
 * coreutils asks whether the destination is a directory by opening it with
 * O_DIRECTORY rather than by calling stat. Told yes, it appended the source's
 * basename and went looking for "b/a".
 */
#if defined(__arm64__) || defined(__aarch64__)
#define	LINUX_O_DIRECTORY	00040000	/* Must be a directory */
#define	LINUX_O_NOFOLLOW	00100000	/* Do not follow links */
#define	LINUX_O_DIRECT		00200000	/* Direct disk access hint */
#define	LINUX_O_LARGEFILE	00400000
#else
#define	LINUX_O_DIRECT		00040000	/* Direct disk access hint */
#define	LINUX_O_LARGEFILE	00100000
#define	LINUX_O_DIRECTORY	00200000	/* Must be a directory */
#define	LINUX_O_NOFOLLOW	00400000	/* Do not follow links */
#endif
#define	LINUX_O_NOATIME		01000000
#define	LINUX_O_CLOEXEC		02000000
#define	LINUX_O_PATH		010000000

#define	LINUX_F_DUPFD		0
#define	LINUX_F_GETFD		1
#define	LINUX_F_SETFD		2
#define	LINUX_F_GETFL		3
#define	LINUX_F_SETFL		4
#ifndef LINUX_F_GETLK
#define	LINUX_F_GETLK		5
#define	LINUX_F_SETLK		6
#define	LINUX_F_SETLKW		7
#endif
#ifndef LINUX_F_SETOWN
#define	LINUX_F_SETOWN		8
#define	LINUX_F_GETOWN		9
#endif
#ifndef LINUX_F_SETSIG
#define	LINUX_F_SETSIG		10
#define	LINUX_F_GETSIG		11
#endif
#ifndef LINUX_F_SETOWN_EX
#define	LINUX_F_SETOWN_EX	15
#define	LINUX_F_GETOWN_EX	16
#define	LINUX_F_GETOWNER_UIDS	17
#endif

#define	LINUX_F_SPECIFIC_BASE	1024

#define	LINUX_F_SETLEASE	(LINUX_F_SPECIFIC_BASE + 0)
#define	LINUX_F_GETLEASE	(LINUX_F_SPECIFIC_BASE + 1)
#define	LINUX_F_CANCELLK	(LINUX_F_SPECIFIC_BASE + 5)
#define	LINUX_F_DUPFD_CLOEXEC	(LINUX_F_SPECIFIC_BASE + 6)
#define	LINUX_F_NOTIFY		(LINUX_F_SPECIFIC_BASE + 2)
#define	LINUX_F_SETPIPE_SZ	(LINUX_F_SPECIFIC_BASE + 7)
#define	LINUX_F_GETPIPE_SZ	(LINUX_F_SPECIFIC_BASE + 8)

/*
 * Open file description locks. Linux calls these F_OFD_*; the older names here
 * are kept because they are what the rest of the tree spelled them as, but the
 * kernel's own names are the ones a reader will be looking for.
 *
 * Unlike POSIX record locks these belong to the open file description rather
 * than to the process, so they are not dropped when some unrelated fd for the
 * same file is closed, and two descriptions in one process can contend. That
 * is exactly BSD flock()'s model, which is how Darwin can serve them at all.
 */
#define	LINUX_F_OFD_GETLK	36
#define	LINUX_F_OFD_SETLK	37
#define	LINUX_F_OFD_SETLKW	38
#define	LINUX_F_GETLKP		LINUX_F_OFD_GETLK
#define	LINUX_F_SETLKP		LINUX_F_OFD_SETLK
#define	LINUX_F_SETLKPW		LINUX_F_OFD_SETLKW

#define	LINUX_F_OWNER_TID	0
#define	LINUX_F_OWNER_PID	1
#define	LINUX_F_OWNER_PGRP	2

#ifndef LINUX_F_RDLCK
#define	LINUX_F_RDLCK		0
#define	LINUX_F_WRLCK		1
#define	LINUX_F_UNLCK		2
#endif

/*
 * getdents family of syscalls
 */
struct l_dirent {
	l_ulong		d_ino;
	l_off_t		d_off;
	l_ushort	d_reclen;
	char		d_name[LINUX_NAME_MAX + 1];
};

struct l_dirent64 {
	uint64_t	d_ino;
	int64_t		d_off;
	l_ushort	d_reclen;
	u_char		d_type;
	char		d_name[LINUX_NAME_MAX + 1];
};

/*
 * mount flags
 */
#define	LINUX_MS_RDONLY		0x0001
#define	LINUX_MS_NOSUID		0x0002
#define	LINUX_MS_NODEV		0x0004
#define	LINUX_MS_NOEXEC		0x0008
#define	LINUX_MS_REMOUNT	0x0020

/*
 * stat family of syscalls
 */

/*
 * The kernel's `struct stat` for newfstatat/fstat is architecture-specific, and
 * the two layouts are genuinely different - not just padding. x86-64 orders
 * st_nlink (8 bytes) before st_mode; aarch64 (the asm-generic layout) puts a
 * 4-byte st_mode before a 4-byte st_nlink and drops the 8-byte nlink. Getting
 * this wrong is silent: stat_darwin_to_linux fills by field name, so a mismatched
 * layout just lands each value at the wrong offset - a regular file reads back
 * with st_mode = its link count. The guest ABI follows the host arch, so the
 * host compiler's arch macro selects the right one.
 */
#if defined(__arm64__) || defined(__aarch64__)
struct l_newstat {			/* asm-generic (aarch64) */
  l_ulong		st_dev;
  l_ulong		st_ino;
  l_uint		st_mode;
  l_uint		st_nlink;
  l_uint		st_uid;
  l_uint		st_gid;
  l_ulong		st_rdev;
  l_ulong		__st_pad1;
  l_long		st_size;
  l_int			st_blksize;
  l_int			__st_pad2;
  l_long		st_blocks;
  struct l_timespec	st_atim;
  struct l_timespec	st_mtim;
  struct l_timespec	st_ctim;
  l_uint		__unused4;
  l_uint		__unused5;
};
#else
struct l_newstat {			/* x86-64 */
  l_dev_t		st_dev;
  l_ino_t		st_ino;
  l_ulong		st_nlink;
  l_uint		st_mode;
  l_uid_t		st_uid;
  l_gid_t		st_gid;
  l_uint		__st_pad1;
  l_dev_t		st_rdev;
  l_off_t		st_size;
  l_long		st_blksize;
  l_long		st_blocks;
  struct l_timespec	st_atim;
  struct l_timespec	st_mtim;
  struct l_timespec	st_ctim;
  l_long		__unused1;
  l_long		__unused2;
  l_long		__unused3;
};
#endif

/*
 * statx (syscall 291 on aarch64). Unlike struct stat, struct statx has a single
 * fixed 256-byte layout shared by every architecture, so no arch split here.
 * The field mask (stx_mask) tells the caller which fields are valid; we fill the
 * STATX_BASIC_STATS set from the same darwin stat newfstatat uses, minus btime
 * (Darwin's birthtime is available but not plumbed through the fs op yet).
 */
struct l_statx_timestamp {
  int64_t	tv_sec;
  uint32_t	tv_nsec;
  int32_t	__reserved;
};

struct l_statx {
  uint32_t	stx_mask;
  uint32_t	stx_blksize;
  uint64_t	stx_attributes;
  uint32_t	stx_nlink;
  uint32_t	stx_uid;
  uint32_t	stx_gid;
  uint16_t	stx_mode;
  uint16_t	__spare0[1];
  uint64_t	stx_ino;
  uint64_t	stx_size;
  uint64_t	stx_blocks;
  uint64_t	stx_attributes_mask;
  struct l_statx_timestamp stx_atime;
  struct l_statx_timestamp stx_btime;
  struct l_statx_timestamp stx_ctime;
  struct l_statx_timestamp stx_mtime;
  uint32_t	stx_rdev_major;
  uint32_t	stx_rdev_minor;
  uint32_t	stx_dev_major;
  uint32_t	stx_dev_minor;
  uint64_t	stx_mnt_id;
  uint32_t	stx_dio_mem_align;
  uint32_t	stx_dio_offset_align;
  uint64_t	__spare3[12];
};

#define LINUX_STATX_TYPE	0x00000001U
#define LINUX_STATX_MODE	0x00000002U
#define LINUX_STATX_NLINK	0x00000004U
#define LINUX_STATX_UID		0x00000008U
#define LINUX_STATX_GID		0x00000010U
#define LINUX_STATX_ATIME	0x00000020U
#define LINUX_STATX_MTIME	0x00000040U
#define LINUX_STATX_CTIME	0x00000080U
#define LINUX_STATX_INO		0x00000100U
#define LINUX_STATX_SIZE	0x00000200U
#define LINUX_STATX_BLOCKS	0x00000400U
#define LINUX_STATX_BASIC_STATS	0x000007ffU

/*
 * epoll. Implemented over kqueue (src/fs/epoll.c), so these are only the guest's
 * side of the ABI.
 *
 * struct epoll_event is packed on x86-64 and NOT on other architectures - the
 * kernel tags it __attribute__((packed)) only under __x86_64__, so aarch64 gets
 * the natural layout with four bytes of padding after the events word. Getting
 * that wrong shifts every data field by four bytes, and since the field is
 * usually a pointer or an index the guest then acts on a plausible-looking wrong
 * value rather than failing.
 */
struct l_epoll_event {
  uint32_t events;
  uint64_t data;
}
#ifdef __x86_64__
__attribute__((packed))
#endif
;

#define LINUX_EPOLL_CTL_ADD  1
#define LINUX_EPOLL_CTL_DEL  2
#define LINUX_EPOLL_CTL_MOD  3

#define LINUX_EPOLLIN        0x0001
#define LINUX_EPOLLPRI       0x0002
#define LINUX_EPOLLOUT       0x0004
#define LINUX_EPOLLERR       0x0008
#define LINUX_EPOLLHUP       0x0010
#define LINUX_EPOLLRDHUP     0x2000
#define LINUX_EPOLLONESHOT   (1u << 30)
#define LINUX_EPOLLET        (1u << 31)

#define LINUX_EPOLL_CLOEXEC  0x80000   /* == O_CLOEXEC */

typedef struct {
  l_int		val[2];
} l_fsid_t;

struct l_statfs {
  l_long	f_type;
  l_long	f_bsize;
  l_long	f_blocks;
  l_long	f_bfree;
  l_long	f_bavail;
  l_long	f_files;
  l_long	f_ffree;
  l_fsid_t	f_fsid;
  l_long	f_namelen;
  l_long        f_frsize;
  l_long	f_flags;
  l_long	f_spare[4];
};

#define LINUX_ST_RDONLY       0x0001
#define LINUX_ST_NOSUID       0x0002
#define LINUX_ST_NODEV        0x0004
#define LINUX_ST_NOEXEC       0x0008
#define LINUX_ST_SYNCHRONOUS  0x0010
#define LINUX_ST_VALID        0x0020
#define LINUX_ST_MANDLOCK     0x0040
#define LINUX_ST_NOATIME      0x0400
#define LINUX_ST_NODIRATIME   0x0800
#define LINUX_ST_RELATIME     0x1000

#define LINUX_FD_SETSIZE 1024

typedef unsigned long l_fd_set[LINUX_FD_SETSIZE / (8 * sizeof(long))];

/*
 * flock
 */
struct l_flock {
  l_short l_type;
  l_short l_whence;
  l_long  l_start;
  l_long  l_len;
  l_pid_t l_pid;
};

#endif	/* !_LINUX_FILE_H_ */
