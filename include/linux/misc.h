/*-
 * Copyright (c) 2016 Yuichi Nishiwaki, Takaya Saeki
 * Copyright (c) 2015 Dmitry Chagin
 * Copyright (c) 2013 Dmitry Chagin
 * Copyright (c) 2002 Doug Rabson
 * Copyright (c) 1994-1996 Søren Schmidt
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
 *    derived from this software without specific prior written permission
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

#ifndef _AMD64_LINUX_H_
#define	_AMD64_LINUX_H_

typedef struct {
  l_time_t	tv_sec;
  l_suseconds_t	tv_usec;
} l_timeval;

/*
 * Miscellaneous
 */
#define LINUX_CTL_MAXNAME	10

#define LINUX_MAX_ARG_STRLEN    (0x1000 * 32)
#define LINUX_MAX_ARG_STRINGS   0x7FFFFFFF

#define LINUX_AT_COUNT		19	/* Count of used aux entry types. */

struct l___sysctl_args
{
  l_uintptr_t	name;
  l_int		nlen;
  l_uintptr_t	oldval;
  l_uintptr_t	oldlenp;
  l_uintptr_t	newval;
  l_size_t	newlen;
  l_ulong	__spare[4];
};

/* Scheduling policies */
#define	LINUX_SCHED_OTHER	0
#define	LINUX_SCHED_FIFO	1
#define	LINUX_SCHED_RR		2
#define	LINUX_SCHED_BATCH	3
#define	LINUX_SCHED_IDLE	5
#define	LINUX_SCHED_DEADLINE	6

/* OR'd into the policy by sched_setscheduler; not a policy of its own. */
#define	LINUX_SCHED_RESET_ON_FORK	0x40000000

/*
 * The priority ranges Linux reports for each policy. These describe the
 * interface rather than what this host can deliver: asking what a policy's
 * range *is* is a different question from asking to be scheduled under it, and
 * a guest comparing its priority against the maximum should get the numbers it
 * would get anywhere else.
 */
#define	LINUX_SCHED_RT_PRIO_MIN	1
#define	LINUX_SCHED_RT_PRIO_MAX	99

struct l_sched_param {
	int	sched_priority;
};

/*
 * sched_attr: the sched_setattr / sched_getattr layout.  The size field
 * versions the structure; a caller that passes a smaller size is asking
 * for an older layout, and the kernel fills only the fields that version
 * covers.  NABI reports v1 (56 bytes) which adds sched_flags.
 */
#define LINUX_SCHED_ATTR_VERSION  1

struct l_sched_attr {
	l_uint		size;
	l_uint		sched_policy;
	l_ulong		sched_flags;
	l_int		sched_nice;
	l_uint		sched_priority;
	l_ulong		sched_runtime;
	l_ulong		sched_deadline;
	l_ulong		sched_period;
};

/* sched_attr flags */
#define LINUX_SCHED_FLAG_RESET_ON_FORK  0x01

/*
 * ustat: the struct filled by the ustat(2) syscall.  Obsolete on Linux,
 * present only on x86-64 (no arm64 number).  The layout matches the
 * x86-64 ABI: __daddr_t (int32) + padding + __ino_t (uint64) + name.
 * NABI fills f_tfree from the host free-block count and f_tinode from
 * the host free-inode count; f_fname and f_fpack are zeroed.
 */
struct l_ustat {
  l_int       f_tfree;    /* Number of free blocks. */
  l_uint      _pad;       /* alignment */
  l_ulong     f_tinode;   /* Number of free inodes. */
  char        f_fname[6];
  char        f_fpack[6];
};

/*
 * struct tms: filled by times(2), the process CPU time counters.
 * Fields are in clock ticks (100 Hz, matching AT_CLKTCK in auxval).
 */
struct l_tms {
  l_clock_t   tms_utime;   /* User CPU time */
  l_clock_t   tms_stime;   /* System CPU time */
  l_clock_t   tms_cutime;  /* User CPU time of children */
  l_clock_t   tms_cstime;  /* System CPU time of children */
};

/* Resource limits */
#define	LINUX_RLIMIT_CPU	0
#define	LINUX_RLIMIT_FSIZE	1
#define	LINUX_RLIMIT_DATA	2
#define	LINUX_RLIMIT_STACK	3
#define	LINUX_RLIMIT_CORE	4
#define	LINUX_RLIMIT_RSS	5
#define	LINUX_RLIMIT_NPROC	6
#define	LINUX_RLIMIT_NOFILE	7
#define	LINUX_RLIMIT_MEMLOCK	8
#define	LINUX_RLIMIT_AS		9	/* Address space limit */
/*
 * The six Linux has that Darwin does not. They still have to exist: pam_limits
 * walks every resource on every session, and one EINVAL from the middle of that
 * walk fails the whole PAM stack - which is how sudo came to report
 * "pam_open_session: Permission denied" while having nothing to do with
 * permissions.
 */
#define	LINUX_RLIMIT_LOCKS	10
#define	LINUX_RLIMIT_SIGPENDING	11
#define	LINUX_RLIMIT_MSGQUEUE	12
#define	LINUX_RLIMIT_NICE	13
#define	LINUX_RLIMIT_RTPRIO	14
#define	LINUX_RLIMIT_RTTIME	15

#define	LINUX_RLIM_NLIMITS	16

#define	LINUX_RLIM_INFINITY	(~0UL)

struct l_rlimit {
  l_ulong		rlim_cur;
  l_ulong		rlim_max;
};

struct l_rusage {
  l_timeval	ru_utime;
  l_timeval	ru_stime;
  l_long	ru_maxrss;
  l_long	ru_ixrss;
  l_long	ru_idrss;
  l_long	ru_isrss;
  l_long	ru_minflt;
  l_long	ru_majflt;
  l_long	ru_nswap;
  l_long	ru_inblock;
  l_long	ru_oublock;
  l_long	ru_msgsnd;
  l_long	ru_msgrcv;
  l_long	ru_nsignals;
  l_long	ru_nvcsw;
  l_long	ru_nivcsw;
} __attribute__ ((packed));

/*
 * poll()
 */
#define	LINUX_POLLIN		0x0001
#define	LINUX_POLLPRI		0x0002
#define	LINUX_POLLOUT		0x0004
#define	LINUX_POLLERR		0x0008
#define	LINUX_POLLHUP		0x0010
#define	LINUX_POLLNVAL		0x0020
#define	LINUX_POLLRDNORM	0x0040
#define	LINUX_POLLRDBAND	0x0080
#define	LINUX_POLLWRNORM	0x0100
#define	LINUX_POLLWRBAND	0x0200
#define	LINUX_POLLMSG		0x0400

struct l_pollfd {
  l_int		fd;
  l_short	events;
  l_short	revents;
};


#define	LINUX_CLONE_VM		   0x00000100
#define	LINUX_CLONE_FS		   0x00000200
#define	LINUX_CLONE_FILES	   0x00000400
#define	LINUX_CLONE_SIGHAND	   0x00000800
#define	LINUX_CLONE_PID		   0x00001000 /* No longer exist in Linux */
#define LINUX_CLONE_PTRACE         0x00002000
#define	LINUX_CLONE_VFORK	   0x00004000
#define	LINUX_CLONE_PARENT	   0x00008000
#define	LINUX_CLONE_THREAD	   0x00010000
#define LINUX_CLONE_NEWNS          0x00020000
#define LINUX_CLONE_SYSVSEM        0x00040000
#define	LINUX_CLONE_SETTLS	   0x00080000
#define	LINUX_CLONE_PARENT_SETTID  0x00100000
#define	LINUX_CLONE_CHILD_CLEARTID 0x00200000
#define	LINUX_CLONE_DETACHED	   0x00400000
#define	LINUX_CLONE_UNTRACED       0x00800000
#define	LINUX_CLONE_CHILD_SETTID   0x01000000
#define LINUX_CLONE_NEWUTS         0x04000000
#define LINUX_CLONE_NEWIPC         0x08000000
#define LINUX_CLONE_NEWUSER        0x10000000
#define LINUX_CLONE_NEWPID         0x20000000
#define LINUX_CLONE_NEWNET         0x40000000
#define LINUX_CLONE_NEWCGROUP      0x02000000
#define LINUX_CLONE_PIDFD     0x00001000
/*
 * Reset the child's signal handlers. Bit 32, so it only fits a 64-bit flags
 * word - which is why Linux takes it through clone3 and, on 64-bit, through
 * clone as well. glibc's posix_spawn asks for it together with CLONE_VM and
 * CLONE_VFORK.
 */
#define LINUX_CLONE_CLEAR_SIGHAND 0x100000000ULL
#define LINUX_CLONE_NEWTIME        0x00000080
#define LINUX_CLONE_IO             0x80000000

#define LINUX_ARCH_SET_GS		0x1001
#define LINUX_ARCH_SET_FS		0x1002
#define LINUX_ARCH_GET_FS		0x1003
#define LINUX_ARCH_GET_GS		0x1004

/* linux sysinfo */
struct l_sysinfo {
  l_long		uptime;		/* Seconds since boot */
  l_ulong		loads[3];	/* 1, 5, and 15 minute load averages */
#define LINUX_SYSINFO_LOADS_SCALE 65536
  l_ulong		totalram;	/* Total usable main memory size */
  l_ulong		freeram;	/* Available memory size */
  l_ulong		sharedram;	/* Amount of shared memory */
  l_ulong		bufferram;	/* Memory used by buffers */
  l_ulong		totalswap;	/* Total swap space size */
  l_ulong		freeswap;	/* swap space still available */
  l_ushort		procs;		/* Number of current processes */
  l_ushort		pads;
  l_ulong		totalhigh;
  l_ulong		freehigh;
  l_uint		mem_unit;
  char			_f[20-2*sizeof(l_long)-sizeof(l_int)];	/* padding */
};

#define	LINUX_WNOHANG		0x00000001
#define	LINUX_WUNTRACED		0x00000002
#define	LINUX_WSTOPPED		LINUX_WUNTRACED
#define	LINUX_WEXITED		0x00000004
#define	LINUX_P_ALL		0
#define	LINUX_P_PID		1
#define	LINUX_P_PGID		2
#define	LINUX_P_PIDFD		3

#define	LINUX_WCONTINUED	0x00000008
#define	LINUX_WNOWAIT		0x01000000

/* reboot(2): the magic numbers that say the caller meant it, and the commands. */
#define	LINUX_REBOOT_MAGIC1	0xfee1dead
#define	LINUX_REBOOT_MAGIC2	672274793
#define	LINUX_REBOOT_MAGIC2A	85072278
#define	LINUX_REBOOT_MAGIC2B	369367448
#define	LINUX_REBOOT_MAGIC2C	537993216

#define	LINUX_REBOOT_CMD_RESTART	0x01234567
#define	LINUX_REBOOT_CMD_HALT		0xCDEF0123
#define	LINUX_REBOOT_CMD_CAD_ON		0x89ABCDEF
#define	LINUX_REBOOT_CMD_CAD_OFF	0x00000000
#define	LINUX_REBOOT_CMD_POWER_OFF	0x4321FEDC
#define	LINUX_REBOOT_CMD_RESTART2	0xA1B2C3D4
#define	LINUX_REBOOT_CMD_SW_SUSPEND	0xD000FCE2
#define	LINUX_REBOOT_CMD_KEXEC		0x45584543

#endif /* !_AMD64_LINUX_H_ */
