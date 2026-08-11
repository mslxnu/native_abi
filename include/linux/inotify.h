#ifndef _LINUX_INOTIFY_H_
#define _LINUX_INOTIFY_H_

/* The events themselves. */
#define LINUX_IN_ACCESS        0x00000001
#define LINUX_IN_MODIFY        0x00000002
#define LINUX_IN_ATTRIB        0x00000004
#define LINUX_IN_CLOSE_WRITE   0x00000008
#define LINUX_IN_CLOSE_NOWRITE 0x00000010
#define LINUX_IN_OPEN          0x00000020
#define LINUX_IN_MOVED_FROM    0x00000040
#define LINUX_IN_MOVED_TO      0x00000080
#define LINUX_IN_CREATE        0x00000100
#define LINUX_IN_DELETE        0x00000200
#define LINUX_IN_DELETE_SELF   0x00000400
#define LINUX_IN_MOVE_SELF     0x00000800

/* Sent by the kernel rather than asked for. */
#define LINUX_IN_UNMOUNT       0x00002000
#define LINUX_IN_Q_OVERFLOW    0x00004000
#define LINUX_IN_IGNORED       0x00008000
#define LINUX_IN_ISDIR         0x40000000

/* Options on a watch rather than events. */
#define LINUX_IN_ONLYDIR       0x01000000
#define LINUX_IN_DONT_FOLLOW   0x02000000
#define LINUX_IN_EXCL_UNLINK   0x04000000
#define LINUX_IN_MASK_CREATE   0x10000000
#define LINUX_IN_MASK_ADD      0x20000000
#define LINUX_IN_ONESHOT       0x80000000

#define LINUX_IN_ALL_EVENTS    0x00000fff

/* inotify_init1 flags, which are the open flags spelled the same way. */
#define LINUX_IN_NONBLOCK      00004000
#define LINUX_IN_CLOEXEC       02000000

struct l_inotify_event {
  int32_t  wd;
  uint32_t mask;
  uint32_t cookie;
  uint32_t len;
  /* name follows, NUL-terminated and padded so the next record is aligned */
};

#endif
