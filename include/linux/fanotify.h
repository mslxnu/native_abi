#ifndef _LINUX_FANOTIFY_H_
#define _LINUX_FANOTIFY_H_

/* Events a mark can ask for. */
#define LINUX_FAN_ACCESS         0x00000001
#define LINUX_FAN_MODIFY         0x00000002
#define LINUX_FAN_ATTRIB         0x00000004
#define LINUX_FAN_CLOSE_WRITE    0x00000008
#define LINUX_FAN_CLOSE_NOWRITE  0x00000010
#define LINUX_FAN_OPEN           0x00000020
#define LINUX_FAN_MOVED_FROM     0x00000040
#define LINUX_FAN_MOVED_TO       0x00000080
#define LINUX_FAN_CREATE         0x00000100
#define LINUX_FAN_DELETE         0x00000200
#define LINUX_FAN_DELETE_SELF    0x00000400
#define LINUX_FAN_MOVE_SELF      0x00000800
#define LINUX_FAN_OPEN_EXEC      0x00001000

#define LINUX_FAN_Q_OVERFLOW     0x00004000
#define LINUX_FAN_FS_ERROR       0x00008000

/* The permission events, which are refused here - see src/fs/fanotify.c. */
#define LINUX_FAN_OPEN_PERM      0x00010000
#define LINUX_FAN_ACCESS_PERM    0x00020000
#define LINUX_FAN_OPEN_EXEC_PERM 0x00040000

#define LINUX_FAN_ONDIR          0x40000000
#define LINUX_FAN_EVENT_ON_CHILD 0x08000000

/* fanotify_init flags. */
#define LINUX_FAN_CLOEXEC        0x00000001
#define LINUX_FAN_NONBLOCK       0x00000002
#define LINUX_FAN_CLASS_NOTIF        0x00000000
#define LINUX_FAN_CLASS_CONTENT      0x00000004
#define LINUX_FAN_CLASS_PRE_CONTENT  0x00000008
#define LINUX_FAN_CLASS_BITS         0x0000000c
#define LINUX_FAN_UNLIMITED_QUEUE    0x00000010
#define LINUX_FAN_UNLIMITED_MARKS    0x00000020
#define LINUX_FAN_REPORT_TID         0x00000100
#define LINUX_FAN_REPORT_FID         0x00000200
#define LINUX_FAN_REPORT_DIR_FID     0x00000400
#define LINUX_FAN_REPORT_NAME        0x00000800

/* fanotify_mark flags. */
#define LINUX_FAN_MARK_ADD           0x00000001
#define LINUX_FAN_MARK_REMOVE        0x00000002
#define LINUX_FAN_MARK_DONT_FOLLOW   0x00000004
#define LINUX_FAN_MARK_ONLYDIR       0x00000008
#define LINUX_FAN_MARK_MOUNT         0x00000010
#define LINUX_FAN_MARK_IGNORED_MASK  0x00000020
#define LINUX_FAN_MARK_IGNORED_SURV_MODIFY 0x00000040
#define LINUX_FAN_MARK_FLUSH         0x00000080
#define LINUX_FAN_MARK_FILESYSTEM    0x00000100

#define LINUX_FANOTIFY_METADATA_VERSION 3

#define LINUX_FAN_ALLOW 0x01
#define LINUX_FAN_DENY  0x02

#define LINUX_FAN_NOFD (-1)

struct l_fanotify_event_metadata {
  uint32_t event_len;
  uint8_t  vers;
  uint8_t  reserved;
  uint16_t metadata_len;
  uint64_t mask;
  int32_t  fd;
  int32_t  pid;
};

/* What follows the metadata when an instance reports handles. */
#define LINUX_FAN_EVENT_INFO_TYPE_FID      1
#define LINUX_FAN_EVENT_INFO_TYPE_DFID_NAME 2
#define LINUX_FAN_EVENT_INFO_TYPE_DFID     3

struct l_fanotify_event_info_header {
  uint8_t  info_type;
  uint8_t  pad;
  uint16_t len;
};

struct l_fanotify_event_info_fid {
  struct l_fanotify_event_info_header hdr;
  int32_t  fsid[2];
  /* a struct l_file_handle and its bytes follow */
};

struct l_fanotify_response {
  int32_t  fd;
  uint32_t response;
};

#endif
