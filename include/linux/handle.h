#ifndef _LINUX_HANDLE_H_
#define _LINUX_HANDLE_H_

/*
 * A file handle: a name for a file that does not go through a path.
 * The bytes after the header are the filesystem's own and opaque to the guest.
 */
struct l_file_handle {
  uint32_t handle_bytes;
  int32_t  handle_type;
  /* f_handle[] follows */
};

/* What fanotify's FID records carry to say which filesystem a handle is on. */
struct l_kernel_fsid {
  int32_t val[2];
};

#endif
