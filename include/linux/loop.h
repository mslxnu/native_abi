/*
 * Loop devices: a regular file made to look like a block device.
 *
 * There is nothing behind these here - see src/fs/loop.c. They exist because
 * util-linux's mount sets one up itself, in userspace, before it will call
 * mount(2) on an image.
 */
#ifndef NABI_LINUX_LOOP_H
#define NABI_LINUX_LOOP_H

#include "linux/common.h"

#define LINUX_LOOP_SET_FD         0x4C00
#define LINUX_LOOP_CLR_FD         0x4C01
#define LINUX_LOOP_SET_STATUS     0x4C02
#define LINUX_LOOP_GET_STATUS     0x4C03
#define LINUX_LOOP_SET_STATUS64   0x4C04
#define LINUX_LOOP_GET_STATUS64   0x4C05
#define LINUX_LOOP_CHANGE_FD      0x4C06
#define LINUX_LOOP_SET_CAPACITY   0x4C07
#define LINUX_LOOP_SET_DIRECT_IO  0x4C08
#define LINUX_LOOP_SET_BLOCK_SIZE 0x4C09
#define LINUX_LOOP_CONFIGURE      0x4C0A

#define LINUX_LOOP_CTL_ADD        0x4C80
#define LINUX_LOOP_CTL_REMOVE     0x4C81
#define LINUX_LOOP_CTL_GET_FREE   0x4C82

#define LINUX_LO_FLAGS_READ_ONLY  1
#define LINUX_LO_FLAGS_AUTOCLEAR  4
#define LINUX_LO_FLAGS_PARTSCAN   8
#define LINUX_LO_FLAGS_DIRECT_IO 16

#define LINUX_LO_NAME_SIZE 64
#define LINUX_LO_KEY_SIZE  32

struct l_loop_info64 {
  uint64_t lo_device;
  uint64_t lo_inode;
  uint64_t lo_rdevice;
  uint64_t lo_offset;
  uint64_t lo_sizelimit;
  uint32_t lo_number;
  uint32_t lo_encrypt_type;
  uint32_t lo_encrypt_key_size;
  uint32_t lo_flags;
  uint8_t  lo_file_name[LINUX_LO_NAME_SIZE];
  uint8_t  lo_crypt_name[LINUX_LO_NAME_SIZE];
  uint8_t  lo_encrypt_key[LINUX_LO_KEY_SIZE];
  uint64_t lo_init[2];
};

/* LOOP_CONFIGURE, which does in one call what SET_FD and SET_STATUS64 did in
 * two. util-linux prefers it and falls back when it is refused. */
struct l_loop_config {
  uint32_t fd;
  uint32_t block_size;
  struct l_loop_info64 info;
  uint64_t __reserved[8];
};

/* The device numbers Linux uses, which anything reading a stat will compare. */
#define LINUX_LOOP_MAJOR        7
#define LINUX_LOOP_CTL_MAJOR   10
#define LINUX_LOOP_CTL_MINOR  237

#endif
