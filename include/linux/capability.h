#ifndef NOAH_LINUX_CAPABILITY_H
#define NOAH_LINUX_CAPABILITY_H

#include <stdint.h>

/*
 * The three versions of the capability ABI. A caller passes one in the header
 * and the kernel corrects it if it cannot serve it, which is how libcap
 * discovers what it is talking to: it calls capget with a version of 0 and
 * reads back the one it should have used.
 */
#define LINUX_CAPABILITY_VERSION_1  0x19980330  /* one 32-bit word */
#define LINUX_CAPABILITY_VERSION_2  0x20071026  /* two, and deprecated on arrival */
#define LINUX_CAPABILITY_VERSION_3  0x20080522  /* two, and what to use */

#define LINUX_CAPABILITY_U32S_1  1
#define LINUX_CAPABILITY_U32S_3  2

/*
 * The highest capability that exists, which is what bounds a full set. Reporting
 * bits above it set would name capabilities no kernel has defined.
 */
#define LINUX_CAP_LAST_CAP  40  /* CAP_CHECKPOINT_RESTORE */

struct l_user_cap_header {
  uint32_t version;
  int32_t  pid;
};

struct l_user_cap_data {
  uint32_t effective;
  uint32_t permitted;
  uint32_t inheritable;
};

#endif
