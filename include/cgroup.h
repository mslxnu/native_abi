/*
 * Control groups: the hierarchy the cgroup namespace rebases a view of.
 * See src/proc/cgroup.c for what is provided and what deliberately is not.
 */
#ifndef NABI_CGROUP_H
#define NABI_CGROUP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define CGROUP_PATH_MAX 256

/*
 * The host directory a hierarchy lives in. A NULL or empty name is cgroup v2's,
 * which is the one directory there used to be; a name is one of the first
 * version's controllers, which has a tree of its own. See src/proc/cgroup.c.
 */
void cgroup_root_dir(const char *name, char *out, size_t n);
int  cgroup_hierarchy(const char *name, char *out, size_t n);
bool cgroup_is_hierarchy_path(const char *hostpath);
/* Which hierarchy a host path is in: its root, and the controller's name (empty
 * for v2). Either output may be NULL. */
bool cgroup_hierarchy_of(const char *hostpath, char *root, size_t rn,
                         char *name, size_t nn);
/* The controllers that have a hierarchy, which is the ones something mounted. */
size_t cgroup_hierarchy_names(char names[][32], size_t max);

/* Give a newly created cgroup the files every cgroup has. */
void cgroup_populate(const char *dir);

/* Which cgroup this process is in, in the hierarchy's own terms. */
const char *cgroup_current(void);
void        cgroup_set_current(const char *path);

/* /proc/<pid>/cgroup, as seen from this process's cgroup namespace. */
int cgroup_proc_text(char *out, size_t n);
/* The same, for a pid that may not be this process. See src/proc/cgroup.c. */
int cgroup_proc_text_for(int32_t nspid, char *out, size_t n);

/* The namespace's root, "/" unless this process unshared. */
const char *cgroup_ns_root(void);
void        cgroup_ns_create(uint64_t ino, const char *root);

/* Writing to cgroup.procs. */
int  cgroup_move(const char *root, const char *cgroup_path, int32_t nspid);
bool cgroup_write_procs(int fd, const char *buf, size_t size, int *out);
/* Reading it, with processes that have died left out. */
bool cgroup_read_procs(int fd, char *out, size_t size, int *ret);

/* Writing to cgroup.subtree_control: refused, no controllers can be enabled. */
bool cgroup_write_control(int fd, const char *buf, size_t size, int *out);

#endif
