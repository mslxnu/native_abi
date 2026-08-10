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

/* The host directory the hierarchy lives in. */
void cgroup_root_dir(char *out, size_t n);
int  cgroup_hierarchy(char *out, size_t n);
bool cgroup_is_hierarchy_path(const char *hostpath);

/* Give a newly created cgroup the files every cgroup has. */
void cgroup_populate(const char *dir);

/* Which cgroup this process is in, in the hierarchy's own terms. */
const char *cgroup_current(void);
void        cgroup_set_current(const char *path);

/* /proc/<pid>/cgroup, as seen from this process's cgroup namespace. */
int cgroup_proc_text(char *out, size_t n);

/* The namespace's root, "/" unless this process unshared. */
const char *cgroup_ns_root(void);
void        cgroup_ns_create(uint64_t ino, const char *root);

/* Writing to cgroup.procs. */
int  cgroup_move(const char *cgroup_path, int32_t nspid);
bool cgroup_write_procs(int fd, const char *buf, size_t size, int *out);

#endif
