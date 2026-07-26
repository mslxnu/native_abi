/*
 * Writing and reading a guest handover. See include/checkpoint.h for why this
 * exists and what shape it takes.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "noah.h"
#include "vmm.h"
#include "mm.h"
#include "checkpoint.h"

/* From src/mm/pt_arm64.c and lib/vmm_arm64.c. */
size_t pt_snapshot(uint64_t *ipa_brk_out, uint64_t *l1_ipa_out,
                   struct checkpoint_pt_chunk *out, size_t max);
size_t vmm_arm64_s2_snapshot(struct checkpoint_s2 *out, size_t max);

/* write(2) that does not give up early. A short write on a pipe is normal. */
static int
write_all(int fd, const void *buf, size_t len)
{
  const char *p = buf;
  while (len > 0) {
    ssize_t n = write(fd, p, len);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    p += n;
    len -= (size_t) n;
  }
  return 0;
}

static int
read_all(int fd, void *buf, size_t len)
{
  char *p = buf;
  while (len > 0) {
    ssize_t n = read(fd, p, len);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (n == 0) {                 /* truncated checkpoint */
      errno = EPROTO;
      return -1;
    }
    p += n;
    len -= (size_t) n;
  }
  return 0;
}

static size_t
count_regions(void)
{
  size_t n = 0;
  struct list_head *l;
  list_for_each (l, &proc.mm->mm_regions)
    n++;
  return n;
}

int
checkpoint_write(int fd)
{
  size_t nr_regions = count_regions();

  /*
   * Ask the two snapshot sources how much they hold before allocating: both
   * report their true count even when handed a smaller buffer, so a single
   * probe-then-fill avoids guessing a bound.
   */
  size_t nr_s2 = vmm_arm64_s2_snapshot(NULL, 0);
  size_t nr_chunks = pt_snapshot(NULL, NULL, NULL, 0);

  struct checkpoint_region *regions = calloc(nr_regions ? nr_regions : 1,
                                             sizeof *regions);
  struct checkpoint_s2 *s2 = calloc(nr_s2 ? nr_s2 : 1, sizeof *s2);
  struct checkpoint_pt_chunk *chunks = calloc(nr_chunks ? nr_chunks : 1,
                                              sizeof *chunks);
  if (!regions || !s2 || !chunks) {
    free(regions); free(s2); free(chunks);
    errno = ENOMEM;
    return -1;
  }

  struct checkpoint_header hdr;
  memset(&hdr, 0, sizeof hdr);
  hdr.magic   = CHECKPOINT_MAGIC;
  hdr.version = CHECKPOINT_VERSION;

  vmm_snapshot_vcpu(&hdr.vcpu);

  hdr.start_brk        = proc.mm->start_brk;
  hdr.current_brk      = proc.mm->current_brk;
  hdr.current_mmap_top = proc.mm->current_mmap_top;

  size_t i = 0;
  struct list_head *l;
  list_for_each (l, &proc.mm->mm_regions) {
    struct mm_region *r = list_entry(l, struct mm_region, list);
    regions[i++] = (struct checkpoint_region){
      .gaddr     = r->gaddr,
      .size      = r->size,
      .arena_off = r->arena_off,
      .prot      = r->prot,
      .mm_flags  = r->mm_flags,
      .mm_fd     = r->mm_fd,
      .pgoff     = r->pgoff,
    };
  }

  vmm_arm64_s2_snapshot(s2, nr_s2);
  pt_snapshot(&hdr.ipa_brk, &hdr.l1_ipa, chunks, nr_chunks);

  hdr.nr_regions   = (uint32_t) nr_regions;
  hdr.nr_s2        = (uint32_t) nr_s2;
  hdr.nr_pt_chunks = (uint32_t) nr_chunks;

  int rc = -1;
  if (write_all(fd, &hdr, sizeof hdr) == 0 &&
      write_all(fd, regions, nr_regions * sizeof *regions) == 0 &&
      write_all(fd, s2, nr_s2 * sizeof *s2) == 0 &&
      write_all(fd, chunks, nr_chunks * sizeof *chunks) == 0)
    rc = 0;

  free(regions); free(s2); free(chunks);
  return rc;
}

int
checkpoint_read(int fd, struct checkpoint_header *hdr,
                struct checkpoint_region **regions_out,
                struct checkpoint_s2 **s2_out,
                struct checkpoint_pt_chunk **chunks_out)
{
  if (read_all(fd, hdr, sizeof *hdr) < 0)
    return -1;

  if (hdr->magic != CHECKPOINT_MAGIC || hdr->version != CHECKPOINT_VERSION) {
    /* Refuse rather than resume a guest from state we may be misreading. */
    errno = EPROTO;
    return -1;
  }

  struct checkpoint_region *regions = calloc(hdr->nr_regions ? hdr->nr_regions : 1,
                                             sizeof *regions);
  struct checkpoint_s2 *s2 = calloc(hdr->nr_s2 ? hdr->nr_s2 : 1, sizeof *s2);
  struct checkpoint_pt_chunk *chunks = calloc(hdr->nr_pt_chunks ? hdr->nr_pt_chunks : 1,
                                              sizeof *chunks);
  if (!regions || !s2 || !chunks) {
    free(regions); free(s2); free(chunks);
    errno = ENOMEM;
    return -1;
  }

  if (read_all(fd, regions, hdr->nr_regions * sizeof *regions) < 0 ||
      read_all(fd, s2, hdr->nr_s2 * sizeof *s2) < 0 ||
      read_all(fd, chunks, hdr->nr_pt_chunks * sizeof *chunks) < 0) {
    free(regions); free(s2); free(chunks);
    return -1;
  }

  *regions_out = regions;
  *s2_out = s2;
  *chunks_out = chunks;
  return 0;
}
