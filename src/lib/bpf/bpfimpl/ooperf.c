/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/*************************************************************************
 * This file contains the onload implementation of the perf functionality
 * that is used by our kernel eBPF components.
 *
 * It is only included in the kernel build as we don't support perf events
 * in the userspace build.
 *************************************************************************/

#include "bpf_kernel_compat.h"

#include <linux/bpf.h>

/* There's a lot of compatibility stuff around handling of cgroups, that the
 * majority of our bpf code doesn't need to care about.  However, some of the
 * perf code does need to care about it because the perf headers have actual
 * dependencies on cgroups.  Because the perf functionality is somewhat
 * separate from the eBPF we don't have the same restriction on requiring a
 * specific kernel versions, so can avoid a compatability nightmare by
 * including the real local header.
 */
#define OO_WANT_REAL_CGROUPS
#include <linux/file.h>
#include <linux/perf_event.h>

#include <ci/tools.h>

#include <onload/bpf_internal.h>
#include "imported_map.h"

extern void *efrm_find_ksym(const char *name);

typedef void perf_event_output_t(struct perf_event*, struct perf_sample_data*,
                                 struct pt_regs*);
static perf_event_output_t* output_func;

#ifdef EFRM_PERF_EVENT_GET_RETURNS_FILE
/* Introduced in linux 4.5.0 and backported to RHEL7.6 */
typedef struct file* perf_event_get_t(unsigned int);

static perf_event_get_t* get_func;
#elif defined(EFRM_PERF_EVENT_GET_RETURNS_EVENT)
/* Introduced in linux 4.3.0 and backported to RHEL7.4. We don't use this
 * function directly, but use it to place a limit on the different versions
 * of the perf API that we support.
 */
static const struct file_operations* perf_event_fops;
#endif

#ifdef EFRM_PERF_EVENT_READ_LOCAL_TAKES_ENABLED
/* Introduced in linux 4.15.0 and backported to RHEL7.6. */
typedef int perf_event_read_local_t(struct perf_event*, u64*, u64*, u64*);
#elif defined(EFRM_PERF_EVENT_READ_LOCAL_TAKES_VALUE)
/* Introduced in linux 4.13.0. */
typedef int perf_event_read_local_t(struct perf_event*, u64*);
#elif defined(EFRM_PERF_EVENT_READ_LOCAL_TAKES_EVENT)
/* Introduced in linux 4.3.0 and backported to RHEL7.4. */
typedef u64 perf_event_read_local_t(struct perf_event*);
#else
/* This isn't called as we'll deny support for perf in this case, but having a
 * definition for this case allows some of the other code to avoid ugly
 * ifdeffery.
 */
typedef void perf_event_read_local_t(void);
#endif

static perf_event_read_local_t* read_func;

#ifndef EFRM_HAVE_PERF_RAW_FRAG

static u8* __percpu *sample_bufs;
#define ONLOAD_SAMPLE_BUF_SIZE 2048

static void free_sample_bufs(void)
{
  int cpu;

  if( !sample_bufs )
    return;

  for_each_possible_cpu(cpu)
    ci_free(*per_cpu_ptr(sample_bufs, cpu));

  free_percpu(sample_bufs);
}

static int alloc_sample_bufs(void)
{
  int cpu;
  int rc = 0;

  sample_bufs = alloc_percpu(u8*);
  if( !sample_bufs )
    return -ENOMEM;

  for_each_possible_cpu(cpu) {
    *per_cpu_ptr(sample_bufs, cpu) = ci_alloc(ONLOAD_SAMPLE_BUF_SIZE);
    if( ! *per_cpu_ptr(sample_bufs, cpu) )
      rc = -ENOMEM;
  }

  if( rc < 0 )
    free_sample_bufs();

  return rc;
}
#endif

/* Digs out the internal kernel functions we need for perf functionality.  We
 * do this now so that we know at the point of setup whether to allow things
 * that would use it, and because we're not in a valid context to look up on
 * demand anyway.
 */
int oo_init_perf(void)
{
#if CI_HAVE_KERNEL_BPF
#ifndef EFRM_BPF_MAP_OPS_HAS_RELEASE
  /* Introduced in 4.8.
   * Without this we are unable to clear the perf events from the map at the
   * time the map is released by userspace.  If we don't have kernel bpf
   * support we don't go via the bpf syscall, so don't have this problem.
   */
  return -EOPNOTSUPP;
#endif
#endif

#if defined(EFRM_PERF_EVENT_GET_RETURNS_FILE)
  get_func = efrm_find_ksym("perf_event_get");
  if( !get_func )
    return -ENOSYS;
#elif defined(EFRM_PERF_EVENT_GET_RETURNS_EVENT)
  /* We need to dig these out so that when we grab the perf event file we can
   * sanity check that the fd is really for a perf event.
   */
  perf_event_fops = efrm_find_ksym("perf_fops");
#else
  return -EOPNOTSUPP;
#endif

  read_func = efrm_find_ksym("perf_event_read_local");
  if( !read_func )
    return -ENOSYS;

  output_func = efrm_find_ksym("perf_event_output");
  if( !output_func )
    return -ENOSYS;

#if !defined(EFRM_HAVE_PERF_RAW_FRAG)
  if( alloc_sample_bufs() < 0 )
    return -ENOMEM;
#endif

  return 0;
}


void oo_release_perf(void)
{
#ifndef EFRM_HAVE_PERF_RAW_FRAG
  free_sample_bufs();
#endif
}


/* The original kernel versions of perf_event_get and perf_event_read_local
 * are #defined to these onload wrappers in our perf_event.h replacement
 * header.  This is because they aren't consistently present on all supported
 * kernel versions, but our imported eBPF code expects the version consistent
 * with the kernel it came from.
 */
int onload_perf_event_read_local(struct perf_event *event, u64 *value,
                                 u64 *enabled, u64 *running)
{
  /* We must use the real function, not an emulation, as we need to
   * interoperate with the perf subsystem as it exists on this specific kernel
   * version.
   */
#ifdef EFRM_PERF_EVENT_READ_LOCAL_TAKES_ENABLED
  return read_func(event, value, enabled, running);
#elif defined(EFRM_PERF_EVENT_READ_LOCAL_TAKES_VALUE)
  return read_func(event, value);
#elif defined(EFRM_PERF_EVENT_READ_LOCAL_TAKES_EVENT)
  *value = read_func(event);
  return 0;
#else
  /* We should have failed to create the map in this case, so should never get
   * this far.
   */
  ci_assert(0);
  return -ENOSYS;
#endif
}

struct file* onload_perf_event_get(unsigned int fd)
{
#ifdef EFRM_PERF_EVENT_GET_RETURNS_FILE
  return get_func(fd);
#elif defined(EFRM_PERF_EVENT_GET_RETURNS_EVENT)
  struct file *file;

  file = fget_raw(fd);
  if( !file )
    return ERR_PTR(-EBADF);

  if( file->f_op != perf_event_fops ) {
    fput(file);
    return ERR_PTR(-EBADF);
  }

  return file;
#else
  /* We should have failed to create the map in this case, so should never get
   * this far.
   */
  ci_assert(0);
  return ERR_PTR(-EINVAL);
#endif
}


static DEFINE_PER_CPU(struct pt_regs, bpf_pt_regs);
static DEFINE_PER_CPU(struct perf_sample_data, bpf_misc_sd);

/* Both this function and the following bpf_event_output function are based on
 * code in the Linux kernel 4.20.3.  However, we can't use the native kernel
 * functions as we need to add our own compatability code to allow use with
 * kernel versions that have differing perf APIs.
 */
static u64 onload_bpf_perf_event_output(struct pt_regs *regs,
                                        struct bpf_map *map, u64 flags,
                                        struct perf_sample_data *sd)
{
  struct bpf_array *array = container_of(map, struct bpf_array, map);
  unsigned int cpu = smp_processor_id();
  u64 index = flags & BPF_F_INDEX_MASK;
  struct bpf_event_entry *ee;
  struct perf_event *event;
  enum perf_sw_ids event_id;

#ifdef EFRM_HAVE_BPF_PERF_EVENT
  /* Introduced in linux 4.4.0 and backported to RHEL7.6. */
  event_id = PERF_COUNT_SW_BPF_OUTPUT;
#elif defined(EFRM_HAVE_SW_DUMMY_PERF_EVENT)
  /* Introduced in linux 3.12.0 and backported to RHEL7.4 */
  event_id = PERF_COUNT_SW_DUMMY;
#else
  /* We should never get here, because any kernel without one of the above
   * two options will not claim bpf perf support.
   */
  ci_assert(0);
  event_id = PERF_COUNT_SW_MAX;
#endif

  ci_assert(output_func);

  if (index == BPF_F_CURRENT_CPU)
    index = cpu;
  if (unlikely(index >= array->map.max_entries))
    return -E2BIG;
  ee = READ_ONCE(array->ptrs[index]);
  if (!ee)
    return -ENOENT;
  event = ee->event;
  if (unlikely(event->attr.type != PERF_TYPE_SOFTWARE ||
      event->attr.config != event_id))
    return -EINVAL;

  if (unlikely(event->oncpu != cpu))
    return -EOPNOTSUPP;

  output_func(event, sd, regs);
  return 0;
}


#ifdef EFRM_HAVE_PERF_RAW_FRAG
static unsigned long data_copy(void *dst_buff, const void *src_buff,
                               unsigned long off, unsigned long len)
{
  memcpy(dst_buff, src_buff + off, len);
  return 0;
}
#endif


u64 onload_bpf_event_output(struct bpf_map *map, u64 flags, void *meta,
                            u64 meta_size, void *ctx, u64 ctx_size)
{
  struct oo_imported_map *oomap = (struct oo_imported_map*)map;
  struct perf_sample_data *sd = this_cpu_ptr(&bpf_misc_sd);
  struct pt_regs *regs = this_cpu_ptr(&bpf_pt_regs);

#ifdef EFRM_HAVE_PERF_RAW_FRAG
  struct perf_raw_frag frag = {
    .copy = data_copy,
    .size = ctx_size,
    .data = ctx,
  };
  struct perf_raw_record raw = {
    .frag = {
      {
      .next = ctx_size ? &frag : NULL,
      },
      .size = meta_size,
      .data = meta,
    },
  };
#else
  ssize_t pkt_data_to_copy;
  struct perf_raw_record raw = {
    .data = *this_cpu_ptr(sample_bufs),
  };

  /* Require that all the metadata fits within the buffer */
  if( meta_size > ONLOAD_SAMPLE_BUF_SIZE )
    return -EFAULT;

  memcpy(raw.data, meta, meta_size);

  /* We allow truncation of packet data.  If the app cares about this it can
   * include the packet length in the metadata, which allows it to detect the
   * truncation and discard.
   */
  pkt_data_to_copy = CI_MIN(ctx_size, ONLOAD_SAMPLE_BUF_SIZE - meta_size);
  memcpy(raw.data + meta_size, ctx, pkt_data_to_copy);
  raw.size = meta_size + pkt_data_to_copy;
#endif

  perf_fetch_caller_regs(regs);
  perf_sample_data_init(sd, 0, 0);
  sd->raw = &raw;

  return onload_bpf_perf_event_output(regs, oomap->imap, flags, sd);
}

