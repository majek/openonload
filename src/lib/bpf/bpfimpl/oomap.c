/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/*************************************************************************
 * This file contains the onload implementation of the map functionality
 * that is used by our kernel eBPF components.
 *************************************************************************/

#ifdef __KERNEL__
#include "bpf_kernel_compat.h"
#else
#include <limits.h>
#include <net/if.h>
#include <ci/kcompat.h>
#endif /* __KERNEL__ */

#include <linux/bpf.h>
#include <linux/filter.h>
#include <onload/bpf_internal.h>

#include <ci/tools.h>

struct bpf_map* __bpf_map_get(struct fd f)
{
  struct oo_bpf_map* oomap;
  if( ! f.file )
    return ERR_PTR(-EBADF);
  oomap = get_oo_map(f.file);
  if( ! oomap )
    return ERR_PTR(-EINVAL);
  return (struct bpf_map*)oomap->kern_bpf_map;
}

struct bpf_map *bpf_map_inc(struct bpf_map *kmap, bool uref)
{
  /* Note that we don't need to worry about the possibility (on kernels with
   * native BPF) that the struct bpf_map containing this one might get freed,
   * i.e. we don't need to use its refcnt field, because there's no way to
   * get from an oo_bpf_map to that bpf_map and therefore nobody can possibly
   * worry about it disappearing. */
  ci_assert_equal(uref, false);
  if( ! ook_bpf_map_incref((struct oo_bpf_map*)kmap) )
    return ERR_PTR(-EBUSY);
  return kmap;
}

void bpf_map_put(struct bpf_map *map)
{
  ook_bpf_map_decref((struct oo_bpf_map*)map);
}

#ifdef __KERNEL__
/* These functions are used only by imported kernel map implementations, which
 * run only in the kernel (they all depend on RCU, so we can't run them in
 * userspace) */

/* We don't need our activeness to cooperate with the kernel's activeness. The
 * value is solely used to protect against reentry due to (e.g.) kprobe BPF.
 * XDP and other networking BPF can't reenter. */
DEFINE_PER_CPU(int, bpf_prog_active);


void bpf_map_init_from_attr(struct bpf_map *map, union bpf_attr *attr)
{
  map->map_type = attr->map_type;
  map->key_size = attr->key_size;
  map->value_size = attr->value_size;
  map->max_entries = attr->max_entries;
  map->map_flags = attr->map_flags;
  map->numa_node = NUMA_NO_NODE;   /* No NUMA support in Onload BPF */
}


void *bpf_map_area_alloc(size_t size, int numa_node)
{
  /* Kernel implementation didn't ignore numa_node, and had an
   * memory-optimisation for small maps. We do neither of those things, in
   * order to make compatibility with older kernels simpler. Nothing about
   * imported kernel-only maps is particularly optimal, so the omission isn't
   * a problem */
  return __vmalloc(size,
                   GFP_KERNEL | __GFP_NOWARN | __GFP_NORETRY | __GFP_ZERO,
                   PAGE_KERNEL);
}


void bpf_map_area_free(void *area)
{
  vfree(area);
}


int bpf_map_precharge_memlock(u32 pages)
{
  /* memory charging not implemented - maps can only be created by root */
  return 0;
}


void btf_type_seq_show(const struct btf *btf, u32 type_id, void *obj,
                       struct seq_file *m)
{
  /* We don't implement printing of maps */
}

int map_check_no_btf(const struct bpf_map *map,
                     const struct btf_type *key_type,
                     const struct btf_type *value_type)
{
  /* Onload has no BTF support */
  return -ENOTSUPP;
}

#endif
