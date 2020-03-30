/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/tools/sysdep.h>
#include <onload/debug.h>
#ifdef __KERNEL__
# include "bpf_kernel_compat.h"
#else
# include <ci/kcompat.h>
#endif
#include <onload/bpf_internal.h>
#include <uapi/linux/bpf.h>
#include <linux/bpf.h>
#include <onload/bpf_map_op_wrap.h>

#include "imported_map.h"

CI_BUILD_ASSERT(sizeof(((struct oo_bpf_map*)NULL)->kern_bpf_map) >=
                sizeof(struct bpf_map));

/* Arbitrary caps to prevent anybody going nuts */
static const size_t MAX_MAP_STORAGE_BYTES = 64*1048576;
static const size_t MAX_MAP_KEY_SIZE_BYTES = 512;
static const size_t MAX_MAP_VALUE_SIZE_BYTES = 262144;
static const int BPF_MAX_REFCNT = 32768;  /* same value as kernel uses */

extern const struct oo_bpf_map_ops oo_array_map_ops;
extern const struct oo_bpf_map_ops oo_hash_map_ops;
extern const struct oo_bpf_map_ops oo_lpm_trie_map_ops;
extern const struct oo_bpf_map_ops oo_perf_event_array_map_ops;
static const struct oo_bpf_map_ops* onload_map_types[] = {
  &oo_array_map_ops,
#ifdef __KERNEL__
  &oo_hash_map_ops,
  &oo_lpm_trie_map_ops,
  &oo_perf_event_array_map_ops,
#endif
};


static inline struct bpf_map* get_kmap(struct oo_bpf_map* map)
{
  return (struct bpf_map*)map->kern_bpf_map;
}


static const struct oo_bpf_map_ops* get_map_ops(int type)
{
  size_t i;
  for( i = 0; i < sizeof(onload_map_types) / sizeof(*onload_map_types); ++i ) {
#ifndef __KERNEL__
    ci_assert_nflags(onload_map_types[i]->flags, OO_BPF_MAP_F_KERNEL_ONLY);
#endif
    if( onload_map_types[i]->type == type )
      return onload_map_types[i];
  }
  return NULL;
}


int oo_bpf_map_init(struct oo_bpf_map* map,
                     const struct oo_bpf_map_create_arg* attr,
                     const struct bpf_map_ops* kops)
{
  struct bpf_map* kmap;

  map->map_type = attr->map_type;
  map->key_size = attr->key_size;
  map->value_size = attr->value_size;
  map->max_entries = attr->max_entries;
  map->map_flags = attr->map_flags;
  strncpy(map->name, attr->map_name, sizeof(map->name));
  ci_atomic_set(&map->refcount, 1);

  kmap = get_kmap(map);
  if( kops ) {
    kmap->ops = kops;
  }
  else {
    const struct oo_bpf_map_ops* ops = get_map_ops(attr->map_type);
    if( ! ops )
      return -EINVAL;
    kmap->ops = ops->kops;
  }
  kmap->map_type = map->map_type;
  kmap->key_size = map->key_size;
  kmap->value_size = map->value_size;
  kmap->max_entries = map->max_entries;
  kmap->map_flags = map->map_flags;
  return 0;
}


int ook_bpf_map_create(struct oo_bpf_map_create_arg* attr,
                       struct oo_bpf_map** out_map)
{
  const struct oo_bpf_map_ops* ops;
  struct oo_bpf_map* map;
  int rc;
  ssize_t shmbuf_bytes;

  ops = get_map_ops(attr->map_type);
  if( ! ops ) {
    OO_DEBUG_ERR(ci_log("%s: map type %d not supported",
                        __FUNCTION__, attr->map_type));
    return -EINVAL;
  }

  ci_assert_ge(ops->struct_bytes, sizeof(struct oo_bpf_map));

  if( attr->key_size == 0 || attr->value_size == 0 || attr->max_entries == 0 )
    return -EINVAL;
  if( attr->key_size > MAX_MAP_KEY_SIZE_BYTES ||
      attr->value_size > MAX_MAP_VALUE_SIZE_BYTES ||
      attr->max_entries > MAX_MAP_STORAGE_BYTES )
    return -E2BIG;

  shmbuf_bytes = ops->shmbuf_bytes(attr->map_type, attr->key_size,
                                   attr->value_size, attr->max_entries,
                                   attr->map_flags);
  if( shmbuf_bytes < 0 )
    return (int)shmbuf_bytes;
  if( shmbuf_bytes > MAX_MAP_STORAGE_BYTES )
    return -E2BIG;

  map = ci_alloc(ops->struct_bytes);
  if( ! map )
    return -ENOMEM;
  memset(map, 0, ops->struct_bytes);
  map->ops = ops;
  oo_bpf_map_init(map, attr, ops->kops);

  if( shmbuf_bytes ) {
    map->data_pages = (shmbuf_bytes + CI_PAGE_SIZE - 1) / CI_PAGE_SIZE;
    map->data = vmalloc_user(map->data_pages * CI_PAGE_SIZE);
    if( ! map->data ) {
      ci_free(map);
      return -ENOMEM;
    }
  }

  if( ops->init ) {
    rc = ops->init(map);
    if( rc < 0 ) {
      vfree(map->data);
      ci_free(map);
      return rc;
    }
  }

  *out_map = map;
  return 0;
}


int/*bool*/ ook_bpf_map_incref(struct oo_bpf_map* map)
{
  if( ci_atomic_xadd(&map->refcount, 1) > BPF_MAX_REFCNT ) {
    ci_atomic_dec(&map->refcount);
    return 0;
  }
  return 1;
}

void ook_bpf_map_decref(struct oo_bpf_map* map)
{
  ci_assert_gt(map->refcount.n, 0);
  if( ci_atomic_dec_and_test(&map->refcount) ) {
    if( map->ops->free )
      map->ops->free(map);
    vfree(map->data);
    ci_free(map);
  }
}


int ook_bpf_map_get_info(struct oo_bpf_map* map,
                         struct oo_bpf_map_info __user* uinfo)
{
  struct oo_bpf_map_info info = {
    .type        = map->map_type,
    .key_size    = map->key_size,
    .value_size  = map->value_size,
    .max_entries = map->max_entries,
    .map_flags   = map->map_flags,
  };

  int rc = copy_to_user(uinfo, &info, sizeof(struct oo_bpf_map_info));
  if( rc != 0 )
    rc = -EFAULT;
  return rc;
}


long ook_bpf_map_lookup_elem(int fd, struct oo_bpf_map* map,
                             const void __user* ukey,
                             void __user* uvalue, ci_uint64 flags)
{
  int rc;
  char stackk[MAX_STACK_SCRATCH_BYTES];
  char* k = map->key_size > sizeof(stackk) ? ci_alloc(map->key_size) : stackk;

  (void)flags;
  if( copy_from_user(k, ukey, map->key_size) ) {
    rc = -EFAULT;
  }
  else {
    const void* v;
    oo_map_lock();
    v = map->ops->lookup(map, k);
    if( ! v )
      rc = -ENOENT;
    else if( copy_to_user(uvalue, v, map->value_size) )
      rc = -EFAULT;
    else
      rc = 0;
    oo_map_unlock();
  }
  if( k != stackk )
    ci_free(k);
  return rc;
}

long ook_bpf_map_update_elem(int fd, struct oo_bpf_map* map,
                             const void __user* ukey, void __user* uvalue,
                             ci_uint64 flags)
{
  MAP_UPDATE_PREFIX
    oo_map_lock();
    if( map->ops->update_special )
      rc = map->ops->update_special(fd, map, k, k + map->key_size, flags);
    else
      rc = map->ops->update(map, k, k + map->key_size, flags);
    oo_map_unlock();
  MAP_UPDATE_SUFFIX
}


long ook_bpf_map_delete_elem(int fd, struct oo_bpf_map* map,
                             const void __user* ukey,
                             void __user* uvalue, ci_uint64 flags)
{
  MAP_DELETE_PREFIX
    oo_map_lock();
    rc = map->ops->delete(map, k);
    oo_map_unlock();
  MAP_DELETE_SUFFIX
}


long ook_bpf_map_get_next_key(int fd, struct oo_bpf_map* map,
                              const void __user* ukey,
                              void __user* unext_key, ci_uint64 flags)
{
  MAP_GET_NEXT_PREFIX
    oo_map_lock();
    rc = map->ops->get_next_key(map, ukey ? k : NULL, k + map->key_size);
    oo_map_unlock();
  MAP_GET_NEXT_SUFFIX
}
