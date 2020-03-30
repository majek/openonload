/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/tools/sysdep.h>
#ifdef __KERNEL__
# include "bpf_kernel_compat.h"
#else
# include <ci/kcompat.h>
# include <limits.h>
#endif
#include <onload/bpf_internal.h>
#include <uapi/linux/bpf.h>
#include <linux/bpf.h>

/* ======================================================================== */
/*                           BPF_MAP_TYPE_ARRAY                             */

static ssize_t array_shmbuf_bytes(enum bpf_map_type type, unsigned key_size,
                                  unsigned value_size, unsigned max_entries,
                                  unsigned flags)
{
  (void)type;
  if( key_size != 4 )
    return -EINVAL;
  if( flags &~ (OO_BPF_F_RDONLY | OO_BPF_F_WRONLY) )
    return -EINVAL;   /* no additional flags supported by the array map */
  return (size_t)max_entries * value_size;
}


static void* array_lookup(const struct oo_bpf_map* map, const void* key)
{
  ci_uint32 k = *(const ci_uint32*)key;
  return k < map->max_entries ? map->data + k * map->value_size : NULL;
}


static int array_update(const struct oo_bpf_map* map, const void* key,
                        const void* value, ci_uint64 flags)
{
  ci_uint32 k = *(const ci_uint32*)key;

  switch( flags ) {
  case BPF_ANY:
  case BPF_EXIST:
    break;
  case BPF_NOEXIST:
    return -EEXIST;   /* can't add new elements to an array */
  default:
    return -EINVAL;
  }
  if( k >= map->max_entries )
    return -E2BIG;
  memcpy(map->data + k * map->value_size, value, map->value_size);
  return 0;
}


static int array_delete(const struct oo_bpf_map* map, const void* key)
{
  /* It's an array... can't delete */
  (void)map;
  (void)key;
  return -EINVAL;
}


static int array_get_next_key(const struct oo_bpf_map* map, const void* key,
                              void* next_key)
{
  ci_uint32 k = key ? *(const ci_uint32*)key : UINT_MAX;
  if( k == map->max_entries - 1 )
    return -ENOENT;
  *(ci_uint32*)next_key = k < map->max_entries ? k + 1 : 0;
  return 0;
}


static const struct bpf_map_ops oo_array_map_kops = {
  .map_lookup_elem = (void*)array_lookup,
  .map_update_elem = (void*)array_update,
  .map_delete_elem = (void*)array_delete,
};

const struct oo_bpf_map_ops oo_array_map_ops = {
  .type = BPF_MAP_TYPE_ARRAY,
  .struct_bytes = sizeof(struct oo_bpf_map),
  .shmbuf_bytes = array_shmbuf_bytes,
  .init = NULL,
  .free = NULL,
  .gen_lookup = NULL,

  .lookup = array_lookup,
  .update = array_update,
  .delete = array_delete,
  .get_next_key = array_get_next_key,
  .kops = &oo_array_map_kops,
};
