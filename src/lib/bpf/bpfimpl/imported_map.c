/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* This file is only included in the kernel build */
#include "bpfimpl_kernel_config.h"
#include "bpf_kernel_compat.h"

#include <linux/bpf.h>

#include <onload/bpf_internal.h>
#include "imported_map.h"


int oo_imported_map_init(struct oo_bpf_map* oomap,
                         const struct bpf_map_ops* ops)
{
  struct oo_imported_map* map = (struct oo_imported_map*)oomap;
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.map_type = oomap->map_type;
  attr.key_size = oomap->key_size;
  attr.value_size = oomap->value_size;
  attr.max_entries = oomap->max_entries;
  attr.map_flags = oomap->map_flags;
  map->imap = ops->map_alloc(&attr);
  if( IS_ERR(map->imap) )
    return PTR_ERR(map->imap);
  map->imap->ops = ops;
  map->imap->map_type = attr.map_type;
  return 0;
}


void oo_imported_map_release(struct oo_bpf_map* oomap, struct file* file)
{
  struct bpf_map* imap = ((struct oo_imported_map*)oomap)->imap;
  imap->ops->map_release(imap, file);
}


void oo_imported_map_free(struct oo_bpf_map* oomap)
{
  struct bpf_map* imap = ((struct oo_imported_map*)oomap)->imap;
  imap->ops->map_free(imap);
}


void* oo_imported_map_lookup(const struct oo_bpf_map* oomap, const void* key)
{
  struct bpf_map* imap = ((struct oo_imported_map*)oomap)->imap;
  return imap->ops->map_lookup_elem(imap, (void*)key);
}


int oo_imported_map_update(const struct oo_bpf_map* oomap, const void* key,
                           const void* value, ci_uint64 flags)
{
  struct bpf_map* imap = ((struct oo_imported_map*)oomap)->imap;
  return imap->ops->map_update_elem(imap, (void*)key, (void*)value, flags);
}


int oo_imported_map_delete(const struct oo_bpf_map* oomap, const void* key)
{
  struct bpf_map* imap = ((struct oo_imported_map*)oomap)->imap;
  return imap->ops->map_delete_elem(imap, (void*)key);
}


int oo_imported_map_get_next_key(const struct oo_bpf_map* oomap,
                                 const void* key, void* next_key)
{
  struct bpf_map* imap = ((struct oo_imported_map*)oomap)->imap;
  return imap->ops->map_get_next_key(imap, (void*)key, next_key);
}
