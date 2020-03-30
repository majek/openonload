/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* This file is only included in the kernel build */
#include "bpfimpl_kernel_config.h"
#include "bpf_kernel_compat.h"
#include <ci/tools/debug.h>

#include "kernel/hashtab.c"

#include <onload/bpf_internal.h>
#include "imported_map.h"


static ssize_t oo_htab_map_shmbuf_bytes(enum bpf_map_type type,
                                        unsigned key_size, unsigned value_size,
                                        unsigned max_entries, unsigned flags)
{
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.map_type = type;
  attr.key_size = key_size;
  attr.value_size = value_size;
  attr.max_entries = max_entries;
  attr.map_flags = flags;
  return htab_map_alloc_check(&attr);
}


static int oo_htab_map_init(struct oo_bpf_map* oomap)
{
  return oo_imported_map_init(oomap, &htab_map_ops);
}


static const struct bpf_map_ops oo_hash_map_kops = {
  .map_lookup_elem = (void*)oo_imported_map_lookup,
  .map_update_elem = (void*)oo_imported_map_update,
  .map_delete_elem = (void*)oo_imported_map_delete,
};

const struct oo_bpf_map_ops oo_hash_map_ops = {
  .type = BPF_MAP_TYPE_HASH,
  .struct_bytes = sizeof(struct oo_imported_map),
  .shmbuf_bytes = oo_htab_map_shmbuf_bytes,
  .flags = OO_BPF_MAP_F_KERNEL_ONLY,
  .init = oo_htab_map_init,
  .free = oo_imported_map_free,
  .gen_lookup = NULL, /* tricky to get working, because of the indirection.
                       * The slow path is fine for now */

  .lookup = oo_imported_map_lookup,
  .update = oo_imported_map_update,
  .delete = oo_imported_map_delete,
  .get_next_key = oo_imported_map_get_next_key,
  .kops = &oo_hash_map_kops,
};

/* Important: When we add percpu hash map, remember that we must require
 * !BPF_F_NO_PREALLOC on kernels<3.18 (!HAVE_ATOMIC_PERCPU). There's no good
 * way to write our own implementation because the underlying kernel code is
 * fundamentally missing stuff. See 5835d96e9ce4 in the kernel. */
