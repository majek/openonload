/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* This file is only included in the kernel build */
#include "bpfimpl_kernel_config.h"
#include "bpf_kernel_compat.h"

/* The kernel lpm_trie.c include net/ipv6.h, which isn't necessary, but pulls
 * in a variety of other network headers, with specific kernel requirements.
 * Just avoid having to deal with this by pretending we've already got it.
 */
#define _NET_IPV6_H
#include "kernel/lpm_trie.c"

#include <onload/bpf_internal.h>
#include "imported_map.h"


static ssize_t oo_lpm_trie_shmbuf_bytes(enum bpf_map_type type,
                                        unsigned key_size, unsigned value_size,
                                        unsigned max_entries, unsigned flags)
{
  /* We aren't currently supporting userspace maps and there's no alloc_check
   * for the kernel lpm trie to allow us to do a useful early sanity check,
   * so just return 0.
   */
  return 0;
}


static int oo_lpm_trie_init(struct oo_bpf_map* oomap)
{
  return oo_imported_map_init(oomap, &trie_map_ops);
}


static const struct bpf_map_ops oo_lpm_trie_map_kops = {
  .map_lookup_elem = (void*)oo_imported_map_lookup,
  .map_update_elem = (void*)oo_imported_map_update,
  .map_delete_elem = (void*)oo_imported_map_delete,
};

const struct oo_bpf_map_ops oo_lpm_trie_map_ops = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .struct_bytes = sizeof(struct oo_imported_map),
  .shmbuf_bytes = oo_lpm_trie_shmbuf_bytes,
  .flags = OO_BPF_MAP_F_KERNEL_ONLY,
  .init = oo_lpm_trie_init,
  .free = oo_imported_map_free,
  .gen_lookup = NULL, /* hard to inline, and the kernel doesn't do it */
  .lookup = oo_imported_map_lookup,
  .update = oo_imported_map_update,
  .delete = oo_imported_map_delete,
  .get_next_key = oo_imported_map_get_next_key,
  .kops = &oo_lpm_trie_map_kops,
};

