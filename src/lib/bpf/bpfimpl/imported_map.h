/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef ONLOAD_IMPORTED_MAP_H_
#define ONLOAD_IMPORTED_MAP_H_

/* We import several map types from the kernel.  These are all handled in a
 * consistent fashion, with a kernel struct bpf_map pointer placed directly
 * following the oo_bpf_map struct.
 *
 * This means that we can define standard handlers for the map ops, that
 * find the imported map based on the onload map, and then call that map's
 * appropriate op.
 */

struct oo_imported_map {
  struct oo_bpf_map oomap;
  /* The necessity for an extra level of indirection here is annoying, but
   * we're already on a slowish path due to having to run in the kernel, so it
   * saves a nightmarish effort to try to interleave kernel and Onload data */
  struct bpf_map* imap;
};


/* Common initialiser to set up the imported map based on the oo_bpf_map */
int oo_imported_map_init(struct oo_bpf_map* oomap,
                         const struct bpf_map_ops* ops);

/* Wrappers to call the appropriate op based on the imported map's ops table */
void oo_imported_map_free(struct oo_bpf_map* oomap);
void oo_imported_map_release(struct oo_bpf_map* oomap, struct file* file);
void* oo_imported_map_lookup(const struct oo_bpf_map* map, const void* key);
int oo_imported_map_update(const struct oo_bpf_map* map, const void* key,
                           const void* value, ci_uint64 flags);
int oo_imported_map_delete(const struct oo_bpf_map* map, const void* key);
int oo_imported_map_get_next_key(const struct oo_bpf_map* map,
                                 const void* key, void* next_key);

#endif /* ONLOAD_IMPORTED_MAP_H_ */
