/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* This file is only included in the kernel build */
#include "bpfimpl_kernel_config.h"
#include "bpf_kernel_compat.h"

#include "kernel/arraymap.c"

#include <onload/bpf_internal.h>
#include "imported_map.h"


/*
 * The behaviour of perf event maps is a bit different to other map types. When
 * a perf event fd is added to the array it is tagged with the struct file via
 * which it was added. This will be different depending on whether it is done
 * via the fd assigned on map creation, or via an fd assigned by pinning.
 * Pinning the map will result in the creation of a new struct file, associated
 * with an anonymous inode. When the last reference to a given struct file is
 * dropped, then all entries in the map referring to that struct file are
 * removed via a call to the map_release map operation made from the struct
 * file's release file operation. As we don't currently support pinning all
 * entries will be tagged with the same struct file. This struct file is only
 * used as a cookie, to identify the event owner. It is not interpreted as an
 * actual file.
 */

static ssize_t oo_perf_event_array_map_shmbuf_bytes(enum bpf_map_type type,
                                        unsigned key_size, unsigned value_size,
                                        unsigned max_entries, unsigned flags)
{
  union bpf_attr attr;

  if( ! oo_have_perf() )
    return -EOPNOTSUPP;

  memset(&attr, 0, sizeof(attr));
  attr.map_type = type;
  attr.key_size = key_size;
  attr.value_size = value_size;
  attr.max_entries = max_entries;
  attr.map_flags = flags;
  return fd_array_map_alloc_check(&attr);
}


static int oo_perf_event_array_map_init(struct oo_bpf_map* oomap)
{
  return oo_imported_map_init(oomap, &perf_event_array_map_ops);
}


static int oo_perf_array_map_update_elem(int fd, struct oo_bpf_map* map,
                                         const void* key, const void* value,
                                         u64 flags)
{
  struct fd f;
  int rc;

  f = fdget(fd);
  if( !f.file )
    return -EBADF;

  rc = bpf_fd_array_map_update_elem(((struct oo_imported_map*)map)->imap,
                                    f.file, (void*)key, (void*)value, flags);

  fdput(f);
  return rc;
}


static const struct bpf_map_ops oo_perf_event_array_map_kops = {
  .map_lookup_elem = (void*)oo_imported_map_lookup,
  .map_update_elem = NULL,
  .map_delete_elem = (void*)oo_imported_map_delete,
};

const struct oo_bpf_map_ops oo_perf_event_array_map_ops = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .struct_bytes = sizeof(struct oo_imported_map),
  .shmbuf_bytes = oo_perf_event_array_map_shmbuf_bytes,
  .flags = OO_BPF_MAP_F_KERNEL_ONLY,
  .init = oo_perf_event_array_map_init,
  .free = oo_imported_map_free,
  .gen_lookup = NULL, /* tricky to get working, because of the indirection.
                       * The slow path is fine for now */
  .release = oo_imported_map_release,
  .lookup = oo_imported_map_lookup,
  .update = NULL,
  .update_special = oo_perf_array_map_update_elem,
  .delete = oo_imported_map_delete,
  .get_next_key = oo_imported_map_get_next_key,
  .kops = &oo_perf_event_array_map_kops,
};
