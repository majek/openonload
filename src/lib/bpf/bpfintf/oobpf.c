/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* This is the implementation of the userspace interface to Onload's BPF
 * kernel facilities. See oobpf.h for the API documentation. */

#include <onload/oobpf.h>
#include <onload/bpf_ioctl.h>
#include <onload/version.h>
#include <onload/common.h>
#include <onload/bpf_internal.h>
#include <ci/kcompat.h>
#include <uapi/linux/bpf.h>
#include "uk_bpf_intf_ver.h"

extern void module_memfree(void *module_region);

/* -*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*- */
/*                              low-level API                              */

int oo_bpf_check_version(int drv)
{
  oo_version_check_t vc;
  strncpy(vc.in_version, ONLOAD_VERSION, sizeof(vc.in_version));
  strncpy(vc.in_uk_intf_ver, OO_UK_BPF_INTF_VER, sizeof(vc.in_uk_intf_ver));
  vc.debug =
#ifdef NDEBUG
    0;
#else
    1;
#endif
  return ioctl(drv, OO_BPF_IOC_CHECK_VERSION, &vc);
}


int oo_bpf_prog_load(int drv, const struct oo_bpf_prog_load_arg* arg)
{
  return ioctl(drv, OO_BPF_IOC_PROG_LOAD, arg);
}


int oo_bpf_prog_get_by_attachment(int drv,
                                  const struct oo_bpf_prog_attach_arg* arg)
{
  return ioctl(drv, OO_BPF_IOC_PROG_GET_BY_ATTACHMENT, arg);
}


int oo_bpf_prog_attach(int drv, struct oo_bpf_prog_attach_arg* arg)
{
  return ioctl(drv, OO_BPF_IOC_PROG_ATTACH, arg);
}


int oo_bpf_prog_detach(int drv, struct oo_bpf_prog_attach_arg* arg)
{
  return ioctl(drv, OO_BPF_IOC_PROG_DETACH, arg);
}


int oo_bpf_prog_test_run(int fd, struct oo_bpf_prog_test_run_arg* arg)
{
  return ioctl(fd, OO_BPF_IOC_PROG_TEST_RUN, arg);
}


int oo_bpf_prog_get_all(int fd, int attach_cnt,
                        struct oo_bpf_prog_attach_arg* attaches)
{
  struct oo_bpf_prog_get_all_arg arg = {
    .attach_cnt = attach_cnt,
    .attaches = (uintptr_t)attaches,
  };
  return ioctl(fd, OO_BPF_IOC_PROG_GET_ALL, &arg);
}


int oo_bpf_prog_get_info(int fd, struct oo_bpf_prog_info* info)
{
  return ioctl(fd, OO_BPF_IOC_PROG_GET_INFO, info);
}


/* map ioctls */

int oo_bpf_map_create(int drv, const struct oo_bpf_map_create_arg* arg)
{
  return ioctl(drv, OO_BPF_IOC_MAP_CREATE, arg);
}


int oo_bpf_map_get_info(int drv, int fd,
                        struct oo_bpf_map_info* info)
{
  struct oo_bpf_map_get_info_arg arg = {
    .map_fd = fd,
    .info = (uintptr_t)info,
  };
  return ioctl(drv, OO_BPF_IOC_MAP_GET_INFO, &arg);
}


#define OO_BPF_IOCTL_MAP_MANIP_IMPL(request, value_param)  \
  struct oo_bpf_map_manip_arg arg = {                      \
    .map_fd = fd,                                          \
    .key = (uintptr_t)key,                                 \
    { .value = (uintptr_t)(value_param) },                 \
    .flags = flags                                         \
  };                                                       \
  return ioctl(drv, (request), &arg);

int oo_bpf_map_lookup_elem(int drv, int fd,
                           const void* key, void* value, uint64_t flags)
{
  OO_BPF_IOCTL_MAP_MANIP_IMPL(OO_BPF_IOC_MAP_LOOKUP_ELEM, value);
}


int oo_bpf_map_update_elem(int drv, int fd,
                           const void* key, const void* value, uint64_t flags)
{
  OO_BPF_IOCTL_MAP_MANIP_IMPL(OO_BPF_IOC_MAP_UPDATE_ELEM, (void*)value);
}


int oo_bpf_map_delete_elem(int drv, int fd,
                           const void* key, uint64_t flags)
{
  OO_BPF_IOCTL_MAP_MANIP_IMPL(OO_BPF_IOC_MAP_DELETE_ELEM, (void*)NULL);
}


int oo_bpf_map_get_next_key(int drv, int fd,
                            const void* key, void* next_key, uint64_t flags)
{
  OO_BPF_IOCTL_MAP_MANIP_IMPL(OO_BPF_IOC_MAP_GET_NEXT_KEY, next_key);
}


/* -*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*- */
/*                             high-level API                              */


int oo_bpf_map_info_compatible(const struct oo_bpf_map_info* a,
                               const struct oo_bpf_map_info* b)
{
  if( a->type != b->type ||
      a->key_size != b->key_size ||
      a->value_size != b->value_size )
    return 0;
  /* Don't check max_entries: it's reasonable to want to play with different
   * sizes */
  /* Don't check flags: there are no maps either for us or for the kernel
   * where the differences in behaviour are fundamental based on flags */
  return 1;
}
