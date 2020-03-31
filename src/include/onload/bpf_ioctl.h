/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* This file contains definitions representing the user/kernel API to
 * /dev/onload_bpf. This and bpf_api.h are the files which are ABI-checked (by
 * md5sum) to ensure user/kernel consistency of the BPF facilities. This file
 * is used for definitions which are only used internally by Onload and the
 * low-level oobpf API, and hence may #include all sorts of other Onload
 * stuff */

#ifndef ONLOAD_BPF_IOCTL_H_
#define ONLOAD_BPF_IOCTL_H_

#include <ci/compat.h>
#include <ci/internal/transport_config_opt.h>
#include "bpf_api.h"


/* Bias the base number solely to make these ioctls be distinct from those
 * for /dev/onload. This isn't necessary for any part of the implementation,
 * it's done solely as an aid to debugging
 *
 * The map manipulation ioctls (but not OO_BPF_OP_MAP_CREATE itself) are also
 * available on map fds. This is because /dev/onload_bpf is only accessible to
 * root, yet it is reasonable for a less-privileged user to want to manipulate
 * a map fd which they have been given by somebody else. */
#define OO_BPF_IOC_BASE    149
enum {
/* generic ioctls */
  OO_BPF_OP_CHECK_VERSION,
#define OO_BPF_IOC_CHECK_VERSION \
  _IOW(OO_BPF_IOC_BASE, OO_BPF_OP_CHECK_VERSION, oo_version_check_t)

/* prog ioctls */
  OO_BPF_OP_PROG_LOAD,
#define OO_BPF_IOC_PROG_LOAD \
  _IOW(OO_BPF_IOC_BASE, OO_BPF_OP_PROG_LOAD, struct oo_bpf_prog_load_arg)
  OO_BPF_OP_PROG_ATTACH,
#define OO_BPF_IOC_PROG_ATTACH \
  _IOW(OO_BPF_IOC_BASE, OO_BPF_OP_PROG_ATTACH, struct oo_bpf_prog_attach_arg)
  OO_BPF_OP_PROG_DETACH,
#define OO_BPF_IOC_PROG_DETACH \
  _IOW(OO_BPF_IOC_BASE, OO_BPF_OP_PROG_DETACH, struct oo_bpf_prog_attach_arg)
  OO_BPF_OP_PROG_GET_BY_ATTACHMENT,
#define OO_BPF_IOC_PROG_GET_BY_ATTACHMENT \
  _IOW(OO_BPF_IOC_BASE, OO_BPF_OP_PROG_GET_BY_ATTACHMENT, \
                        struct oo_bpf_prog_attach_arg)
  OO_BPF_OP_PROG_GET_ALL,
#define OO_BPF_IOC_PROG_GET_ALL \
  _IOW(OO_BPF_IOC_BASE, OO_BPF_OP_PROG_GET_ALL, \
                        struct oo_bpf_prog_get_all_arg)
  OO_BPF_OP_PROG_GET_INFO,

  /* These ioctls apply to prog fds, not to /dev/onload_bpf */
  OO_BPF_OP_PROG_TEST_RUN,
#define OO_BPF_IOC_PROG_TEST_RUN \
  _IOWR(OO_BPF_IOC_BASE, OO_BPF_OP_PROG_TEST_RUN, \
                         struct oo_bpf_prog_test_run_arg)
#define OO_BPF_IOC_PROG_GET_INFO \
  _IOWR(OO_BPF_IOC_BASE, OO_BPF_OP_PROG_GET_INFO, struct oo_bpf_prog_info)

/* map ioctls */
  OO_BPF_OP_MAP_CHECK_VERSION,
#define OO_BPF_IOC_MAP_CHECK_VERSION \
  _IOW(OO_BPF_IOC_BASE, OO_BPF_OP_MAP_CHECK_VERSION, oo_version_check_t)
  OO_BPF_OP_MAP_CREATE,
#define OO_BPF_IOC_MAP_CREATE \
  _IOW(OO_BPF_IOC_BASE, OO_BPF_OP_MAP_CREATE, struct oo_bpf_map_create_arg)
  OO_BPF_OP_MAP_LOOKUP_ELEM,
#define OO_BPF_IOC_MAP_LOOKUP_ELEM \
  _IOW(OO_BPF_IOC_BASE, OO_BPF_OP_MAP_LOOKUP_ELEM, \
                        struct oo_bpf_map_manip_arg)
  OO_BPF_OP_MAP_UPDATE_ELEM,
#define OO_BPF_IOC_MAP_UPDATE_ELEM \
  _IOW(OO_BPF_IOC_BASE, OO_BPF_OP_MAP_UPDATE_ELEM, \
                        struct oo_bpf_map_manip_arg)
  OO_BPF_OP_MAP_DELETE_ELEM,
#define OO_BPF_IOC_MAP_DELETE_ELEM \
  _IOW(OO_BPF_IOC_BASE, OO_BPF_OP_MAP_DELETE_ELEM, \
                        struct oo_bpf_map_manip_arg)
  OO_BPF_OP_MAP_GET_NEXT_KEY,
#define OO_BPF_IOC_MAP_GET_NEXT_KEY \
  _IOW(OO_BPF_IOC_BASE, OO_BPF_OP_MAP_GET_NEXT_KEY, \
                        struct oo_bpf_map_manip_arg)
  OO_BPF_OP_MAP_GET_INFO,
#define OO_BPF_IOC_MAP_GET_INFO \
  _IOW(OO_BPF_IOC_BASE, OO_BPF_OP_MAP_GET_INFO, \
                        struct oo_bpf_map_get_info_arg)
};

#endif
