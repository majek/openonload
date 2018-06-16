/*
** Copyright 2005-2018  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This program is free software; you can redistribute it and/or modify it
** under the terms of version 2 of the GNU General Public License as
** published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/

/* This file contains description of the Onload ioctls used by the Control
 * Plane server.  Any change in this file is likely to result in
 * misfunctioning cplane server. */

#ifndef __CPLANE_IOCTL_H__
#define __CPLANE_IOCTL_H__

#include <cplane/mib.h>

struct oo_op_cplane_ipmod {
  ci_ip_addr_t net_ip;
  ci_ifid_t ifindex;
  ci_int8/*bool*/ add;
};

struct oo_op_cplane_llapmod {
  ci_ifid_t ifindex;
  ci_uint16 flags; /* 0x1 means interface is up */
  ci_uint32 hwport_mask;
  ci_uint16 vlan_id;
  ci_mac_addr_t mac;
};


#include <onload/ioctl_base.h>

/* This is the first part of a large enum defined in
 * include/onload/ioctl.h.
 * It MUST be synchronised with the oo_operations table! */
enum {
  OO_OP_GET_CPU_KHZ,
#define OO_IOC_GET_CPU_KHZ        OO_IOC_R(GET_CPU_KHZ, ci_uint32)

  OO_OP_IFINDEX_TO_HWPORT,
#define OO_IOC_IFINDEX_TO_HWPORT  OO_IOC_RW(IFINDEX_TO_HWPORT, ci_uint32)

  OO_OP_CP_MIB_SIZE,
#define OO_IOC_CP_MIB_SIZE        OO_IOC_R(CP_MIB_SIZE, ci_uint32)

  OO_OP_CP_FWD_RESOLVE,
#define OO_IOC_CP_FWD_RESOLVE     OO_IOC_W(CP_FWD_RESOLVE, struct cp_fwd_key)

  OO_OP_CP_FWD_RESOLVE_COMPLETE,
#define OO_IOC_CP_FWD_RESOLVE_COMPLETE     OO_IOC_W(CP_FWD_RESOLVE_COMPLETE, \
                                                    ci_uint32)
  OO_OP_CP_ARP_RESOLVE,
#define OO_IOC_CP_ARP_RESOLVE     OO_IOC_W(CP_ARP_RESOLVE, cicp_verinfo_t)

  OO_OP_CP_ARP_CONFIRM,
#define OO_IOC_CP_ARP_CONFIRM     OO_IOC_W(CP_ARP_CONFIRM, cicp_verinfo_t)

  OO_OP_CP_WAIT_FOR_SERVER,
#define OO_IOC_CP_WAIT_FOR_SERVER OO_IOC_W(CP_WAIT_FOR_SERVER, ci_uint32)
  OO_OP_CP_LINK,
#define OO_IOC_CP_LINK            OO_IOC_NONE(CP_LINK)
  OO_OP_CP_READY,
#define OO_IOC_CP_READY           OO_IOC_NONE(CP_READY)
  OO_OP_CP_CHECK_VERSION,
#define OO_IOC_CP_CHECK_VERSION   OO_IOC_W(CP_CHECK_VERSION, \
                                           oo_cp_version_check_t)

  OO_OP_OOF_CP_IP_MOD,
#define OO_IOC_OOF_CP_IP_MOD      OO_IOC_W(OOF_CP_IP_MOD, \
                                           struct oo_op_cplane_ipmod)

  OO_OP_OOF_CP_LLAP_MOD,
#define OO_IOC_OOF_CP_LLAP_MOD    OO_IOC_W(OOF_CP_LLAP_MOD, \
                                           struct oo_op_cplane_llapmod)

  OO_OP_OOF_CP_LLAP_UPDATE_FILTERS,
#define OO_IOC_OOF_CP_LLAP_UPDATE_FILTERS OO_IOC_W(OOF_CP_LLAP_UPDATE_FILTERS, \
                                                   struct oo_op_cplane_llapmod)

  OO_OP_CP_PRINT,
#define OO_IOC_CP_PRINT           OO_IOC_NONE(CP_PRINT)

  OO_OP_CP_NOTIFY_LLAP_MONITORS,
#define OO_IOC_CP_NOTIFY_LLAP_MONITORS OO_IOC_NONE(CP_NOTIFY_LLAP_MONITORS)

  OO_OP_CP_END  /* This had better be last! */
};

#endif /*__CPLANE_IOCTL_H__*/

