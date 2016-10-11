/*
** Copyright 2005-2016  Solarflare Communications Inc.
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

/* Internal cplane file - provides linkage between UL cplane library and
 * kernel cplane module. */
#ifndef __CPLANE_IOCTL_H__
#define __CPLANE_IOCTL_H__

#include <ci/compat.h>

typedef struct {
  /* IN: versions to check */
  ci_user_ptr_t api_version;
  ci_user_ptr_t lib_version;

  /* OUT: */
  ci_uint32 mac_mmap_len;
  ci_uint32 fwdinfo_mmap_len;
  ci_uint32 llapinfo_mmap_len;
  ci_uint32 bondinfo_mmap_len;
  ci_uint32 mmap_len;
} cicp_ns_mmap_info_t;

typedef struct {
  cicp_mac_verinfo_t ver;
  ci_ip_addr_t ip;
  ci_mac_addr_t mac;
  ci_ifid_t ifindex;
  ci_int32 /*bool*/  confirm;
} cp_mac_update_t;

typedef struct {
  ci_ip_addr_t   ip_be32; /* IN */
  ci_ifid_t      ifindex;
  ci_hwport_id_t hwport;
  ci_mac_addr_t  mac;
  ci_mtu_t       mtu;
  cicp_encap_t   encap;
} cp_src_addr_checks_t;

#include <asm/ioctls.h>

/* Do we need some automation to keep OO_LINUX_IOC_BASE OO_EPOLL_IOC_BASE
 * CI_IOC_CHAR_BASE CICP_IOC_BASE different? */
#define CICP_IOC_BASE 91

#define CICP_IOC_W(nr, type)  _IOW(CICP_IOC_BASE, nr, type)
#define CICP_IOC_R(nr, type)  _IOR(CICP_IOC_BASE, nr, type)
#define CICP_IOC_RW(nr, type) _IOWR(CICP_IOC_BASE, nr, type)

#define CICP_IOC_INIT_MMAP      CICP_IOC_RW(0, cicp_ns_mmap_info_t)
#define CICP_IOC_MAC_UPDATE     CICP_IOC_W(1, cp_mac_update_t)
#define CICP_IOC_USER_FIND_HOME CICP_IOC_RW(2, cp_src_addr_checks_t)

#endif /* __CPLANE_IOCTL_H__ */
