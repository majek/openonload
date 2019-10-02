/*
** Copyright 2005-2019  Solarflare Communications Inc.
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

/* Data types for cppl subsystem - driver only */
#ifndef __CPLANE_PROT_TYPES_H__
#define __CPLANE_PROT_TYPES_H__

/*! This file provides definitions are specific to given address resolution
 *  scenario.  For example two versions of this header may be used to deal
 *  with explicit ARP protocols and with "raw" socket ARP use.
 *
 *  In the (distant?) future ICMPv6 support may be added here.
 *
 *  The prefix cicppl is used for definitions in this header:
 *       ci - our main prefix
 *       cp - control plane
 *       pl - protocols
 */

/*----------------------------------------------------------------------------
 * O/S-specific Address Resolution MIB Data types
 *---------------------------------------------------------------------------*/


struct cicp_bufpool_pkt {
  int id;
  int len;
};


/*----------------------------------------------------------------------------
 * Pooled packet buffer
 *---------------------------------------------------------------------------*/

typedef struct cicp_bufpool_s cicp_bufpool_t;

struct cicppl_stat {
  ci_uint32 dropped_ip;        /*!< # of IP pkts dropped                  */
};


struct cicppl_instance {
  struct socket *bindtodev_raw_sock;
  ci_ifid_t bindtodevice_ifindex;
  cicp_bufpool_t *pktpool;
  struct cicppl_stat stat;
  spinlock_t lock;
  struct oo_cplane_handle *cp;
};


#endif /* __CPLANE_PROT_TYPES_H__ */
