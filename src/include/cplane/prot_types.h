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

/* The details of these data structures are not public - please do not
   refer to their content directly - use the functions defined in
   <onload/cplane.h>
*/


typedef struct {
    ci_ip_addr_t ip;
    ci_uint16 id;
    ci_uint16 tx_seq_next;
    ci_uint8 rx_type;
    ci_uint8 rx_code;
    ci_uint16 rx_seq;
    ci_uint8 rx_valid;
} cicppl_client_t;


struct cicp_bufpool_pkt {
  int id;
  int len;
};


/*----------------------------------------------------------------------------
 * Address Resolution MIB Data Types
 *---------------------------------------------------------------------------*/


/*! Protocol-support module-specific per-entry information */
typedef struct
{   /*! e.g. a field that is valid when an ARP request has been sent and we are
     *  waiting for the reply. If arp_pending.arp_pktid == -1, then the
     *  no ARP packet is pending i.e. structure is unsused.
     */
    /* e.g. ci_arp_pending_t arp_pending; */
} cicppl_mac_row_t;


/*! Protocol-support module-specific per-table information */
typedef struct  
{   ci_uint32 flags;
    /*! queued data in driverlink, is used to batch queue packets in
     *  driverlink and then sending a single notification for the whole
     *  batch */
} cicppl_mac_mib_t;


/*----------------------------------------------------------------------------
 * Pooled packet buffer
 *---------------------------------------------------------------------------*/

typedef struct cicp_bufpool_s cicp_bufpool_t;


#endif /* __CPLANE_PROT_TYPES_H__ */
