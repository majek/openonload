/*
** Copyright 2005-2015  Solarflare Communications Inc.
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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  stg
**  \brief  Linux specific ICMP & IGMP & UDP handlers.  UDP handling is
**          for broadcasts which are not (currently) filtered by the NIC.
**   \date  2004/06/23
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab */

#ifndef __CI_DRIVER_EFAB_IP__PROTOCOLS_H__
#define __CI_DRIVER_EFAB_IP__PROTOCOLS_H__

#ifndef __ci_driver__
#error "This is a driver module."
#endif

#include <ci/net/ipv4.h>


/*! struct containing ptrs into icmp data area and 
 * addressing & protocol data from an ICMP pkt */
typedef struct {
  const ci_ip4_hdr *ip; /*< IP PDU holding ICMP message */
  ci_icmp_hdr *icmp;    /*< ICMP header in IP PDU */
  ci_uint8* data;       /*< ICMP reply data following header */
  int data_len;         /*< ICMP len if icmp set & whole IP PDU in reply */
  ci_uint32 saddr_be32; /*< dest IP of IP PDU in ICMP reply data */
  ci_uint32 daddr_be32; /*< src IP of IP PDU in ICMP reply data */
  ci_uint16 sport_be16; /*< dest port of TCP/UDP IP PDU in ICMP reply data */
  ci_uint16 dport_be16; /*< src port of TCP/UDP IP PDU in ICMP reply data */
  ci_uint8  protocol;   /*< protocol of IP PDU in ICMP reply data */
} efab_ipp_addr;

#endif

/*! \cidoxg_end */
