/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
**  \brief  "Private" interface for the driverlink filter module
**           Filtering support for the Net -> char data traffic
**   \date  2004/08/23
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab */

#ifndef __CI_DRIVER_EFAB_DRIVERLINK__FILTER__PRIVATE_H__
#define __CI_DRIVER_EFAB_DRIVERLINK__FILTER__PRIVATE_H__

/* This file is a part of driverlink_filter.h; it is included only from
 * driverlink_filter.h. */
#ifndef __ci_driver__
#error "This is a driver module."
#endif


/*! This structure defines one record in the local address lut */
typedef struct efx_dlfilt_local_addr_s {
  ci_dllink link;
  ci_uint32 addr_be32;	/*!< Efab IP address */
  int ref_count;        /*!< Refcount from main filters (if in use) */
} efx_dlfilt_local_addr_t;


#if CI_CFG_NET_DHCP_FILTER
/*! Type for DHCP filtering hook function */
typedef int (*efx_dlfilter_dhcp_hook_t)(const ci_ether_hdr*,
                                        const void* ip_hdr, int len);
#endif


/* This needs to be sufficiently large to include all local IP addresses
 * and all multicast addresses we're subscribing too.
 */
#define EFAB_DLFILT_LA_COUNT 120


/*! Defines one entry in the master filter table */
typedef struct efx_dlfilt_entry_s {
  int       thr_id;     /*!< TCP helper res. ID from char driver 
			* (-1 if unknown) */
  ci_uint32 raddr_be32;
  ci_uint16 rport_be16;
  ci_uint16 lport_be16;
  ci_int16  laddr_idx;
  ci_uint16 state;
#define EFAB_DLFILT_INUSE      0x0000
#define EFAB_DLFILT_TOMBSTONE  0x4000
                            /* 0x8000 invalid */
#define EFAB_DLFILT_EMPTY      0xC000
#define EFAB_DLFILT_STATE_MASK 0xC000
#define EFAB_DLFILT_STATE_SHIFT 14
  ci_uint8  ip_protocol;
} efx_dlfilt_entry_t;


/* ?? FIXME: This really should not be defined here. */
#define EFHW_IP_FILTER_NUM		8192

/* MUST BE a power of 2, <= 16384  & accomodate the number 
 * of NIC hardware filters */
#define EFAB_DLFILT_ENTRY_COUNT (2*(EFHW_IP_FILTER_NUM))


/*! The master filter table control block. One per NIC.  */
typedef struct efx_dlfilt_cb_s {
  int used_slots;
  efx_dlfilt_entry_t table[EFAB_DLFILT_ENTRY_COUNT];
  /* la_free and la_used lists are locked by filter manager lock. */
  ci_dllist la_free;
  ci_dllist la_used;
  efx_dlfilt_local_addr_t la_table[EFAB_DLFILT_LA_COUNT];
#if CI_CFG_NET_DHCP_FILTER
  efx_dlfilter_dhcp_hook_t dhcp_filter;
#endif
} efx_dlfilter_cb_t ;


#endif /* __CI_DRIVER_EFAB_DRIVERLINK__FILTER__PRIVATE_H__ */
/*! \cidoxg_end */
