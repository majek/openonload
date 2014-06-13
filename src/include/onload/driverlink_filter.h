/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
** \author  stg, djr
**  \brief  Filter for "net driver" packets inspected via driverlink.
**   \date  2004/08/23
**    \cop  (c) Level 5 Networks Limited, Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab */

#ifndef __CI_DRIVER_EFAB_DRIVERLINK__FILTER_H__
#define __CI_DRIVER_EFAB_DRIVERLINK__FILTER_H__


struct ci_ether_hdr_s;
struct efx_dlfilt_cb_s;


/*! Construct a driverlink filter object - stored in the per-nic struct.
 * \Return     ptr to object or NULL if failed
 */
extern struct efx_dlfilt_cb_s* efx_dlfilter_ctor(void);

/*! Clean-up object created through efx_dlfilter_ctor() */
extern void efx_dlfilter_dtor(struct efx_dlfilt_cb_s*);

/*! Data-passing entry point. */
extern int
efx_dlfilter_handler(int ifindex, struct efx_dlfilt_cb_s*,
                     const struct ci_ether_hdr_s*, const void* ip_hdr, int len);


extern void efx_dlfilter_dump(struct efx_dlfilt_cb_s*, unsigned what);
#define EFAB_DLFILT_DUMP_LAT	     0x00010000
#define EFAB_DLFILT_DUMP_LACB_FREE   0x00000001
#define EFAB_DLFILT_DUMP_LACB_USED   0x00002000
#define EFAB_DLFILT_DUMP_ENTRYT	     0x00040000
#define EFAB_DLFILT_DUMP_ACTIVE      0x10000000


/* Add a filter.  Caller is responsible for protecting this and
 * efx_dlfilter_remove() from concurrency.
 */
extern void
efx_dlfilter_add(struct efx_dlfilt_cb_s*, unsigned protocol, unsigned laddr, 
                 ci_uint16 lport,  unsigned raddr, ci_uint16 rport, 
                 int thr_id, unsigned* handle_out);

/* Remove a filter.  Caller is responsible for protecting this and
 * efx_dlfilter_add() from concurrency.
 */
extern void
efx_dlfilter_remove(struct efx_dlfilt_cb_s*, unsigned handle);

#define EFX_DLFILTER_HANDLE_BAD  ((unsigned) -1)


extern void
efx_dlfilter_count_stats(struct efx_dlfilt_cb_s* fcb,
                         int *n_empty, int *n_tomp, int *n_used);

#endif /* __CI_DRIVER_EFAB_DRIVERLINK__FILTER_H__ */
/*! \cidoxg_end */
