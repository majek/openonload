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
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: slp
**     Started: 2005/04/22
** Description: Interface for the tcp driver pluggin. This is all the
** stuff, control plane and asynchronous threads which is requried to
** support a ULTCP stack
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab  */

#ifndef __CI_DRIVER_EFAB_TCP_DRIVER_H__
#define __CI_DRIVER_EFAB_TCP_DRIVER_H__

#include <onload/cplane_types.h>
#include <onload/ipid.h>
#include <onload/id_pool.h>
#include <onload/tcp_helper.h>


/* Table of TCP helpers. Contains all TCP helpers created by the driver.
 * Should be grown  if necessary.
 */
typedef struct {
  /*! Instances of tcp helpers */
  ci_id_pool_t  instances;

  /*! List of all stacks (orphaned or not). */
  ci_dllist     all_stacks;

  /*! Lock */
  ci_irqlock_t  lock;
} tcp_helpers_table_t;


/*----------------------------------------------------------------------------
 *
 * tcp driver interface
 * \todo FIXME split this structure (and global variable efab_tcp_driver)
 * into separate fields.
 *
 *---------------------------------------------------------------------------*/

struct oof_manager;


typedef struct efab_tcp_driver_s {

  /*! TCP helpers table */
  tcp_helpers_table_t     thr_table;

  /*! Control plane tables handle (this is not simply a pointer) */
  cicp_handle_t           cplane_handle;

  /* ID field in the IP header handling */
  efab_ipid_cb_t          ipid;         /* see ipid.h in this dir. */

  /*! Management of RX demux -- s/w and h/w filters. */
  struct oof_manager*           filter_manager;
  cicpos_ipif_callback_handle_t filter_manager_cp_handle;

  /*! work queue */
  ci_workqueue_t          workqueue;

  /*! Number of pages pinned by all sendpage() users */
  ci_atomic_t sendpage_pinpages_n;
  /*! An overall limit of pinned pages for all sendpage() users */
  int sendpage_pinpages_max;


  struct efx_dlfilt_cb_s* dlfilter;

  struct oo_file_ref*     file_refs_to_drop;

  /* Dynamic stack list update: flag and wait queue.  Used by tcpdump */
  ci_uint32         stack_list_seq;
  ci_waitq_t        stack_list_wq;

} efab_tcp_driver_t;


/* Global structure for onload driver */
extern efab_tcp_driver_t efab_tcp_driver;


#define CI_GLOBAL_CPLANE         (efab_tcp_driver.cplane_handle)
#define THR_TABLE                (efab_tcp_driver.thr_table)
#define CI_GLOBAL_WORKQUEUE      (efab_tcp_driver.workqueue)


#endif /* __CI_DRIVER_EFAB_TCP_DRIVER_H__ */
/*! \cidoxg_end */
