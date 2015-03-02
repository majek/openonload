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
** \author  ok_sasha
**  \brief  eplock resource internal API
**     $Id$
**   \date  2007/08
**    \cop  (c) Solaraflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_onload  */

/* This file is a part of ci/internal/ip.h or.
 * ***** Do not include it directly! Include ip.h instead! *****
 */

#ifndef __ONLOAD_EPLOCK_REOSURCE_H__
#define __ONLOAD_EPLOCK_REOSURCE_H__

/*--------------------------------------------------------------------
 *
 * eplock_resource_t
 *
 *--------------------------------------------------------------------*/

/* Set this to 1 to record which user processes waited when acquiring
** eplock.
*/
#define CI_CFG_EFAB_EPLOCK_RECORD_CONTENTIONS	0
#define EFAB_EPLOCK_MAX_NO_PIDS     40

/*! Comment? */
typedef struct {
  wait_queue_head_t     wq;

#if CI_CFG_EFAB_EPLOCK_RECORD_CONTENTIONS
  /* if asked we keep a record of who waited on this lock */
  int                   pids_who_waited[EFAB_EPLOCK_MAX_NO_PIDS];
  unsigned              pids_no_waits[EFAB_EPLOCK_MAX_NO_PIDS];
  ci_irqlock_t          pids_lock;
#endif
} eplock_helper_t;


extern int eplock_ctor(ci_netif *ni);
extern void eplock_dtor(ci_netif *ni);

/*! Comment? */
extern int efab_eplock_unlock_and_wake(ci_netif *ni, int in_dl_context);

/*! Comment? */
extern int efab_eplock_lock_wait(ci_netif* ni
				 CI_BLOCKING_CTX_ARG(ci_blocking_ctx_t bc));

extern int
efab_eplock_lock_timeout(ci_netif* ni, signed long timeout_jiffies);

#endif /* __ONLOAD_EPLOCK_REOSURCE_H__ */
/*! \cidoxg_end */
