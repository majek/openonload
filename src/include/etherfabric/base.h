/*
** Copyright 2005-2013  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Base definitions for EtherFabric HAL.
**   \date  2004/06/23
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_etherfabric */
#ifndef __EFAB_BASE_H__
#define __EFAB_BASE_H__

#include <etherfabric/ef_vi.h>

#ifdef __cplusplus
extern "C" {
#endif


/* This must die. It is used where we don't yet know how to find the 
 * right NIC to use in a multiple NIC system. */
#define CI_DEFAULT_NIC 0


  /*! \i_ef_base An [ef_driver_handle] is needed to allocate resources. */
#ifdef __KERNEL__
typedef struct efhw_nic*   ef_driver_handle;
#else
typedef int                ef_driver_handle;
#endif

struct timeval;

#define EF_ADDR_FMT             "%"CI_PRIx64
#define EF_INVALID_ADDR         ((ef_addr) -1)


/**********************************************************************
 * ef_vi **************************************************************
 **********************************************************************/

  /*! \i_ef_event Allocate an event queue for a singe NIC.
  **
  ** The NIC supports a limited range of capacities.  The actually capacity
  ** of the queue will may be larger than that requested, or may be smaller
  ** if the capacity requested is larger than the maximum supported.
  **
  */
extern int ef_eventq_alloc(ef_vi* evq, ef_driver_handle nic,
                           unsigned capacity);

  /*! \i_ef_event Free an event queue. This function is deeply flawed
   when talking about multiple NICs. */
extern int ef_eventq_free(ef_vi*, ef_driver_handle nic);

  /*! \i_ef_event Block until the event queue is non-empty.
  **
  ** Note that when this function returns it is not guaranteed that an
  ** event will be present in the event queue, but in most cases there will
  ** be.
  **
  **   \param current_ptr must come from ef_eventq_current()
  **   \param timeout of zero means wait forever
  **
  **   \return 0 on success, or -ETIMEDOUT on time-out
  */
extern int ef_eventq_wait(ef_vi*, ef_driver_handle nic,
                          unsigned current_ptr,
                          const struct timeval*);


/**********************************************************************
 * ef_driver **********************************************************
 **********************************************************************/

  /*! \i_ef_base Obtain a driver handle. */
extern int ef_driver_open(ef_driver_handle* dh_out);

  /*! \i_ef_base Close a driver handle. */
extern int ef_driver_close(ef_driver_handle);

#ifdef __cplusplus
}
#endif

#endif  /* __EFAB_BASE_H__ */
/*! \cidoxg_end */
