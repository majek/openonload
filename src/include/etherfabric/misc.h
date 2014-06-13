/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
#ifndef __ETHERFABRIC_MISC_H__
#define __ETHERFABRIC_MISC_H__

#include <etherfabric/base.h>
#include <ci/driver/efab/open.h>
#include <ci/driver/efab/efch_id.h>


ef_vi_inline efch_resource_id_t ef_eventq_id(ef_vi* vi)
{ return efch_make_resource_id(vi->vi_resource_id); }


  /*! Send an event to an event queue.
  **
  ** Right now you only get 16 bits to play with.
  */
extern int ef_eventq_put(efch_resource_id_t evq_id,
                         ef_driver_handle, unsigned ev);


#endif  /* __ETHERFABRIC_MISC_H__ */
