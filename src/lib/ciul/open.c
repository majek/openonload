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
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_ef */
#include <etherfabric/base.h>
#include "ef_vi_internal.h"
#include "logging.h"
#include <fcntl.h>
#include <unistd.h>


int ef_driver_open(ef_driver_handle* pfd)
{
  int rc;
  rc = open("/dev/sfc_char", O_RDWR);
  if( rc >= 0 ) {
    *pfd = rc;
    return 0;
  }
  return -errno;
}


int ef_driver_close(ef_driver_handle dh)
{
  return close(dh);
}

/*! \cidoxg_end */
