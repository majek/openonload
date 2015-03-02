/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
** \author  Akhi Singhania <asinghania@solarflare.com>
**  \brief  FD priming support
**   \date  2014/05/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include "ef_vi_internal.h"
#include "driver_access.h"


int ef_vi_prime(ef_vi* vi, ef_driver_handle dh, unsigned current_ptr)
{
  ci_resource_prime_op_t  op;
  op.crp_id = efch_make_resource_id(vi->vi_resource_id);
  op.crp_current_ptr = current_ptr;
  return ci_resource_prime(dh, &op);
}
