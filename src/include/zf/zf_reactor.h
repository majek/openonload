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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  mj
**  \brief  ZF Reactor - fast path
**   \date  2015/10/20
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*/

#ifndef __REACTOR_H__
#define __REACTOR_H__


#include <zf/zf_platform.h>
#include <zf/types.h>

struct zf_stack;

/*! \brief Process events on a stack 
**
** \param st           Stack for which to process events.
**
** \return 0 if nothing user-visible occurred as a result\n
**         1 if something user-visible occurred as a result.
*/
LIBENTRY ZF_HOT int
zf_reactor_perform(struct zf_stack* st);


#endif /* __REACTOR_H__ */
