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
** <L5_PRIVATE L5_SOURCE>
** \author  djr; jf, refactoring
**  \brief  Event timer helper routines
**   \date  2008/07/31
**    \cop  (c) Level 5 Networks Limited.
**    \cop  (c) 2008, Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_citools */

#include <etherfabric/timer.h>
#include "ef_vi_internal.h"


static void ef_eventq_timer_poke(ef_vi* q, unsigned v)
{
  writel(v, q->evq_timer_reg);
  mmiowb();
}


void falcon_ef_eventq_timer_prime(ef_vi* q, unsigned v)
{
  int vv = (((v * 1000) + q->timer_quantum_ns - 1) / q->timer_quantum_ns);
  EF_VI_BUG_ON(v <= 0);
  EF_VI_BUG_ON(vv <= 0);
  EF_VI_BUG_ON(q->nic_type.arch != EF_VI_ARCH_FALCON);
  if( q->nic_type.variant >= 'C' )
    ef_eventq_timer_poke(q, vv | EFVI_FALCON_CZ_EVQTIMER_HOLD);
  else
    ef_eventq_timer_poke(q, vv | EFVI_FALCON_AB_EVQTIMER_HOLD);
}


void falcon_ef_eventq_timer_run(ef_vi* q, unsigned v)
{
  int vv = (((v * 1000) + q->timer_quantum_ns - 1) / q->timer_quantum_ns);
  EF_VI_BUG_ON(v <= 0);
  EF_VI_BUG_ON(vv <= 0);
  EF_VI_BUG_ON(q->nic_type.arch != EF_VI_ARCH_FALCON);
  if( q->nic_type.variant >= 'C' )
    ef_eventq_timer_poke(q, vv | EFVI_FALCON_CZ_EVQTIMER_RUN);
  else
    ef_eventq_timer_poke(q, vv | EFVI_FALCON_AB_EVQTIMER_RUN);
}


void falcon_ef_eventq_timer_clear(ef_vi* q)
{
  EF_VI_BUG_ON(q->nic_type.arch != EF_VI_ARCH_FALCON);
  if( q->nic_type.variant >= 'C' )
    ef_eventq_timer_poke(q, EFVI_FALCON_CZ_EVQTIMER_DISABLE);
  else
    ef_eventq_timer_poke(q, EFVI_FALCON_AB_EVQTIMER_DISABLE);
}


void falcon_ef_eventq_timer_zero(ef_vi* q)
{
  EF_VI_BUG_ON(q->nic_type.arch != EF_VI_ARCH_FALCON);
  if( q->nic_type.variant >= 'C' )
    ef_eventq_timer_poke(q, 1u | EFVI_FALCON_CZ_EVQTIMER_HOLD);
  else
    ef_eventq_timer_poke(q, 1u | EFVI_FALCON_AB_EVQTIMER_HOLD);
}
