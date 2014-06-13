/*
** Copyright 2005-2014  Solarflare Communications Inc.
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


/* Workaround for the lockup issue: bug35981,
 * bug35887, bug35388, bug36064.
 *
 * bug35887, comment35 describes the encoding.
 */
#define REV0_OP_TMR (3 << 10)
#define REV0_TIMER_SHIFT 8


#define REV0_HUNTINGTON_DZ_EVQTIMER_HOLD \
    (FFE_CZ_TIMER_MODE_TRIG_START << REV0_TIMER_SHIFT)
#define REV0_HUNTINGTON_DZ_EVQTIMER_RUN \
    (FFE_CZ_TIMER_MODE_IMMED_START << REV0_TIMER_SHIFT)
#define REV0_HUNTINGTON_DZ_EVQTIMER_DISABLE \
    (FFE_CZ_TIMER_MODE_DIS << REV0_TIMER_SHIFT)


#define EFVI_HUNTINGTON_DZ_EVQTIMER_HOLD \
    (FFE_CZ_TIMER_MODE_TRIG_START << ERF_DZ_TC_TIMER_MODE_LBN)
#define EFVI_HUNTINGTON_DZ_EVQTIMER_RUN \
    (FFE_CZ_TIMER_MODE_IMMED_START << ERF_DZ_TC_TIMER_MODE_LBN)
#define EFVI_HUNTINGTON_DZ_EVQTIMER_DISABLE \
    (FFE_CZ_TIMER_MODE_DIS << ERF_DZ_TC_TIMER_MODE_LBN)


#define bug35388_workaround_needed(vi)					\
  ((vi)->nic_type.variant == 'A' && (vi)->nic_type.revision < 2)


static inline void poke_timer(ef_vi* vi, unsigned v)
{
  /* TODO: Verify that this NIC variant does not require the bug35388
   * workaround.
   */
  EF_VI_BUG_ON( 1 );
  writel(v, vi->io + ER_DZ_EVQ_TMR_REG);
  /* ?? fixme: why does falcon use mmiowb() here but we don't? */
}


static inline void poke_timer_bug35388(ef_vi* vi, unsigned v)
{
  writel(v | REV0_OP_TMR, vi->io + ER_DZ_TX_DESC_UPD_REG + 8);
  /* ?? fixme: why does falcon use mmiowb() here but we don't? */
}


void ef10_ef_eventq_timer_prime(ef_vi* q, unsigned v)
{
  int vv = (((v * 1000) + q->timer_quantum_ns - 1) / q->timer_quantum_ns);
  EF_VI_ASSERT(v > 0);
  EF_VI_ASSERT(vv > 0);
  EF_VI_ASSERT(q->nic_type.arch == EF_VI_ARCH_EF10);
  EF_VI_ASSERT(q->inited & EF_VI_INITED_TIMER);

  if( bug35388_workaround_needed(q) ) {
    if( vv > 0xff )
      vv = 0xff;
    poke_timer_bug35388(q, vv | REV0_HUNTINGTON_DZ_EVQTIMER_HOLD);
  }
  else {
    poke_timer(q, vv | EFVI_HUNTINGTON_DZ_EVQTIMER_HOLD);
  }
}


void ef10_ef_eventq_timer_run(ef_vi* q, unsigned v)
{
  int vv = (((v * 1000) + q->timer_quantum_ns - 1) / q->timer_quantum_ns);
  EF_VI_ASSERT(v > 0);
  EF_VI_ASSERT(vv > 0);
  EF_VI_ASSERT(q->nic_type.arch == EF_VI_ARCH_EF10);
  EF_VI_ASSERT(q->inited & EF_VI_INITED_TIMER);

  if( bug35388_workaround_needed(q) ) {
    if( vv > 0xff )
      vv = 0xff;
    poke_timer_bug35388(q, vv | REV0_HUNTINGTON_DZ_EVQTIMER_RUN);
  }
  else {
    poke_timer(q, vv | EFVI_HUNTINGTON_DZ_EVQTIMER_RUN);
  }
}


void ef10_ef_eventq_timer_clear(ef_vi* q)
{
  EF_VI_ASSERT(q->nic_type.arch == EF_VI_ARCH_EF10);
  EF_VI_ASSERT(q->inited & EF_VI_INITED_TIMER);
  if( bug35388_workaround_needed(q) )
    poke_timer_bug35388(q, REV0_HUNTINGTON_DZ_EVQTIMER_DISABLE);
  else
    poke_timer(q, EFVI_HUNTINGTON_DZ_EVQTIMER_DISABLE);
}


void ef10_ef_eventq_timer_zero(ef_vi* q)
{
  EF_VI_ASSERT(q->nic_type.arch == EF_VI_ARCH_EF10);
  EF_VI_ASSERT(q->inited & EF_VI_INITED_TIMER);
  if( bug35388_workaround_needed(q) )
    poke_timer_bug35388(q, 1u | REV0_HUNTINGTON_DZ_EVQTIMER_HOLD);
  else
    poke_timer(q, 1u | EFVI_HUNTINGTON_DZ_EVQTIMER_HOLD);
}
