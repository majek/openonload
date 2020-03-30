/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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


static void ef_eventq_timer_poke(ef_vi* vi, unsigned v)
{
  writel(v, vi->io + FR_BZ_TIMER_COMMAND_REGP0_OFST);
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
