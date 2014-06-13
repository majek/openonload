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


void ef10_ef_eventq_timer_prime(ef_vi* q, unsigned v)
{
  int vv = (((v * 1000) + q->timer_quantum_ns - 1) / q->timer_quantum_ns);
  BUG_ON(v <= 0);
  BUG_ON(vv <= 0);
  BUG_ON(q->nic_type.arch != EF_VI_ARCH_EF10);

  if( q->nic_type.flags & EF_VI_NIC_FLAG_BUG35388_WORKAROUND ) {
    if( vv > 0xff )
      vv = 0xff;
    writel(REV0_OP_TMR | REV0_HUNTINGTON_DZ_EVQTIMER_HOLD | vv,
           q->vi_txq.doorbell);
  }
  else {
    /* Verify that this NIC variant does not require the workaround.
     */
    BUG_ON( q->nic_type.revision < 2 );
    writel(vv | EFVI_HUNTINGTON_DZ_EVQTIMER_HOLD, q->evq_timer_reg);
  }
}


void ef10_ef_eventq_timer_run(ef_vi* q, unsigned v)
{
  int vv = (((v * 1000) + q->timer_quantum_ns - 1) / q->timer_quantum_ns);
  BUG_ON(v <= 0);
  BUG_ON(vv <= 0);
  BUG_ON(q->nic_type.arch != EF_VI_ARCH_EF10);

  if( q->nic_type.flags & EF_VI_NIC_FLAG_BUG35388_WORKAROUND ) {
    if( vv > 0xff )
      vv = 0xff;
    writel(REV0_OP_TMR | REV0_HUNTINGTON_DZ_EVQTIMER_RUN | vv,
           q->vi_txq.doorbell);
  }
  else {
    /* Verify that this NIC variant does not require the workaround.
     */
    BUG_ON( q->nic_type.revision < 2 );
    writel(vv | EFVI_HUNTINGTON_DZ_EVQTIMER_RUN, q->evq_timer_reg);
  }
}


void ef10_ef_eventq_timer_clear(ef_vi* q)
{
  BUG_ON(q->nic_type.arch != EF_VI_ARCH_EF10);
  if( q->nic_type.flags & EF_VI_NIC_FLAG_BUG35388_WORKAROUND ) {
    writel(REV0_OP_TMR | REV0_HUNTINGTON_DZ_EVQTIMER_DISABLE,
           q->vi_txq.doorbell);
  }
  else {
    /* Verify that this NIC variant does not require the workaround.
     */
    BUG_ON( q->nic_type.revision < 2 );
    writel(EFVI_HUNTINGTON_DZ_EVQTIMER_DISABLE, q->evq_timer_reg);
  }
}


void ef10_ef_eventq_timer_zero(ef_vi* q)
{
  BUG_ON(q->nic_type.arch != EF_VI_ARCH_EF10);
  if( q->nic_type.flags & EF_VI_NIC_FLAG_BUG35388_WORKAROUND ) {
    writel(1u | REV0_OP_TMR | REV0_HUNTINGTON_DZ_EVQTIMER_HOLD,
           q->vi_txq.doorbell);
  }
  else {
    /* Verify that this NIC variant does not require the workaround.
     */
    BUG_ON( q->nic_type.revision < 2 );
    writel(1u | EFVI_HUNTINGTON_DZ_EVQTIMER_HOLD, q->evq_timer_reg);
  }
}
