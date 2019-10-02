/*
** Copyright 2005-2019  Solarflare Communications Inc.
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

/****************************************************************************
 * Copyright 2002-2005: Level 5 Networks Inc.
 * Copyright 2005-2008: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

/*! \cidoxg_lib_ef */
#include "ef_vi_internal.h"


int ef_vi_receive_post(ef_vi* vi, ef_addr addr, ef_request_id dma_id)
{
  int rc = ef_vi_receive_init(vi, addr, dma_id);
  if( rc == 0 )  ef_vi_receive_push(vi);
  return rc;
}


int ef_vi_receive_unbundle(ef_vi* vi, const ef_event* ev,
                           ef_request_id* ids)
{
  ef_request_id* ids_in = ids;
  ef_vi_rxq* q = &vi->vi_rxq;
  ef_vi_rxq_state* qs = &vi->ep_state->rxq;
  unsigned i;

  EF_VI_BUG_ON( EF_EVENT_TYPE(*ev) != EF_EVENT_TYPE_RX_MULTI &&
                EF_EVENT_TYPE(*ev) != EF_EVENT_TYPE_RX_MULTI_DISCARD );
  EF_VI_BUG_ON( ev->rx_multi.n_descs > EF_VI_RECEIVE_BATCH );

  for( i = 0; i < ev->rx_multi.n_descs; ++i ) {
    unsigned di = qs->removed & q->mask;
    ++(qs->removed);
    if( q->ids[di] != EF_REQUEST_ID_MASK ) {
      *ids++ = q->ids[di];
      q->ids[di] = EF_REQUEST_ID_MASK;
    }
  }

  /* Check we didn't remove more than we've added. */
  EF_VI_ASSERT( qs->added - qs->removed <= q->mask );

  return (int) (ids - ids_in);
}

/*! \cidoxg_end */
