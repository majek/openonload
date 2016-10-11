/*
** Copyright 2005-2016  Solarflare Communications Inc.
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

/*
 * \author  djr
 *  \brief  Packet-mode transmit interface.
 *   \date  2003/04/02
 */

/*! \cidoxg_lib_ef */
#include <etherfabric/pio.h>
#include "ef_vi_internal.h"
#include "logging.h"
#include "memcpy_to_io.h"


int ef_vi_transmit_init(ef_vi* vi, ef_addr base, int len, ef_request_id dma_id)
{
  ef_iovec iov = { base, len };
  return ef_vi_transmitv_init(vi, &iov, 1, dma_id);
}


int ef_vi_transmit_unbundle(ef_vi* vi, const ef_event* ev,
			    ef_request_id* ids)
{
  ef_request_id* ids_in = ids;
  ef_vi_txq* q = &vi->vi_txq;
  ef_vi_txq_state* qs = &vi->ep_state->txq;
  unsigned i, stop = ev->tx.desc_id & q->mask;

  EF_VI_BUG_ON(EF_EVENT_TYPE(*ev) != EF_EVENT_TYPE_TX &&
               EF_EVENT_TYPE(*ev) != EF_EVENT_TYPE_TX_ERROR);

  /* Shouldn't be batching more than 128 descriptors, and should not go
  ** backwards. See comment 7 on bug 44002. */
  EF_VI_BUG_ON(((ev->tx.desc_id - qs->removed) & q->mask) > 128);
  /* Should not complete more than we've posted. */
  EF_VI_BUG_ON(((ev->tx.desc_id - qs->removed) & q->mask) >
               qs->added - qs->removed);

  for( i = qs->removed & q->mask; i != stop; i = ++qs->removed & q->mask )
    if( q->ids[i] != EF_REQUEST_ID_MASK ) {
      *ids++ = q->ids[i];
      q->ids[i] = EF_REQUEST_ID_MASK;
    }

  /* This is a count of packets, not descriptors. Again, see comment 7 on
   * bug 44002. */
  EF_VI_BUG_ON(ids - ids_in > EF_VI_TRANSMIT_BATCH);
  return (int) (ids - ids_in);
}


int ef_pio_memcpy(ef_vi* vi, const void* base, int offset, int len)
{
  /* PIO region on NIC is write only, and to avoid silicon bugs must
   * only be hit with writes at are 64-bit aligned and a multiple of
   * 64-bits in size.
   */
  ef_pio* pio = vi->linked_pio;

  EF_VI_ASSERT(offset + len <= pio->pio_len);

  memcpy(pio->pio_buffer + offset, base, len);

  len += CI_OFFSET(offset, MEMCPY_TO_PIO_ALIGN);
  offset = CI_ROUND_DOWN(offset, MEMCPY_TO_PIO_ALIGN);
  len = CI_ROUND_UP(len, MEMCPY_TO_PIO_ALIGN);

  /* To ensure that the resulting TLPs are aligned and have all their
   * byte-enable bits set, we must ensure that the data in the WC buffer is
   * always contiguous. See bug49906.
   */
  wmb_wc();
  memcpy_to_pio_aligned(pio->pio_io + offset, pio->pio_buffer + offset, len);
  return 0;
}


unsigned ef_vi_transmit_alt_num_ids(ef_vi* vi)
{
  return vi->tx_alt_num;
}

/*! \cidoxg_end */
