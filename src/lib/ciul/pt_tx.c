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
	** backwards. */
	EF_VI_BUG_ON(((ev->tx.desc_id - qs->removed) & q->mask) > 128);
	/* Should not complete more than we've posted. */
	EF_VI_BUG_ON(((ev->tx.desc_id - qs->removed) & q->mask) >
		     qs->added - qs->removed);

	for( i = qs->removed & q->mask; i != stop; i = ++qs->removed & q->mask )
		if( q->ids[i] != EF_REQUEST_ID_MASK ) {
			*ids++ = q->ids[i];
			q->ids[i] = EF_REQUEST_ID_MASK;
		}

	EF_VI_BUG_ON(ids - ids_in > EF_VI_TRANSMIT_BATCH);
	return (int) (ids - ids_in);
}


int ef_pio_memcpy(ef_vi* vi, const void* base, int offset, int len)
{
	/* PIO region on NIC is write only and has some alignment
	   requirements. */
	ef_pio* pio = vi->linked_pio;
	uint64_t *src, *dst;

	if( offset + len > pio->pio_len ) {
		LOGVV(ef_log("%s: offset(%d) + len(%d) > pio_len(%u)", 
			     __FUNCTION__, offset, len, pio->pio_len));
		return -EINVAL;
	}

	memcpy(pio->pio_buffer + offset, base, len);

	len += CI_OFFSET(offset, 8);
	offset = CI_ROUND_DOWN(offset, 8);
	len = CI_ROUND_UP(len, 8);

	/* This loop is doing the following, but guarantees word access:
	 * memcpy(pio->pio_io + offset, pio->pio_buffer + offset, len); 
	 */
	dst=(uint64_t*)(pio->pio_io + offset);
	src=(uint64_t*)(pio->pio_buffer + offset);
	for( ; src < (uint64_t*)(pio->pio_buffer + offset + len); ++src,++dst )
		*dst = *src;
  
	return 0;
}

/*! \cidoxg_end */
