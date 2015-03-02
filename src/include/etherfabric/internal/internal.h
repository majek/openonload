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

/****************************************************************************
 * Copyright 2013-2015: Solarflare Communications Inc,
 *                      7505 Irvine Center Drive, Suite 100
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

#ifndef __EFAB_INTERNAL_H__
#define __EFAB_INTERNAL_H__

/* Internal interfaces, so exclude from doxygen documentation */
/*! \cond internal */

/* This must die. It is used where we don't yet know how to find the 
 * right NIC to use in a multiple NIC system. */
#define CI_DEFAULT_NIC 0

typedef union {
  uint64_t  u64[1];
  uint32_t  u32[2];
  uint16_t  u16[4];
} ef_vi_qword;


struct ef_vi;


/*! Return size of state buffer of an initialised VI. */
extern int ef_vi_state_bytes(ef_vi*);

/*! Return size of buffer needed for VI state given sizes of RX and TX
** DMA queues.  Queue sizes must be legal sizes (power of 2), or 0 (no
** queue).
*/
extern int ef_vi_calc_state_bytes(int rxq_size, int txq_size);

/*! Convert an efhw device arch to ef_vi_arch, or returns -1 if not
** recognised.
*/
extern int  ef_vi_arch_from_efhw_arch(int efhw_arch);

/* Add a VI into the set managed by a VI with an event queue.  Only needed
 * when a VI is constructed manually.
 *
 * Returns the Q label (>= 0) on success, or -EBUSY if [evq_vi] already has
 * a full complement of slaved VIs.
 */
extern int ef_vi_add_queue(ef_vi* evq_vi, ef_vi* add_vi);

/* Place statistics relating to errors in the nominated buffer.
 *
 * This call does not populate [s] immediately; stats are updated by other
 * calls, so the lifetime of [s] must be as long as the vi.
 */
extern void ef_vi_set_stats_buf(ef_vi* vi, ef_vi_stats* s);


/**********************************************************************
 * Re-Initialisation **************************************************
 **********************************************************************/

/* This set of functions will reinitialise the software rings and deal
 * with any buffers that they contain by calling the supplied callback
 * for each one to allow it to be freed.
 */

typedef void (*ef_vi_reinit_callback)(ef_request_id id, void* arg);

extern int ef_vi_rxq_reinit(ef_vi* vi, ef_vi_reinit_callback cb, void* cb_arg);
extern int ef_vi_txq_reinit(ef_vi* vi, ef_vi_reinit_callback cb, void* cb_arg);
extern int ef_vi_evq_reinit(ef_vi* vi);


/**********************************************************************
 * Misc ***************************************************************
 **********************************************************************/

extern int  ef_vi_rx_ring_bytes(struct ef_vi*);

extern int  ef_vi_init(struct ef_vi*, int arch, int variant, int revision,
		       unsigned ef_vi_flags, ef_vi_state*);

extern void ef_vi_init_io(struct ef_vi*, void* io_area);

extern void ef_vi_init_rxq(struct ef_vi*, int ring_size, void* descriptors,
			   void* ids, int prefix_len);

extern void ef_vi_init_txq(struct ef_vi*, int ring_size, void* descriptors,
			   void* ids);

extern void ef_vi_init_evq(struct ef_vi*, int ring_size, void* event_ring);

extern void ef_vi_init_timer(struct ef_vi* vi, int timer_quantum_ns);

extern void ef_vi_init_rx_timestamping(struct ef_vi* vi, int rx_ts_correction);
extern void ef_vi_init_tx_timestamping(struct ef_vi* vi);

extern void ef_vi_init_out_flags(struct ef_vi* vi, unsigned flags);

extern void ef_vi_init_state(struct ef_vi*);

extern void ef_vi_reset_rxq(struct ef_vi*);

extern void ef_vi_reset_txq(struct ef_vi*);

extern void ef_vi_reset_evq(struct ef_vi*, int clear_ring);


/* Internal interfaces, so exclude from doxygen documentation */
/*! \endcond internal */

#endif  /* __EFAB_INTERNAL_H__ */
