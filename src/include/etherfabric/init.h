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

#ifndef __EFAB_INIT_H__
#define __EFAB_INIT_H__


struct ef_vi;


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


#endif  /* __EFAB_INIT_H__ */
