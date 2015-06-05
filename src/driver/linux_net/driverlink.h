/*
** Copyright 2005-2015  Solarflare Communications Inc.
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

/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005      Fen Systems Ltd.
 * Copyright 2006-2015 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_DRIVERLINK_H
#define EFX_DRIVERLINK_H

struct efx_nic;

void efx_dl_register_nic(struct efx_nic *efx);
void efx_dl_unregister_nic(struct efx_nic *efx);

/* Suspend and resume client drivers over a hardware reset */
void efx_dl_reset_suspend(struct efx_nic *efx);
void efx_dl_reset_resume(struct efx_nic *efx, int ok);

/* Send unrecognised event to client drivers */
int efx_dl_handle_event(struct efx_nic *efx, void *event, int budget);

/* Pass the first fragment of an RX packet to client drivers for inspection,
 * allowing them to request that it be discarded
 */
bool efx_dl_rx_packet(struct efx_nic *efx, int channel, u8 *pkt_hdr, int len);

/* List of all registered Efx ports. Protected by the rtnl_lock */
extern struct list_head efx_port_list;

#endif /* EFX_DRIVERLINK_H */
