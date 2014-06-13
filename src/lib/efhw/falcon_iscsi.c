/*
** Copyright 2005-2014  Solarflare Communications Inc.
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

  /**************************************************************************\
*//*! \file falcon_iscsi.c EtherFabric EFXXXX NIC  (iSCSI configuration)
   ** <L5_PRIVATE L5_SOURCE>
   ** \author  mjs
   **  \brief  Package - driver/efab     EtherFabric NIC driver
   **   \date  2006/05
   **    \cop  (c) Level 5 Networks Limited.
   ** </L5_PRIVATE>
   *//*
     \************************************************************************* */

/*! \cidoxg_driver_efab */

#include <ci/driver/efab/hardware.h>
#include <ci/driver/efab/hardware/falcon_iscsi.h>

/*----------------------------------------------------------------------------
 *
 * Reconfigure hardware for iSCSI digest offload
 *
 *---------------------------------------------------------------------------*/

void falcon_iscsi_update_tx_q_flags(efhw_nic_t * nic, uint dmaq, uint flags)
{
	FALCON_LOCK_DECL;
	uint64_t val1, val2;
	ulong offset = TX_DESC_PTR_TBL_OFST + (dmaq * FALCON_REGISTER128);
	ci_iohandle_t handle = EFAB_IOHANDLE(nic);
	efhw_ioaddr_t efhw_kva = EFHW_KVA(nic);

	/* Q attributes */
	int iscsi_hdig_en = ((flags & EFHW_VI_ISCSI_TX_HDIG_EN) != 0);
	int iscsi_ddig_en = ((flags & EFHW_VI_ISCSI_TX_DDIG_EN) != 0);

	DEBUGNIC(ci_log("%s: %x:%x:%x", __FUNCTION__,
			dmaq, iscsi_hdig_en, iscsi_ddig_en));

	FALCON_LOCK_LOCK(nic);
	if (!nic->resetting) {
		val1 = ci_get64(handle, efhw_kva + offset);
		val2 = ci_get64(handle, efhw_kva + offset + 8);

		val2 &= ~((1 << __DW3(TX_ISCSI_HDIG_EN_LBN)) |
			  (1 << __DW3(TX_ISCSI_DDIG_EN_LBN)));
		val2 |= ((iscsi_hdig_en << __DW3(TX_ISCSI_HDIG_EN_LBN)) |
			 (iscsi_ddig_en << __DW3(TX_ISCSI_DDIG_EN_LBN)));

		/* Falcon requires 128 bit atomic access for this register */
		falcon_write_qq(handle, efhw_kva + offset, val1, val2);
		ci_ul_iowb();
	}
	FALCON_LOCK_UNLOCK(nic);

	return;
}

EXPORT_SYMBOL(falcon_iscsi_update_tx_q_flags);

void falcon_iscsi_update_rx_q_flags(efhw_nic_t * nic, uint dmaq, uint flags)
{
	FALCON_LOCK_DECL;
	uint64_t val1, val2;
	ulong offset = RX_DESC_PTR_TBL_OFST + (dmaq * FALCON_REGISTER128);
	ci_iohandle_t handle = EFAB_IOHANDLE(nic);
	efhw_ioaddr_t efhw_kva = EFHW_KVA(nic);

	/* Q attributes */
	int iscsi_hdig_en = ((flags & EFAB_VI_ISCSI_RX_HDIG_EN) != 0);
	int iscsi_ddig_en = ((flags & EFAB_VI_ISCSI_RX_DDIG_EN) != 0);

	DEBUGNIC(ci_log("%s: %x:%x:%x", __FUNCTION__,
			dmaq, iscsi_hdig_en, iscsi_ddig_en));

	FALCON_LOCK_LOCK(nic);

	val1 = ci_get64(handle, efhw_kva + offset);
	val2 = ci_get64(handle, efhw_kva + offset + 8);

	val2 &= ~((1 << __DW3(RX_ISCSI_HDIG_EN_LBN)) |
		  (1 << __DW3(RX_ISCSI_DDIG_EN_LBN)));
	val2 |= ((iscsi_hdig_en << __DW3(RX_ISCSI_HDIG_EN_LBN)) |
		 (iscsi_ddig_en << __DW3(RX_ISCSI_DDIG_EN_LBN)));

	/* Falcon requires 128 bit atomic access for this register */
	falcon_write_qq(handle, efhw_kva + offset, val1, val2);
	ci_ul_iowb();

	FALCON_LOCK_UNLOCK(nic);

	return;
}

EXPORT_SYMBOL(falcon_iscsi_update_rx_q_flags);

/*! \cidoxg_end */
