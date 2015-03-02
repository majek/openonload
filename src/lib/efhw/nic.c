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
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains EtherFabric Generic NIC instance (init, interrupts,
 * etc)
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
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

#include <ci/efhw/debug.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efhw/falcon.h>
#include <ci/efhw/ef10.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/eventq.h>

/* Return 0 if not a known type */
int efhw_device_type_init(struct efhw_device_type *dt,
			  int vendor_id, int device_id,
			  int class_revision)
{
	if (vendor_id != 0x1924)
		return 0;

	memset(dt, 0, sizeof(*dt));
	
	switch (device_id) {
	case 0x0703:
	case 0x6703:
		dt->arch = EFHW_ARCH_FALCON;
		dt->variant = 'A';
		switch (class_revision) {
		case 0:
			dt->revision = 0;
			break;
		case 1:
			dt->revision = 1;
			break;
		default:
			return 0;
		}
		break;
	case 0x0710:
		dt->arch = EFHW_ARCH_FALCON;
		dt->variant = 'B';
		switch (class_revision) {
		case 2:
			dt->revision = 0;
			break;
		default:
			return 0;
		}
		break;
	/* Development */
	case 0x0770:
		dt->arch = EFHW_ARCH_FALCON;
		dt->variant = 'C';
		break;
	case 0x7777:
		dt->arch = EFHW_ARCH_FALCON;
		dt->variant = 'C';
		switch (class_revision) {
		case 0:
			dt->revision = 0;
			break;
		default:
			return 0;
		}
		break;
	/* cosim */
	case 0x7778:
		dt->arch = EFHW_ARCH_FALCON;
		dt->variant = 'C';
		dt->revision = 0;
		if (class_revision > 0xf)
			return 0;
		break;
	case 0x0803:
        case 0x0813:
		dt->arch = EFHW_ARCH_FALCON;
		dt->variant = 'C';
		switch (class_revision) {
		case 0: /* ASIC */
			dt->revision = 0;
			break;

		case 1:
		case 2: /* 20/Oct/08 indicates DBI has been alt initialized */
                case 3: /* 30/Sep/08 indicates DBI has been initialized */
			dt->revision = 0;
			break;

		default:
			return 0;
		}
		break;
        case 0x1923:
        case 0x1903:
        case 0x0923:
        case 0x0903:
        case 0x0901:
		dt->function = device_id & 0x1000 ? EFHW_FUNCTION_VF :
			EFHW_FUNCTION_PF;
		dt->arch = EFHW_ARCH_EF10;
		dt->variant = 'A';
		dt->revision = class_revision;
		break;
	default:
		return 0;
	}

	return 1;
}


/*--------------------------------------------------------------------
 *
 * NIC Initialisation
 *
 *--------------------------------------------------------------------*/

/* make this separate from initialising data structure
** to allow this to be called at a later time once we can access PCI
** config space to find out what hardware we have
*/
void efhw_nic_init(struct efhw_nic *nic, unsigned flags, unsigned options,
		   struct efhw_device_type *dev_type, unsigned map_min,
		   unsigned map_max, unsigned vi_base, unsigned vport_id)
{
	nic->devtype = *dev_type;
	nic->flags = flags;
	nic->resetting = 0;
	nic->options = options;
	nic->bar_ioaddr = 0;
	spin_lock_init(&nic->the_reg_lock);
	nic->reg_lock = &nic->the_reg_lock;
	nic->mtu = 1500 + ETH_HLEN; /* ? + ETH_VLAN_HLEN */
	/* Default: this will get overwritten if better value is known */
	nic->timer_quantum_ns = 4968; 
	/* This will get set via driverlink for Falcon */
	nic->rx_prefix_len = 0;
	nic->vi_min = map_min;
	nic->vi_lim = map_max;

	switch (nic->devtype.arch) {
	case EFHW_ARCH_FALCON:
		/* 32768 is not supported by current approach to buftable
		 * allocation: 32768 entries = 256Kb = 2 buftable blocks */
		nic->q_sizes[EFHW_EVQ] = 512 | 1024 | 2048 | 4096 | 8192 |
			16384 /*| 32768*/;
		nic->q_sizes[EFHW_TXQ] = 512 | 1024 | 2048 | 4096;
		nic->q_sizes[EFHW_RXQ] = 512 | 1024 | 2048 | 4096;
		nic->efhw_func = &falcon_char_functional_units;
		switch (nic->devtype.variant) {
		case 'B':
			/* There are really 4096 queue-sets, but it's not
			 * worth trying to map more than 1024. */
			/* deliberate drop through */
		case 'C':
			nic->ctr_ap_bar = FALCON_P_CTR_AP_BAR;
			nic->num_evqs   = 1024;
			nic->num_dmaqs  = 1024;
			nic->num_timers = 1024;
			/* The BAR size is at least 16M.  But don't
			 * map Falcon's MSI-X tables as some versions
			 * of Linux do not allow them to be remapped.
			 */
			nic->ctr_ap_bytes = FR_BZ_RX_INDIRECTION_TBL_OFST + 
				FR_BZ_RX_INDIRECTION_TBL_STEP * 
				FR_BZ_RX_INDIRECTION_TBL_ROWS;
			break;
		default:
			EFHW_ASSERT(0);
			break;
		}
		break;
	case EFHW_ARCH_EF10:
		nic->q_sizes[EFHW_EVQ] = 512 | 1024 | 2048 | 4096 | 8192 |
			16384 | 32768;
		nic->q_sizes[EFHW_TXQ] = 512 | 1024 | 2048 | 4096;
		nic->q_sizes[EFHW_RXQ] = 512 | 1024 | 2048 | 4096;

		nic->ctr_ap_bar = dev_type->function == EFHW_FUNCTION_PF ?
			EF10_PF_P_CTR_AP_BAR : EF10_VF_P_CTR_AP_BAR;
		nic->num_evqs   = 1024;
		nic->num_dmaqs  = 1024;
		nic->num_timers = 1024;
		/* For EF10 we map VIs on demand.  We don't need mappings
		 * for any other reason as all control ops go via the net
		 * driver and MCDI.
		 */
		nic->ctr_ap_bytes = 0;
		nic->efhw_func = &ef10_char_functional_units;
		nic->vi_base = vi_base;
		nic->vport_id = vport_id;
		break;
	default:
		EFHW_ASSERT(0);
		break;
	}
}

void efhw_nic_dtor(struct efhw_nic *nic)
{
	EFHW_ASSERT(nic);

	/* Check that we have functional units because the software only
	 * driver doesn't initialise anything hardware related any more */

	/* destroy event queues */
	EFHW_TRACE("%s: event queues ... ", __FUNCTION__);

#ifndef __ci_ul_driver__
	if (nic->non_interrupting_evq.evq_mask)
		efhw_keventq_dtor(nic, &nic->non_interrupting_evq);


	/* close_hardware destroys buffer table manager on Falcon/Siena. */
	EFHW_TRACE("%s: functional units ... ", __FUNCTION__);

	if (efhw_nic_have_functional_units(nic)) {
		efhw_nic_close_hardware(nic);
	}
	EFHW_TRACE("%s: functional units ... done", __FUNCTION__);
#endif

	EFHW_TRACE("%s: event queues ... done", __FUNCTION__);

	spin_lock_destroy(&nic->the_reg_lock);

	EFHW_TRACE("%s: DONE", __FUNCTION__);
}
