/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
 * This file provides EtherFabric NIC hardware interface.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
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
#ifdef __CI_DRIVER_EFAB_HARDWARE_H__
# error This header should only be included directly in .c files
#endif
#define __CI_DRIVER_EFAB_HARDWARE_H__

#include <ci/efhw/hardware_sysdep.h>


/*----------------------------------------------------------------------------
 *
 * Common EtherFabric definitions
 *
 *---------------------------------------------------------------------------*/

#include <ci/efhw/debug.h>
#include <ci/efhw/common.h>
#include <ci/driver/efab/hardware/common.h>

/*----------------------------------------------------------------------------
 *
 * EtherFabric varients
 *
 *---------------------------------------------------------------------------*/

#ifdef USE_OLD_HWDEFS
#define FR_AA_TIMER_COMMAND_REG_KER_OFST       0x00000420
#define FR_BZ_TIMER_COMMAND_REGP0_OFST   0x00000420
#define FR_AB_TIMER_COMMAND_REGP123_OFST        0x01000420
#define FR_AA_TIMER_COMMAND_REGP0_OFST         0x00008420
#define FR_AA_TX_DESC_UPD_REG_KER_OFST         0x00000a10
#define FR_AB_TX_DESC_UPD_REGP123_OFST          0x01000a10
#define FR_AA_TX_DESC_UPD_REGP0_OFST           0x00008a10
#define FR_AA_RX_DESC_UPD_REG_KER_OFST         0x00000830
#define FR_AA_RX_DESC_UPD_REGP0_OFST           0x00008830
#define FR_AB_RX_DESC_UPD_REGP123_OFST          0x01000830
#else
#include "ci/driver/efab/hardware/host_common.h"
#include "ci/driver/efab/hardware/host_common_pci_defs.h"
#include "ci/driver/efab/hardware/host_common_mac.h"

#define FR_AA_TX_PACE_TBL_FIRST_QUEUE 4
#define FR_BZ_TX_PACE_TBL_FIRST_QUEUE 0

#define GEN_MODE_REG_KER 0xC90  /* here in B0 too, but not in headers? */
  #define DATAPATH_LOOPBACK_EN_SIENA_LBN 4
  #define DATAPATH_LOOPBACK_EN_SIENA_WIDTH 1

#define SIENA_USER_EV_DECODE 8
#define SIENA_EVENT_CODE_USER  ((uint64_t)SIENA_USER_EV_DECODE << EV_CODE_LBN)

#define SIENA_USER_EV_QID_LBN           32
#define SIENA_USER_EV_QID_WIDTH         10
#define SIENA_USER_EV_REG_VALUE_LBN     0
#define SIENA_USER_EV_REG_VALUE_WIDTH   32

#define SIENA_EVENT_USER_QID_MASK					\
  (__FALCON_OPEN_MASK(SIENA_USER_EV_QID_WIDTH) << SIENA_USER_EV_QID_LBN)
#define SIENA_EVENT_USER_EV_REG_VALUE_MASK		\
  (__FALCON_OPEN_MASK(SIENA_USER_EV_REG_VALUE_WIDTH) << \
   SIENA_USER_EV_REG_VALUE_LBN)

#define SIENA_EVENT_USER_Q_ID(evp)		    \
  (((evp)->u64 & SIENA_EVENT_USER_QID_MASK) >>	    \
   SIENA_USER_EV_QID_LBN)

#define SIENA_EVENT_USER_EV_REG_VALUE(evp)			\
  (((evp)->u64 &  SIENA_EVENT_USER_EV_REG_VALUE_MASK) >>	\
   SIENA_USER_EV_REG_VALUE_LBN)

/* Additional constants relevant to Siena only */

#define SIENA_RX_PKT_NOT_PARSED_CUTOFF 2560
#define SIENA_PORT1_MCPUIND_MAP_OFFSET 0x800000

#endif
#include <ci/driver/efab/hardware/falcon.h>

#ifndef __KERNEL__
#include <ci/driver/efab/hardware/falcon_ul.h>
#endif

/*----------------------------------------------------------------------------
 *
 * EtherFabric Portable Hardware Layer defines
 *
 *---------------------------------------------------------------------------*/

  /*-------------- Initialisation ------------ */
#define efhw_nic_close_hardware(nic) \
	((nic)->efhw_func->close_hardware(nic))

#define efhw_nic_init_hardware(nic, ev_handlers, mac_addr, non_irq_evq) \
	((nic)->efhw_func->init_hardware((nic), (ev_handlers), (mac_addr), \
					 (non_irq_evq)))
#define efhw_nic_post_reset(nic) \
	((nic)->efhw_func->post_reset((nic)))
/*-------------- Interrupt support  ------------ */

#define efhw_nic_set_interrupt_moderation(nic, evq, val)                 \
	((nic)->efhw_func->set_interrupt_moderation(nic, evq, val))

/*-------------- Event support  ------------ */

#define efhw_nic_event_queue_enable(nic, evq, size, buf_base, interrupting, dos_p) \
	((nic)->efhw_func->event_queue_enable((nic), (evq), (size),     \
					      (buf_base), (interrupting), (dos_p)))

#define efhw_nic_event_queue_disable(nic, evq, timer_only) \
	((nic)->efhw_func->event_queue_disable(nic, evq, timer_only))

#define efhw_nic_wakeup_request(nic, rd_ptr, evq)                       \
	((nic)->efhw_func->wakeup_request((nic), (rd_ptr), (evq)))

#define efhw_nic_sw_event(nic, data, ev) \
	((nic)->efhw_func->sw_event(nic, data, ev))

/*-------------- DMA support  ------------ */
#define efhw_nic_dmaq_tx_q_init(nic, dmaq, evq, owner, tag,		\
				dmaq_size, index, flags)		\
	((nic)->efhw_func->dmaq_tx_q_init(nic, dmaq, evq, owner, tag,	\
					  dmaq_size, index, flags))

#define efhw_nic_dmaq_rx_q_init(nic, dmaq, evq, owner, tag,		\
				dmaq_size, index, flags) \
	((nic)->efhw_func->dmaq_rx_q_init(nic, dmaq, evq, owner, tag,	\
					  dmaq_size, index, flags))

#define efhw_nic_dmaq_tx_q_disable(nic, dmaq) \
	((nic)->efhw_func->dmaq_tx_q_disable(nic, dmaq))

#define efhw_nic_dmaq_rx_q_disable(nic, dmaq) \
	((nic)->efhw_func->dmaq_rx_q_disable(nic, dmaq))

#define efhw_nic_flush_tx_dma_channel(nic, dmaq) \
	((nic)->efhw_func->flush_tx_dma_channel(nic, dmaq))

#define efhw_nic_flush_rx_dma_channel(nic, dmaq) \
	((nic)->efhw_func->flush_rx_dma_channel(nic, dmaq))

/*-------------- MAC Low level interface ---- */
#define efhw_gmac_get_mac_addr(nic) \
	((nic)->gmac->get_mac_addr((nic)->gmac))

/*-------------- Buffer table -------------- */
#define efhw_nic_buffer_table_set(nic, addr, region, own_id, buf_id)    \
	((nic)->efhw_func->buffer_table_set(nic, addr, region, own_id, buf_id))

#define efhw_nic_buffer_table_set_n(nic, buf_id, addr,                  \
				    region, n_pages, own_id)            \
	((nic)->efhw_func->buffer_table_set_n(nic, buf_id, addr,	\
					      region, n_pages, own_id))

#define efhw_nic_buffer_table_clear(nic, id, num) \
	((nic)->efhw_func->buffer_table_clear(nic, id, num))

#define efhw_nic_buffer_table_commit(nic) \
	((nic)->efhw_func->buffer_table_commit(nic))


/*----------------------------------------------------------------------------
 * Hardware specific portability macros for performance critical code.
 *
 * Warning: and driver code which is using these defines is not
 * capable of supporting multiple NIC varients and should be built and
 * marked appropriately
 *
 *---------------------------------------------------------------------------*/

/* --- Buffers --- */
#define EFHW_BUFFER_ADDR		FALCON_BUFFER_4K_ADDR
#define EFHW_BUFFER_PAGE		FALCON_BUFFER_4K_PAGE
#define EFHW_BUFFER_OFF			FALCON_BUFFER_4K_OFF

#if PAGE_SIZE <= EFHW_MAX_PAGE_SIZE
#define EFHW_NIC_PAGE_SIZE PAGE_SIZE
#else
#define EFHW_NIC_PAGE_SIZE EFHW_MAX_PAGE_SIZE
#endif
#define EFHW_NIC_PAGE_MASK (~(EFHW_NIC_PAGE_SIZE-1))
