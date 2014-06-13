/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
 * This file provides struct efhw_nic and some related types.
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

#ifndef __CI_EFHW_EFAB_TYPES_H__
#define __CI_EFHW_EFAB_TYPES_H__

#include <ci/efhw/efhw_config.h>
#include <ci/efhw/hardware_sysdep.h>
#include <ci/efhw/iopage_types.h>
#include <ci/efhw/sysdep.h>

/*--------------------------------------------------------------------
 *
 * forward type declarations
 *
 *--------------------------------------------------------------------*/

struct efhw_nic;

/*--------------------------------------------------------------------
 *
 * Managed interface
 *
 *--------------------------------------------------------------------*/

enum efhw_q_type {
	EFHW_TXQ,
	EFHW_RXQ,
	EFHW_EVQ,
	EFHW_N_Q_TYPES
};


struct efhw_buffer_table_allocation{
	unsigned base;
	unsigned order;
};

struct eventq_resource_hardware {
	/*!iobuffer allocated for eventq - can be larger than eventq */
	struct efhw_iopages iobuff;
	struct efhw_buffer_table_allocation buf_tbl_alloc;
	int capacity;		/*!< capacity of event queue */
};

/*--------------------------------------------------------------------
 *
 * event queues and event driven callbacks
 *
 *--------------------------------------------------------------------*/

struct efhw_keventq {
	int lock;
	caddr_t evq_base;
	int32_t evq_ptr;
	uint32_t evq_mask;
	unsigned instance;
	struct eventq_resource_hardware hw;
	struct efhw_ev_handler *ev_handlers;
};


/**********************************************************************
 * Portable HW interface. ***************************************
 **********************************************************************/

/*--------------------------------------------------------------------
 *
 * EtherFabric Functional units - configuration and control
 *
 *--------------------------------------------------------------------*/

struct efhw_func_ops {

  /*-------------- Initialisation ------------ */

	/*! close down all hardware functional units - leaves NIC in a safe
	   state for driver unload */
	void (*close_hardware) (struct efhw_nic *nic);

	/*! initialise all hardware functional units */
	int (*init_hardware) (struct efhw_nic *nic,
			      struct efhw_ev_handler *,
			      const uint8_t *mac_addr, int non_irq_evq);

	/*! re-set necessary configuration after a reset */
	void (*post_reset) (struct efhw_nic *nic);

  /*-------------- Interrupt support  ------------ */

	/*! Set interrupt moderation strategy for the given IRQ unit
	 ** val is in usec
	 */
	void (*set_interrupt_moderation)(struct efhw_nic *nic, int evq,
					 uint val);

  /*-------------- Event support  ------------ */

	/*! Enable the given event queue
	   depending on the underlying implementation (EF1 or Falcon) then
	   either a q_base_addr in host memory, or a buffer base id should
	   be proivded
	 */
	void (*event_queue_enable) (struct efhw_nic *nic,
				    uint evq,	/* evnt queue index */
				    uint evq_size,	/* units of #entries */
				    uint buf_base_id,
				    int interrupting, 
				    int enable_dos_p);

	/*! Disable the given event queue (and any associated timer) */
	void (*event_queue_disable) (struct efhw_nic *nic, uint evq,
				     int timer_only);

	/*! request wakeup from the NIC on a given event Q */
	void (*wakeup_request) (struct efhw_nic *nic, int rd_ptr, int evq);

	/*! Push a SW event on a given eventQ */
	void (*sw_event) (struct efhw_nic *nic, int data, int evq);

  /*-------------- DMA support  ------------ */

	/*! Initialise NIC state for a given TX DMAQ */
	void (*dmaq_tx_q_init) (struct efhw_nic *nic,
				uint dmaq, uint evq, uint owner, uint tag,
				uint dmaq_size, uint buf_idx, uint flags);

	/*! Initialise NIC state for a given RX DMAQ */
	void (*dmaq_rx_q_init) (struct efhw_nic *nic,
				uint dmaq, uint evq, uint owner, uint tag,
				uint dmaq_size, uint buf_idx, uint flags);

	/*! Disable a given TX DMAQ */
	void (*dmaq_tx_q_disable) (struct efhw_nic *nic, uint dmaq);

	/*! Disable a given RX DMAQ */
	void (*dmaq_rx_q_disable) (struct efhw_nic *nic, uint dmaq);

	/*! Flush a given TX DMA channel */
	int (*flush_tx_dma_channel) (struct efhw_nic *nic, uint dmaq);

	/*! Flush a given RX DMA channel */
	int (*flush_rx_dma_channel) (struct efhw_nic *nic, uint dmaq);

  /*-------------- Buffer table Support ------------ */

	/*! Initialise a buffer table page */
	void (*buffer_table_set) (struct efhw_nic *nic,
				  dma_addr_t dma_addr,
				  uint region,
				  int own_id, int buffer_id);

	/*! Initialise a block of buffer table pages */
	void (*buffer_table_set_n) (struct efhw_nic *nic, int buffer_id,
				    dma_addr_t dma_addr, uint region,
				    int n_pages, int own_id);

	/*! Clear a block of buffer table pages */
	void (*buffer_table_clear) (struct efhw_nic *nic, int buffer_id,
				    int num);

	/*! Commit a buffer table update  */
	void (*buffer_table_commit) (struct efhw_nic *nic);
};


/*----------------------------------------------------------------------------
 *
 * NIC type
 *
 *---------------------------------------------------------------------------*/

struct efhw_device_type {
	int  arch;            /* enum efhw_arch */
	char variant;         /* 'A', 'B', ... */
	int  revision;        /* 0, 1, ... */
	int  in_fpga:1;
	int  in_cosim:1;
};


/*----------------------------------------------------------------------------
 *
 * EtherFabric NIC instance - nic.c for HW independent functions
 *
 *---------------------------------------------------------------------------*/

struct pci_dev;

/*! */
struct efhw_nic {
	/*! zero base index in efrm_nic_tablep->nic array */
	int index;
	int ifindex;		/*!< OS level nic index */
	struct pci_dev *pci_dev;	/*!< pci descriptor */

	struct efhw_device_type devtype;

	/*! Options that can be set by user. */
	unsigned options;
# define NIC_OPT_EFTEST             0x1	/* owner is an eftest app */
# define NIC_OPT_DEFAULT            0

	/*! Internal flags that indicate hardware properties at runtime. */
	unsigned flags;
# define NIC_FLAG_10G                   0x10
# define NIC_FLAG_ONLOAD_UNSUPPORTED    0x20

	unsigned resetting;	/*!< NIC is currently being reset */

	unsigned mtu;		/*!< MAC MTU (includes MAC hdr) */

	/* hardware resources */

	/*! Pointer to the control aperture bar. */
	volatile char __iomem *bar_ioaddr;
	/*! Bar number of control aperture. */
	unsigned               ctr_ap_bar;
	/*! Length of control aperture in bytes. */
	unsigned               ctr_ap_bytes;
	/*! DMA address of the control aperture. */
	dma_addr_t             ctr_ap_dma_addr;

	uint8_t mac_addr[ETH_ALEN];	/*!< mac address  */

	/*! EtherFabric Functional Units -- functions */
	const struct efhw_func_ops *efhw_func;

	/*! This lock protects a number of misc NIC resources.  It should
	 * only be used for things that can be at the bottom of the lock
	 * order.  ie. You mustn't attempt to grab any other lock while
	 * holding this one.
	 */
	spinlock_t *reg_lock;
	spinlock_t the_reg_lock;

	int buf_commit_outstanding;	/*!< outstanding buffer commits */

	struct efhw_keventq non_interrupting_evq;

	/*! Bit masks of the sizes of event queues and dma queues supported
	 * by this nic.
	 */
	unsigned q_sizes[EFHW_N_Q_TYPES];

	/* Number of event queues, DMA queues and timers. */
	unsigned num_evqs;
	unsigned num_dmaqs;
	unsigned num_timers;

	/* Nanoseconds for hardware timeout timer quantum */
	unsigned timer_quantum_ns;
};


#define EFHW_KVA(nic)       ((nic)->bar_ioaddr)

static inline int efhw_in_fpga(struct efhw_nic *nic) {
	return nic->devtype.in_fpga;
}

static inline int efhw_in_cosim(struct efhw_nic *nic) {
	return nic->devtype.in_cosim;
}

#endif /* __CI_EFHW_EFHW_TYPES_H__ */
