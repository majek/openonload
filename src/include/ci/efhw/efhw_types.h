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
#include <ci/efhw/common.h>

/*--------------------------------------------------------------------
 *
 * forward type declarations
 *
 *--------------------------------------------------------------------*/

struct efhw_nic;

typedef uint32_t efhw_btb_handle;

/*--------------------------------------------------------------------
 *
 * Buffer table management
 *
 *--------------------------------------------------------------------*/
#define EFHW_BUFFER_TABLE_BLOCK_SIZE  32

/* Block of buffer table entries.
 * For some hardware types (Falcon) we pre-allocate a lot of such
 * structures for every NIC at load time, so we mut keep this structure as
 * small as possible.
 */
struct efhw_buffer_table_block {

	/* Support linked lists. */
	struct efhw_buffer_table_block *btb_next;

	/* Buffer table virtual address of the first entry. */
	uint64_t btb_vaddr;

	/* hw-specific data */
	union {
		/* handle for Huntington */
		struct {
			efhw_btb_handle handle;
		} ef10;

		/* owner for Falcon */
		struct {
			int owner;
		} falcon;
	} btb_hw;

	/* Bit masks of free entries.  Free entries are set to 1. */
#ifndef NDEBUG
	uint32_t btb_clear_mask;
#endif
	uint32_t btb_free_mask;
};

#define EFHW_BT_BLOCK_FREE_ALL ((uint32_t)(-1))
#define EFHW_BT_BLOCK_RANGE(first, n) \
	((n) == EFHW_BUFFER_TABLE_BLOCK_SIZE ? EFHW_BT_BLOCK_FREE_ALL : \
	 ((1 << (n)) - 1) << (first))

#define EFHW_NIC_PAGES_IN_OS_PAGE (PAGE_SIZE / EFHW_NIC_PAGE_SIZE)
#define EFHW_GFP_ORDER_TO_NIC_ORDER(gfp_order) \
	((gfp_order) + PAGE_SHIFT - EFHW_NIC_PAGE_SHIFT)

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


struct eventq_resource_hardware {
	/*!iobuffer allocated for eventq - can be larger than eventq */
	struct efhw_iopages iobuff;
	struct efhw_buffer_table_block *bt_block;
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
			      const uint8_t *mac_addr, int non_irq_evq,
			      int bt_min, int bt_lim);

	/*! re-set necessary configuration after a reset */
	void (*post_reset) (struct efhw_nic *nic);

  /*-------------- Event support  ------------ */

	/*! Enable the given event queue
	   depending on the underlying implementation (EF1 or Falcon) then
	   either a q_base_addr in host memory, or a buffer base id should
	   be proivded
	 */
	int (*event_queue_enable) (struct efhw_nic *nic,
				    uint evq,	/* evnt queue index */
				    uint evq_size,	/* units of #entries */
				    uint buf_base_id,
				    dma_addr_t* dma_addr,
				    uint n_pages,
				    int interrupting, 
				    int enable_dos_p,
				    int wakeup_evq,
				    int enable_time_sync_events,
				    int *rx_ts_correction_out,
				    int* flags_out);

	/*! Disable the given event queue (and any associated timer) */
	void (*event_queue_disable) (struct efhw_nic *nic, uint evq,
				     int time_sync_events_enabled);

	/*! request wakeup from the NIC on a given event Q */
	void (*wakeup_request) (struct efhw_nic *nic,
				volatile void __iomem* io_page, int rd_ptr);

	/*! Push a SW event on a given eventQ */
	void (*sw_event) (struct efhw_nic *nic, int data, int evq);

	/*! Handle an event from hardware, e.g. delivered via driverlink */
	int (*handle_event) (struct efhw_nic *nic, struct efhw_ev_handler *h, 
			     efhw_event_t *ev);

  /*-------------- DMA support  ------------ */

	/*! Initialise NIC state for a given TX DMAQ */
	int (*dmaq_tx_q_init) (struct efhw_nic *nic,
			       uint dmaq, uint evq, uint owner, uint tag,
			       uint dmaq_size, uint buf_idx,
			       dma_addr_t *dma_addrs, int n_dma_addrs,
			       uint stack_id, uint flags);

	/*! Initialise NIC state for a given RX DMAQ */
	int (*dmaq_rx_q_init) (struct efhw_nic *nic,
			       uint dmaq, uint evq, uint owner, uint tag,
			       uint dmaq_size, uint buf_idx,
			       dma_addr_t *dma_addrs, int n_dma_addrs,
			       uint stack_id, uint flags);

	/*! Disable a given TX DMAQ */
	void (*dmaq_tx_q_disable) (struct efhw_nic *nic, uint dmaq);

	/*! Disable a given RX DMAQ */
	void (*dmaq_rx_q_disable) (struct efhw_nic *nic, uint dmaq);

	/*! Flush a given TX DMA channel */
	int (*flush_tx_dma_channel) (struct efhw_nic *nic, uint dmaq);

	/*! Flush a given RX DMA channel */
	int (*flush_rx_dma_channel) (struct efhw_nic *nic, uint dmaq);

	/*! specify a pace value for a TX DMA Queue */
	int (*tx_q_pace)(struct efhw_nic *nic, uint dmaq, int pace);


  /*-------------- Buffer table Support ------------ */
	/*! Find all page orders available on this NIC.
	 * order uses EFHW_NIC_PAGE_SIZE as a base (i.e. EFHW_NIC_PAGE_SIZE
	 * has order 0).
	 * orders[] is array of size EFHW_NIC_PAGE_ORDERS_NUM.
	 * The real number of available orders is returned. */
	const int *buffer_table_orders;
	int buffer_table_orders_num;

	/*! Allocate buffer table block. */
	int (*buffer_table_alloc) (struct efhw_nic *nic, int owner, int order,
				   struct efhw_buffer_table_block **block_out);

	/* Re-allocate buffer table block after NIC reset.
	 * In case of failure, the block should be marked as invalid;
	 * caller must free it via buffer_table_free call. */
	int (*buffer_table_realloc) (struct efhw_nic *nic,
				     int owner, int order,
				     struct efhw_buffer_table_block *block);

	/*! Free buffer table block */
	void (*buffer_table_free) (struct efhw_nic *nic,
				   struct efhw_buffer_table_block *block);

	/*! Set/program buffer table page entries */
	void (*buffer_table_set) (struct efhw_nic *nic,
				  struct efhw_buffer_table_block *block,
				  int first_entry, int n_entries,
				  dma_addr_t* dma_addrs);

	/*! Clear a block of buffer table pages */
	void (*buffer_table_clear) (struct efhw_nic *nic,
				    struct efhw_buffer_table_block *block,
				    int first_entry, int n_entries);

  /*-------------- Sniff Support ------------ */
	/*! Enable or disable port sniff.
	 * If rss_context_handle is -1 instance is treated as a single RX
	 * queue.  If rss_context_handle is a valid rss context handle then
	 * instance is treated as a base queue and RSS is enabled.
	 */
	int (*set_port_sniff) (struct efhw_nic *nic, int instance, int enable,
			       int promiscuous, int rss_context_handle);

  /*-------------- RSS Support ------------ */
	/*! Allocate an RX RSS context */
	int (*rss_context_alloc) (struct efhw_nic *nic, int num_qs, int shared,
				  int *handle_out);

	/*! Free an RX RSS context */
	int (*rss_context_free) (struct efhw_nic *nic, int handle);

	/*! Set up an indirection table for an RSS context */
	int (*rss_context_set_table) (struct efhw_nic *nic, int handle,
				      const uint8_t *table);

	/*! Set up a key for an RSS context */
	int (*rss_context_set_key) (struct efhw_nic *nic, int handle,
				    const uint8_t *key);

  /*-------------- Licensing ------------------------ */
	int (* license_challenge) (struct efhw_nic *nic,
				   const uint32_t feature,
				   const uint8_t* challenge,
				   uint32_t* expiry,
				   uint8_t* signature);

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
# define NIC_FLAG_VLAN_FILTERS          0x40
# define NIC_FLAG_BUG35388_WORKAROUND   0x80
# define NIC_FLAG_MCAST_LOOP_HW         0x100
# define NIC_FLAG_14BYTE_PREFIX         0x200

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

	struct efhw_buffer_table_block *bt_free_block; /*!< falcon only */
	void *bt_blocks_memory;

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

	/* On Falcon, this is the prefix len chosen globally by the
	 * net driver.  On Torino, this is the prefix len if one was
	 * asked to be inserted during RXQ initialisation. */
	unsigned rx_prefix_len;

	/* Limit on size of rx buffer to use */
	unsigned rx_usr_buf_size;

	/* Base offset of queues used when dealing with absolute numbers, 
	 * e.g. wakeup events.  Can change when NIC is reset.
	 */
	unsigned vi_base;
	/* VI range to use, relative to vi_base, useful for validating
	 * wakeup event VI is in range
	 */
	unsigned vi_min;
	unsigned vi_lim;
};


#define EFHW_KVA(nic)       ((nic)->bar_ioaddr)

#endif /* __CI_EFHW_EFHW_TYPES_H__ */
