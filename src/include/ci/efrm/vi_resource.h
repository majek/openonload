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
 * This file contains public API for VI resource.
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

#ifndef __CI_EFRM_VI_RESOURCE_H__
#define __CI_EFRM_VI_RESOURCE_H__

#include <ci/efhw/efhw_types.h>
#include <ci/efrm/resource.h>
#include <ci/efrm/debug.h>


struct efrm_vi;
struct efrm_vi_set;
struct efrm_vf;
struct efrm_pd;
struct efrm_client;


struct efrm_vi_attr {
	/* Please try to avoid changing the size of this.  We've like to
	 * preserve binary compatibility as far as possible.
	 */
	void* opaque[8];
};


struct efrm_vi_info {
	/** The base of the I/O aperture (4K) containing doorbells. */
	dma_addr_t  vi_window_base;
	/** The instance number of this VI. */
	int         vi_instance;
	/** Size of host memory mapping. */
	int         vi_mem_mmap_bytes;
};


struct efrm_vi_q_size {
	/** The number of "entries" in the queue. */
	int  q_len_entries;
	/** The size of the queue in bytes. */
	int  q_len_bytes;
	/** log2 of the number of 4K pages required. */
	int  q_len_page_order;
	/** Bitmask of the queue sizes supported. */
	int  q_sizes_supported;
};


enum efrm_vi_q_flags {
	/** RXQ, TXQ: Select physical addressing mode. */
	EFRM_VI_PHYS_ADDR             = 0x1,
	/** TXQ: Enable IP checksum offload. */
	EFRM_VI_IP_CSUM               = 0x2,
	/** TXQ: Enable TCP/UDP checksum offload. */
	EFRM_VI_TCP_UDP_CSUM          = 0x4,
	/** TXQ: Enable iSCSI header digest offload. */
	EFRM_VI_ISCSI_HEADER_DIGEST   = 0x8,
	/** TXQ: Enable iSCSI data digest offload. */
	EFRM_VI_ISCSI_DATA_DIGEST     = 0x10,
	/** TXQ: Outgoing packets must match an Ethernet filter. */
	EFRM_VI_ETH_FILTER            = 0x20,
	/** TXQ: Outgoing packets must match a TCP/UDP filter. */
	EFRM_VI_TCP_UDP_FILTER        = 0x40,
	/** RXQ: Contiguous buffer mode.  Only works with EFRM_VI_PHYS_ADDR. */
	EFRM_VI_CONTIGUOUS            = 0x80,
};


/** Initialise an efrm_vi_attr object to default values. */
#define efrm_vi_attr_init(attr)					\
      __efrm_vi_attr_init(NULL, (attr), sizeof(struct efrm_vi_attr))
extern int __efrm_vi_attr_init(struct efrm_client *client_obsolete,
			       struct efrm_vi_attr *attr, int attr_size);

/** Set the protection domain for a VI. */
extern void efrm_vi_attr_set_pd(struct efrm_vi_attr *attr,
				struct efrm_pd *pd);

/** Allocate a VI that has an associated interrupt. */
extern void efrm_vi_attr_set_with_interrupt(struct efrm_vi_attr *attr,
					    int with_interrupt);

/** Allocate a VI that has an associated timer. */
extern void efrm_vi_attr_set_with_timer(struct efrm_vi_attr *attr,
					int with_timer);

/** Allocate VI from a VI set.  Returns -EINVAL if instance is not in
 * range.
 */
extern int efrm_vi_attr_set_instance(struct efrm_vi_attr *attr,
				      struct efrm_vi_set *,
				      int instance_in_set);

/** Allocate VI from a VF. */
extern int efrm_vi_attr_set_vf(struct efrm_vi_attr *, struct efrm_vf *);

/** The interrupt associated with the VI should be on (or close to) the
 * given core.
 */
extern int efrm_vi_attr_set_interrupt_core(struct efrm_vi_attr *, int core);

/** The VI should use the given net-driver channel for wakeups. */
extern int efrm_vi_attr_set_wakeup_channel(struct efrm_vi_attr *,
					   int channel_id);


/**
 * Allocate a VI resource instance.
 *
 * [client] is obsolete and only remains for backwards compatibility.  You
 * should instead provide a vi_set or pd via the attributes, and set client
 * to NULL.
 *
 * [attr] may be NULL only if client is not NULL.
 */
extern int  efrm_vi_alloc(struct efrm_client *client,
			  const struct efrm_vi_attr *attr,
			  struct efrm_vi **p_virs_out);

/**
 * Returns various attributes of a VI.
 *
 * See definition of [efrm_vi_info] for more details.
 */
extern void efrm_vi_get_info(struct efrm_vi *virs,
			     struct efrm_vi_info *info_out);


#define EFRM_VI_Q_GET_SIZE_CURRENT  -123

/**
 * Returns information about the size of a DMA or event queue.
 *
 * If [n_q_entries == EFRM_VI_Q_GET_SIZE_CURRENT]: If the queue is already
 * initialised, then return the size of the existing queue.  Else return
 * -EINVAL.
 *
 * If [n_q_entries > 0]: Return the size of a queue that has the given
 * number of entries.  If [n_q_entries] is not a supported queue size, then
 * it is rounded up to the nearest supported size.  If [n_q_entries] is
 * larger than the max supported size, return -EINVAL.
 *
 * [q_size_out->q_sizes_supported] is always initialised, even if an error
 * code is returned.
 */
extern int  efrm_vi_q_get_size(struct efrm_vi *virs, enum efhw_q_type q_type,
			       int n_q_entries,
			       struct efrm_vi_q_size *q_size_out);

/**
 * Initialise a VI dma/event queue.
 *
 * [n_q_entries] must be a supported size for this NIC and [q_type], else
 * -EINVAL is returned.  Use efrm_vi_q_get_size() to choose an appropriate
 * size.
 *
 * [dma_addrs] gives the DMA address of each of the pages backing the
 * queue.
 *
 * [q_tag] is only used for RXQs and TXQs, and specifies the tag reflected
 * in completion events.
 *
 * [q_flags] takes values from [efrm_vi_q_flags].
 *
 * [evq] identifies the event queue to be used for a DMA queue.  If NULL
 * then [virs] is used.  Ignored when [q_type == EFHW_EVQ].
 */
extern int efrm_vi_q_init(struct efrm_vi *virs, enum efhw_q_type q_type,
			  int n_q_entries,
			  const dma_addr_t *dma_addrs, int dma_addrs_n,
			  int q_tag, unsigned q_flags,
			  struct efrm_vi *evq);

/**
 * Allocate a VI dma/event queue.
 *
 * This function does everything that efrm_vi_q_init() does, but also
 * allocates and dma-maps memory for the ring.
 */
extern int efrm_vi_q_alloc(struct efrm_vi *virs, enum efhw_q_type q_type,
			   int n_q_entries, int q_tag_in, unsigned vi_flags,
			   struct efrm_vi *evq);



struct pci_dev;
extern struct pci_dev *efrm_vi_get_pci_dev(struct efrm_vi *);

extern struct efrm_vf *efrm_vi_get_vf(struct efrm_vi *);


/* Make these inline instead of macros for type checking */
static inline struct efrm_vi *
efrm_to_vi_resource(struct efrm_resource *rs)
{
	EFRM_ASSERT(rs->rs_type == EFRM_RESOURCE_VI);
	return (struct efrm_vi *) rs;
}
static inline struct
efrm_resource *efrm_from_vi_resource(struct efrm_vi *rs)
{
	return (struct efrm_resource *)rs;
}

#define EFAB_VI_RESOURCE_INSTANCE(virs) \
    (efrm_from_vi_resource(virs)->rs_instance)

#define EFAB_VI_RESOURCE_PRI_ARG(virs) \
    (efrm_from_vi_resource(virs)->rs_instance)

extern int
efrm_vi_resource_alloc(struct efrm_client *client,
		       struct efrm_vi *evq_virs,
		       struct efrm_vi_set *vi_set, int vi_set_instance,
		       struct efrm_vf *vf, const char *name,
		       unsigned vi_flags,
		       int evq_capacity, int txq_capacity, int rxq_capacity,
		       int tx_q_tag, int rx_q_tag, int wakeup_cpu_core,
		       int wakeup_channel,
		       struct efrm_vi **virs_in_out,
		       uint32_t *out_io_mmap_bytes,
		       uint32_t *out_mem_mmap_bytes,
		       uint32_t *out_txq_capacity,
		       uint32_t *out_rxq_capacity);

extern void efrm_vi_resource_release(struct efrm_vi *);
extern void efrm_vi_resource_release_callback(struct efrm_vi *virs);

/* Return the protection domain associated with this VI.  This function
 * returns a borrowed reference which lives as long as the VI.
 */
extern struct efrm_pd *efrm_vi_get_pd(struct efrm_vi *);


/*--------------------------------------------------------------------
 *
 * eventq handling
 *
 *--------------------------------------------------------------------*/

/*! Reset an event queue and clear any associated timers */
extern void efrm_eventq_reset(struct efrm_vi *virs);

/*! Register a kernel-level handler for the event queue.  This function is
 * called whenever a timer expires, or whenever the event queue is woken
 * but no thread is blocked on it.
 *
 * This function returns -EBUSY if a callback is already installed.
 *
 * \param rs      Event-queue resource
 * \param handler Callback-handler
 * \param arg     Argument to pass to callback-handler
 * \return        Status code
 */
extern int
efrm_eventq_register_callback(struct efrm_vi *rs,
			      void (*handler)(void *arg, int is_timeout,
					      struct efhw_nic *nic),
			      void *arg);

/*! Kill the kernel-level callback.
 *
 * This function stops the timer from running and unregisters the callback
 * function.  It waits for any running timeout handlers to complete before
 * returning.
 *
 * \param rs      Event-queue resource
 * \return        Nothing
 */
extern void efrm_eventq_kill_callback(struct efrm_vi *rs);

/*! Ask the NIC to generate a wakeup when an event is next delivered. */
extern void efrm_eventq_request_wakeup(struct efrm_vi *rs,
				       unsigned current_ptr);

/*! Set interrupt moderation.  Only works for VI-in-VF.  Returns 0 on
 *  success, or -EINVAL if VI is not in a VF.
 */
extern int efrm_vi_irq_moderate(struct efrm_vi *, int usec);

/*! Set interrupt affinity.  Only works for VI-in-VF.  Returns 0 on
 *  success, or -EINVAL if VI is not in a VF.
 */
extern int efrm_vi_irq_affinity(struct efrm_vi *, int cpu_core_id);

/*! Register a kernel-level handler for flush completions.
 * \TODO Currently, it is unsafe to install a callback more than once.
 *
 * \param rs      VI resource being flushed.
 * \param handler Callback handler function.
 * \param arg     Argument to be passed to handler.
 */
extern void
efrm_vi_register_flush_callback(struct efrm_vi *rs,
				void (*handler)(void *),
				void *arg);

/*! Comment? */
extern void efrm_pt_flush(struct efrm_vi *);

/*! If there are flushes outstanding on this NIC wait until they have
 * completed
 */
extern void efrm_vi_wait_nic_complete_flushes(struct efhw_nic *nic);

/*!
 * Iterate the lists of pending flushes and complete any that are more
 * than 1 second old 
 */
extern void efrm_vi_check_flushes(struct work_struct *data);

/*!
 * Timer to call efrm_vi_check_flushes periodically
 */
extern void efrm_vi_flush_timer_fn(unsigned long l);

/*! Comment? */
extern int efrm_pt_pace(struct efrm_vi*, int val);

/*! Set [n_entries] to -1 to get size of existing EVQ. */
extern uint32_t efrm_vi_rm_evq_bytes(struct efrm_vi *virs, int n_entries);


/* Fill [out_vi_data] with information required to allow a VI to be init'd.
 * [out_vi_data] must ref at least VI_MAPPINGS_SIZE bytes.
 */
extern void efrm_vi_resource_mappings(struct efrm_vi *, void *out_vi_data);

/*! Find page offset for timer register */
extern int efrm_vi_timer_page_offset(struct efrm_vi* vi);

#endif /* __CI_EFRM_VI_RESOURCE_H__ */
