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
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2005-2010 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_DRIVERLINK_API_H
#define EFX_DRIVERLINK_API_H

#include <linux/list.h>
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_FASTCALL)
	#include <linux/version.h>
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
		#define EFX_USE_FASTCALL yes
		#include <linux/linkage.h>
	#endif
#endif

#include "filter.h"

/* Forward declarations */
struct pci_dev;
struct net_device;
struct sk_buff;
struct efx_dl_device;
struct efx_dl_device_info;

/* An extra safeguard in addition to symbol versioning */
#define EFX_DRIVERLINK_API_VERSION 7

/* enum efx_dl_ev_prio - Priority level that driverlink handles registe at */
enum efx_dl_ev_prio {
	EFX_DL_EV_HIGH = 0,
	EFX_DL_EV_MED,
	EFX_DL_EV_LOW,
};

/**
 * struct efx_dl_driver - An Efx driverlink device driver
 *
 * A driverlink client defines and initializes as many instances of
 * efx_dl_driver as required, registering each one with
 * efx_dl_register_driver().
 *
 * @name: Name of the driver
 * @probe: Called when device added
 *	The client should use the @def_info linked list and @silicon_rev
 *	to determine if they wish to attach to this device.
 *	Context: process, rtnl_lock or driverlink mutex held
 * @remove: Called when device removed
 *	The client must ensure the finish all operations with this
 *	device before returning from this method.
 *	Context: process, rtnl_lock or driverlink mutex held
 * @reset_suspend: Called before device is reset
 *	Called immediately before a hardware reset. The client must stop all
 *	hardware processing before returning from this method. Callbacks will
 *	be inactive when this method is called.
 *	Context: process, rtnl_lock and/or driverlink mutex held
 * @reset_resume: Called after device is reset
 *	Called after a hardware reset. If @ok is true, the client should
 *	state and resume normal operations. If @ok is false, the client should
 *	abandon use of the hardware resources. remove() will still be called.
 *	Context: process, rtnl_lock and/or driverlink mutex held
 * @handle_event: Called when an event on a single-function port may need to
 *	be handled by a client. May be %NULL. Currently only the first
 *	implementation in any driver registered for a device will be called.
 *	Context: NAPI.
 */
struct efx_dl_driver {
	const char *name;
	enum efx_dl_ev_prio priority;

	int (*probe) (struct efx_dl_device *efx_dl_dev,
		      const struct net_device *net_dev,
		      const struct efx_dl_device_info *dev_info,
		      const char *silicon_rev);
	void (*remove) (struct efx_dl_device *efx_dev);
	void (*reset_suspend) (struct efx_dl_device *efx_dev);
	void (*reset_resume) (struct efx_dl_device *efx_dev, int ok);
	bool (*handle_event) (struct efx_dl_device *efx_dev, void *p_event);

/* private: */
	struct list_head node;
	struct list_head device_list;
};

/**
 * enum efx_dl_device_info_type - Device information identifier.
 *
 * Used to identify each item in the &struct efx_dl_device_info linked list
 * provided to each driverlink client in the probe() @dev_info member.
 *
 * @EFX_DL_FALCON_RESOURCES: Information type is &struct efx_dl_falcon_resources
 * @EFX_DL_HASH_INSERTION: Information type is &struct efx_dl_hash_insertion
 * @EFX_DL_SIENA_SRIOV: Information type is &struct efx_dl_siena_sriov
 * @EFX_DL_AOE_RESOURCES: Information type is &struct efx_dl_aoe
 */
enum efx_dl_device_info_type {
	/** Falcon resources available for export */
	EFX_DL_FALCON_RESOURCES = 0,
	EFX_DL_HASH_INSERTION = 1,
	EFX_DL_SIENA_SRIOV = 2,
	EFX_DL_MCDI_RESOURCES = 3,
	EFX_DL_AOE_RESOURCES = 4,
};

/**
 * struct efx_dl_device_info - device information structure
 *
 * @next: Link to next structure, if any
 * @type: Type code for this structure
 */
struct efx_dl_device_info {
	struct efx_dl_device_info *next;
	enum efx_dl_device_info_type type;
};

/**
 * enum efx_dl_falcon_resource_flags - Falcon resource information flags.
 *
 * Flags that describe hardware variations for the current Falcon device.
 *
 * @EFX_DL_FALCON_DUAL_FUNC: Port is dual-function.
 *	Certain silicon revisions have two pci functions, and require
 *	certain hardware resources to be accessed via the secondary
 *	function
 * @EFX_DL_FALCON_USE_MSI: Port is initialised to use MSI/MSI-X interrupts.
 *	Falcon supports traditional legacy interrupts and MSI/MSI-X
 *	interrupts. The choice is made at run time by the sfc driver, and
 *	notified to the clients by this enumeration
 * @EFX_DL_FALCON_ONLOAD_UNSUPPORTED: OpenOnload unsupported on this port.
 * @EFX_DL_FALCON_HAVE_RSS_CHANNEL_COUNT: %rs_channel_count member is valid.
 * @EFX_DL_FALCON_HAVE_TIMER_QUANTUM_NS: %timer_quantum_ns member is valid.
 */
enum efx_dl_falcon_resource_flags {
	EFX_DL_FALCON_DUAL_FUNC = 0x1,
	EFX_DL_FALCON_USE_MSI = 0x2,
	EFX_DL_FALCON_ONLOAD_UNSUPPORTED = 0x4,
	EFX_DL_FALCON_WRITE_COMBINING = 0x8,
	EFX_DL_FALCON_HAVE_RSS_CHANNEL_COUNT = 0x10,
	EFX_DL_FALCON_HAVE_TIMER_QUANTUM_NS = 0x20,
};

/**
 * struct efx_dl_falcon_resources - Falcon resource information.
 *
 * This structure describes Falcon hardware resources available for
 * use by a driverlink driver.
 *
 * @hdr: Resource linked list header
 * @biu_lock: Register access lock.
 *	Some Falcon revisions require register access for configuration
 *	registers to be serialised between ports and PCI functions.
 *	The sfc driver will provide the appropriate lock semantics for
 *	the underlying hardware.
 * @buffer_table_min: First available buffer table entry
 * @buffer_table_lim: Last available buffer table entry + 1
 * @evq_timer_min: First available event queue with timer
 * @evq_timer_lim: Last available event queue with timer + 1
 * @evq_int_min: First available event queue with interrupt
 * @evq_int_lim: Last available event queue with interrupt + 1
 * @rxq_min: First available RX queue
 * @rxq_lim: Last available RX queue + 1
 * @txq_min: First available TX queue
 * @txq_lim: Last available TX queue + 1
 * @flags: Hardware variation flags
 * @rss_channel_count: Number of receive channels used for RSS. This member is
 *	only present if %EFX_DL_FALCON_HAVE_RSS_CHANNEL_COUNT is set.
 * @timer_quantum_ns: Timer quantum (nominal period between timer ticks)
 *	for wakeup timers, in nanoseconds. This member is only present if
 *	%EFX_DL_FALCON_HAVE_TIMER_QUANTUM_NS is set.
 */
struct efx_dl_falcon_resources {
	struct efx_dl_device_info hdr;
	spinlock_t *biu_lock;
	unsigned buffer_table_min;
	unsigned buffer_table_lim;
	unsigned evq_timer_min;
	unsigned evq_timer_lim;
	unsigned evq_int_min;
	unsigned evq_int_lim;
	unsigned rxq_min;
	unsigned rxq_lim;
	unsigned txq_min;
	unsigned txq_lim;
	enum efx_dl_falcon_resource_flags flags;
	unsigned rss_channel_count;
	unsigned timer_quantum_ns;
};

/**
 * enum efx_dl_hash_type_flags - Hash insertion type flags
 *
 * @EFX_DL_HASH_TOEP_TCPIP4: Toeplitz hash of TCP/IPv4 4-tuple
 * @EFX_DL_HASH_TOEP_IP4: Toeplitz hash of IPv4 addresses
 * @EFX_DL_HASH_TOEP_TCPIP6: Toeplitz hash of TCP/IPv6 4-tuple
 * @EFX_DL_HASH_TOEP_IP6: Toeplitz hash of IPv6 addresses
 */
enum efx_dl_hash_type_flags {
	EFX_DL_HASH_TOEP_TCPIP4 = 0x1,
	EFX_DL_HASH_TOEP_IP4 = 0x2,
	EFX_DL_HASH_TOEP_TCPIP6 = 0x4,
	EFX_DL_HASH_TOEP_IP6 = 0x8,
};

/**
 * struct efx_dl_hash_insertion - Hash insertion behaviour
 *
 * @hdr: Resource linked list header
 * @data_offset: Offset of packet data relative to start of buffer
 * @hash_offset: Offset of hash relative to start of buffer
 * @flags: Flags for hash type(s) enabled
 */
struct efx_dl_hash_insertion {
	struct efx_dl_device_info hdr;
	unsigned data_offset;
	unsigned hash_offset;
	enum efx_dl_hash_type_flags flags;
};

/**
 * struct efx_dl_siena_sriov - Siena SRIOV information
 *
 * This structure is initialised before pci_enable_sriov() is called,
 * which mail fail. Therefore the consumer should cope with the fact
 * that there may be fewer than %vf_count VFs.
 *
 * @hdr: Resource linked list header
 * @vi_base: The zeroth VI mapped into VFs
 * @vi_scale: Log2 of the number of VIs per VF
 * @vf_count: Number of VFs intended to be enabled
 */
struct efx_dl_siena_sriov {
	struct efx_dl_device_info hdr;
	unsigned vi_base;
	unsigned vi_scale;
	unsigned vf_count;
};

/**
 * struct efx_dl_aoe - AOE information
 *
 * @hdr: Resource linked list header
 */

struct efx_dl_aoe_resources {
	struct efx_dl_device_info hdr;
	unsigned internal_macs;
	unsigned external_macs;
};

/**
 * struct efx_dl_device - An Efx driverlink device.
 *
 * @pci_dev: PCI device used by the sfc driver.
 * @priv: Driver private data
 *	Driverlink clients can use this to store a pointer to their
 *	internal per-device data structure. Each (driver, device)
 *	tuple has a separate &struct efx_dl_device, so clients can use
 *	this @priv field independently.
 * @driver: Efx driverlink driver for this device
 */
struct efx_dl_device {
	struct pci_dev *pci_dev;
	void *priv;
	struct efx_dl_driver *driver;
};

/* Include API version number in symbol used for efx_dl_register_driver */
#define efx_dl_stringify_1(x, y) x ## y
#define efx_dl_stringify_2(x, y) efx_dl_stringify_1(x, y)
#define efx_dl_register_driver					\
	efx_dl_stringify_2(efx_dl_register_driver_api_ver_,	\
			   EFX_DRIVERLINK_API_VERSION)

/**
 * efx_dl_register_driver() - Register a client driver
 * @driver: Driver operations structure
 *
 * This acquires the rtnl_lock and therefore must be called from
 * process context.
 */
extern int efx_dl_register_driver(struct efx_dl_driver *driver);

/**
 * efx_dl_unregister_driver() - Unregister a client driver
 * @driver: Driver operations structure
 *
 * This acquires the rtnl_lock and therefore must be called from
 * process context.
 */
extern void efx_dl_unregister_driver(struct efx_dl_driver *driver);

/**
 * efx_dl_netdev_is_ours() - Check whether device is handled by sfc
 * @net_dev: Net device to be checked
 */
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_FASTCALL)
extern bool fastcall efx_dl_netdev_is_ours(const struct net_device *net_dev);
#else
extern bool efx_dl_netdev_is_ours(const struct net_device *net_dev);
#endif

/**
 * efx_dl_dev_from_netdev() - Find Driverlink device structure for net device
 * @net_dev: Net device to be checked
 * @driver: Driver structure for the device to be found
 *
 * Caller must hold the rtnl_lock.
 */
extern struct efx_dl_device *
efx_dl_dev_from_netdev(const struct net_device *net_dev,
		       struct efx_dl_driver *driver);

/* Schedule a reset without grabbing any locks */
extern void efx_dl_schedule_reset(struct efx_dl_device *efx_dev);

extern int efx_dl_filter_insert(struct efx_dl_device *efx_dev,
				struct efx_filter_spec *spec,
				bool replace_equal);
extern void efx_dl_filter_remove(struct efx_dl_device *efx_dev,
				 int filter_id);
extern void efx_dl_filter_redirect(struct efx_dl_device *efx_dev,
				   int filter_id, int rxq_i);

extern int efx_dl_mcdi_rpc(struct efx_dl_device *dl_dev, unsigned int cmd,
			   size_t inlen, size_t outlen, size_t *outlen_actual,
			   const u8 *inbuf, u8 *outbuf);

/**
 * efx_dl_for_each_device_info_matching - iterate an efx_dl_device_info list
 * @_dev_info: Pointer to first &struct efx_dl_device_info
 * @_type: Type code to look for
 * @_info_type: Structure type corresponding to type code
 * @_field: Name of &struct efx_dl_device_info field in the type
 * @_p: Iterator variable
 *
 * Example:
 *	struct efx_dl_falcon_resources *res;
 *	efx_dl_for_each_device_info_matching(dev_info, EFX_DL_FALCON_RESOURCES,
 *					     struct efx_dl_falcon_resources,
 *					     hdr, res) {
 *		if (res->flags & EFX_DL_FALCON_DUAL_FUNC)
 *			....
 *	}
 */
#define efx_dl_for_each_device_info_matching(_dev_info, _type,		\
					     _info_type, _field, _p)	\
	for ((_p) = container_of((_dev_info), _info_type, _field);	\
	     (_p) != NULL;						\
	     (_p) = container_of((_p)->_field.next, _info_type, _field))\
		if ((_p)->_field.type != _type)				\
			continue;					\
		else

/**
 * efx_dl_search_device_info - search an efx_dl_device_info list
 * @_dev_info: Pointer to first &struct efx_dl_device_info
 * @_type: Type code to look for
 * @_info_type: Structure type corresponding to type code
 * @_field: Name of &struct efx_dl_device_info member in this type
 * @_p: Result variable
 *
 * Example:
 *	struct efx_dl_falcon_resources *res;
 *	efx_dl_search_device_info(dev_info, EFX_DL_FALCON_RESOURCES,
 *				  struct efx_dl_falcon_resources, hdr, res);
 *	if (res)
 *		....
 */
#define efx_dl_search_device_info(_dev_info, _type, _info_type,		\
				  _field, _p)				\
	efx_dl_for_each_device_info_matching((_dev_info), (_type),	\
					     _info_type, _field, (_p))	\
		break;

#endif /* EFX_DRIVERLINK_API_H */
