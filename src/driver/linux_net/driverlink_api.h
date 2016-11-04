/*
** Copyright 2005-2016  Solarflare Communications Inc.
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
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2005-2015 Solarflare Communications Inc.
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

/* Driverlink API source compatibility version.  This is incremented
 * whenever a definition is added, removed or changed such that a
 * client might need to guard its use with a compile-time check.  It
 * is not used for binary compatibility checking, as that is done by
 * kbuild and the module loader using symbol versions.
 */
#define EFX_DRIVERLINK_API_VERSION 22
#define EFX_DRIVERLINK_API_VERSION_MINOR_MAX 4

#ifndef EFX_DRIVERLINK_API_VERSION_MINOR
#define EFX_DRIVERLINK_API_VERSION_MINOR 0
#endif

/**
 * enum efx_dl_ev_prio - Driverlink client's priority level for event handling
 * @EFX_DL_EV_HIGH: Client driver wants to handle events first
 * @EFX_DL_EV_MED: Client driver is not particular about priority
 * @EFX_DL_EV_LOW: Client driver wants to handle events last
 */
enum efx_dl_ev_prio {
	EFX_DL_EV_HIGH = 0,
	EFX_DL_EV_MED,
	EFX_DL_EV_LOW,
};

/**
 * enum efx_dl_driver_flags - flags for Driverlink client driver behaviour
 * @EFX_DL_DRIVER_CHECKS_FALCON_RX_USR_BUF_SIZE: Set by drivers that
 *	promise to use the RX buffer size programmed by the net driver
 *	on Falcon and Siena.  Defined from API version 8.
 * @EFX_DL_DRIVER_REQUIRES_MINOR_VER: Set by client drivers to indicate the
 *      minor_ver entry us present in their struct. Defined from API 22.1.
 * @EFX_DL_DRIVER_SUPPORTS_MINOR_VER: Set by the server driver to
 *      indicate the minor version supplied by the client is supported.
 */
enum efx_dl_driver_flags {
	EFX_DL_DRIVER_CHECKS_FALCON_RX_USR_BUF_SIZE = 0x1,
	EFX_DL_DRIVER_REQUIRES_MINOR_VER = 0x2,
	EFX_DL_DRIVER_SUPPORTS_MINOR_VER = 0x4,
};

/**
 * struct efx_dl_driver - Driverlink client device driver
 *
 * A driverlink client defines and initializes as many instances of
 * efx_dl_driver as required, registering each one with
 * efx_dl_register_driver().
 *
 * @name: Name of the driver
 * @priority: Priority of this driver in event handling
 * @flags: Flags describing driver behaviour.  Defined from API version 8.
 * @probe: Called when device added
 *	The client should use the @dev_info linked list to determine
 *	if they wish to attach to this device.  (@silicon_rev is a
 *	dummy parameter.)
 *	Context: process, rtnl_lock held
 * @remove: Called when device removed
 *	The client must ensure the finish all operations with this
 *	device before returning from this method.
 *	Context: process, rtnl_lock held
 * @reset_suspend: Called before device is reset
 *	Called immediately before a hardware reset. The client must stop all
 *	hardware processing before returning from this method. Callbacks will
 *	be inactive when this method is called.
 *	Context: process, rtnl_lock held
 * @reset_resume: Called after device is reset
 *	Called after a hardware reset. If @ok is true, the client should
 *	state and resume normal operations. If @ok is false, the client should
 *	abandon use of the hardware resources. remove() will still be called.
 *	Context: process, rtnl_lock held
 * @handle_event: Called when an event on a single-function port may
 *	need to be handled by a client.  May be %NULL if the client
 *	driver does not handle events.  Returns %true if the event is
 *	recognised and handled, else %false.  If multiple clients
 *	registered for a device implement this operation, they will be
 *	called in priority order from high to low, until one returns
 *	%true.  Context: NAPI.
 * @rx_packet: Called when processing an RX packet, after prefetching the data
 *      but before forming the skb.  Returns %true if the client wants the
 *      packet to be discarded, else %false.
 *      Context: NAPI.
 *
 * Prior to API version 7, only one driver with non-null @handle_event
 * could be registered for each device.  The @priority field was not
 * defined and the return type of @handle_event was void.
 */
struct efx_dl_driver {
/* public: */
	const char *name;
	enum efx_dl_ev_prio priority;
	enum efx_dl_driver_flags flags;

	int (*probe) (struct efx_dl_device *efx_dl_dev,
		      const struct net_device *net_dev,
		      const struct efx_dl_device_info *dev_info,
		      const char *silicon_rev);
	void (*remove) (struct efx_dl_device *efx_dev);
	void (*reset_suspend) (struct efx_dl_device *efx_dev);
	void (*reset_resume) (struct efx_dl_device *efx_dev, int ok);
	int (*handle_event) (struct efx_dl_device *efx_dev,
			     void *p_event, int budget);
	bool (*rx_packet) (struct efx_dl_device *efx_dev, int channel,
			   u8 *pkt_hdr, int len);

/* private: */
	struct list_head node;
	struct list_head device_list;

/* public: */
	unsigned int minor_ver;
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
 * @EFX_DL_AOE_RESOURCES: Information type is &struct efx_dl_aoe_resources.
 *	Defined from API version 6.
 * @EFX_DL_EF10_RESOURCES: Information type is &struct efx_dl_ef10_resources.
 *	Defined from API version 9.
 */
enum efx_dl_device_info_type {
	EFX_DL_FALCON_RESOURCES = 0,
	EFX_DL_HASH_INSERTION = 1,
	EFX_DL_SIENA_SRIOV = 2,
	EFX_DL_MCDI_RESOURCES = 3,
	EFX_DL_AOE_RESOURCES = 4,
	EFX_DL_EF10_RESOURCES = 5,
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
 * enum efx_dl_falcon_resource_flags - Falcon/Siena resource information flags.
 *
 * Flags that describe hardware variations for the current Falcon or
 * Siena device.
 *
 * @EFX_DL_FALCON_DUAL_FUNC: Port is dual-function. (obsolete)
 * @EFX_DL_FALCON_USE_MSI: Port is initialised to use MSI/MSI-X interrupts.
 *	Falcon supports traditional legacy interrupts and MSI/MSI-X
 *	interrupts. The choice is made at run time by the sfc driver, and
 *	notified to the clients by this enumeration
 * @EFX_DL_FALCON_ONLOAD_UNSUPPORTED: OpenOnload unsupported on this port.
 * @EFX_DL_FALCON_HAVE_RSS_CHANNEL_COUNT: %rss_channel_count member is valid.
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
 * struct efx_dl_falcon_resources - Falcon/Siena resource information.
 *
 * This structure describes Falcon or Siena hardware resources available for
 * use by a driverlink driver.
 *
 * @hdr: Resource linked list header
 * @biu_lock: Register access lock. Access to configuration registers on
 *	the underlying PCI function must be serialised using this spinlock.
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
 * @rx_usr_buf_size: RX buffer size for user-mode queues and kernel-mode
 *	queues with scatter enabled, in bytes.  Defined from API version 8.
 * @rx_channel_count: Number of receive channels available for use.
 */
struct efx_dl_falcon_resources {
	struct efx_dl_device_info hdr;
	spinlock_t *biu_lock;
	unsigned int buffer_table_min;
	unsigned int buffer_table_lim;
	unsigned int evq_timer_min;
	unsigned int evq_timer_lim;
	unsigned int evq_int_min;
	unsigned int evq_int_lim;
	unsigned int rxq_min;
	unsigned int rxq_lim;
	unsigned int txq_min;
	unsigned int txq_lim;
	enum efx_dl_falcon_resource_flags flags;
	unsigned int rss_channel_count;
	unsigned int timer_quantum_ns;
	unsigned int rx_usr_buf_size;
#if EFX_DRIVERLINK_API_VERSION > 22 || (EFX_DRIVERLINK_API_VERSION == 22 && EFX_DRIVERLINK_API_VERSION_MINOR > 1)
	unsigned int rx_channel_count;
#endif
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
	unsigned int data_offset;
	unsigned int hash_offset;
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
	unsigned int vi_base;
	unsigned int vi_scale;
	unsigned int vf_count;
};

/**
 * struct efx_dl_aoe - Information about an AOE attached to the NIC
 *
 * @hdr: Resource linked list header
 * @internal_macs: Number of internal MACs (connected to the NIC)
 * @external_macs: Number of external MACs
 *
 * Defined from API version 6.
 */
struct efx_dl_aoe_resources {
	struct efx_dl_device_info hdr;
	unsigned internal_macs;
	unsigned int external_macs;
};

/**
 * enum efx_dl_ef10_resource_flags - EF10 resource information flags.
 *
 * Flags that describe hardware variations for the current EF10 or
 * Siena device.
 *
 * @EFX_DL_EF10_USE_MSI: Port is initialised to use MSI/MSI-X interrupts.
 *      EF10 supports traditional legacy interrupts and MSI/MSI-X
 *      interrupts. The choice is made at run time by the sfc driver, and
 *      notified to the clients by this enumeration
 */
enum efx_dl_ef10_resource_flags {
	EFX_DL_EF10_USE_MSI = 0x2,
};

/**
 * struct efx_dl_ef10_resources - EF10 resource information
 *
 * @hdr: Resource linked list header
 * @vi_base: Absolute index of first VI in this function.  This may change
 *	after a reset.  Clients that cache this value will need to update
 *	the cached value in their reset_resume() function.
 * @vi_min: Relative index of first available VI
 * @vi_lim: Relative index of last available VI + 1
 * @timer_quantum_ns: Timer quantum (nominal period between timer ticks)
 *      for wakeup timers, in nanoseconds.
 * @rss_channel_count: Number of receive channels used for RSS.
 * @rx_channel_count: Number of receive channels available for use.
 * @vi_shift: Shift value for absolute VI number computation.
 */
struct efx_dl_ef10_resources {
	struct efx_dl_device_info hdr;
	unsigned int vi_base;
	unsigned int vi_min;
	unsigned int vi_lim;
	unsigned int timer_quantum_ns;
	unsigned int rss_channel_count;
	enum efx_dl_ef10_resource_flags flags;
	unsigned int vport_id;
#if EFX_DRIVERLINK_API_VERSION > 22 || (EFX_DRIVERLINK_API_VERSION == 22 && EFX_DRIVERLINK_API_VERSION_MINOR > 0)
	unsigned int rx_channel_count;
#endif
#if EFX_DRIVERLINK_API_VERSION > 22 || (EFX_DRIVERLINK_API_VERSION == 22 && EFX_DRIVERLINK_API_VERSION_MINOR > 2)
	unsigned int vi_shift;
#endif
};

/**
 * struct efx_dl_device - An Efx driverlink device.
 *
 * @pci_dev: Underlying PCI function
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

/**
 * efx_dl_unregister_driver() - Unregister a client driver
 * @driver: Driver operations structure
 *
 * This acquires the rtnl_lock and therefore must be called from
 * process context.
 */
void efx_dl_unregister_driver(struct efx_dl_driver *driver);

/* Include API version number in symbol used for efx_dl_register_driver */
#define efx_dl_stringify_1(x, y) x ## y
#define efx_dl_stringify_2(x, y) efx_dl_stringify_1(x, y)
#define __efx_dl_register_driver				\
	efx_dl_stringify_2(efx_dl_register_driver_api_ver_,	\
			   EFX_DRIVERLINK_API_VERSION)

/**
 * efx_dl_register_driver() - Register a client driver
 * @driver: Driver operations structure
 *
 * This acquires the rtnl_lock and therefore must be called from
 * process context.
 */
int __efx_dl_register_driver(struct efx_dl_driver *driver);

static inline int efx_dl_register_driver(struct efx_dl_driver *driver)
{
	int rc;

#if EFX_DRIVERLINK_API_VERSION_MINOR > 0
	driver->flags |= EFX_DL_DRIVER_REQUIRES_MINOR_VER;
	driver->flags &= ~EFX_DL_DRIVER_SUPPORTS_MINOR_VER;
	driver->minor_ver = EFX_DRIVERLINK_API_VERSION_MINOR;
#endif

	rc = __efx_dl_register_driver(driver);

#if EFX_DRIVERLINK_API_VERSION_MINOR > 0
	if (rc == 0 && !(driver->flags & EFX_DL_DRIVER_SUPPORTS_MINOR_VER)) {
		efx_dl_unregister_driver(driver);
		rc = -EPERM;
	}
#endif
	return rc;
}

/**
 * efx_dl_netdev_is_ours() - Check whether device is handled by sfc
 * @net_dev: Net device to be checked
 */
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_FASTCALL)
bool fastcall efx_dl_netdev_is_ours(const struct net_device *net_dev);
#else
bool efx_dl_netdev_is_ours(const struct net_device *net_dev);
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
void efx_dl_schedule_reset(struct efx_dl_device *efx_dev);

int efx_dl_filter_insert(struct efx_dl_device *efx_dev,
			 const struct efx_filter_spec *spec,
			 bool replace_equal);
int efx_dl_filter_remove(struct efx_dl_device *efx_dev, int filter_id);
int efx_dl_filter_redirect(struct efx_dl_device *efx_dev,
			   int filter_id, int rxq_i, int stack_id);

int efx_dl_vport_filter_insert(struct efx_dl_device *efx_dev,
			       unsigned int vport_id,
			       const struct efx_filter_spec *spec,
			       u64 *filter_id_out, bool *is_exclusive_out);
int efx_dl_vport_filter_remove(struct efx_dl_device *efx_dev,
			       unsigned int vport_id,
			       u64 filter_id, bool is_exclusive);


/**
 * enum efx_dl_filter_block_kernel_type
 * @EFX_DL_FILTER_BLOCK_KERNEL_UCAST: Unicast
 * @EFX_DL_FILTER_BLOCK_KERNEL_MCAST: Multicast
 */
enum efx_dl_filter_block_kernel_type {
	EFX_DL_FILTER_BLOCK_KERNEL_UCAST = 0,
	EFX_DL_FILTER_BLOCK_KERNEL_MCAST,
	EFX_DL_FILTER_BLOCK_KERNEL_MAX,
};

/**
 * efx_dl_filter_block_kernel - Block the kernel from receiving packets
 * @dl_dev: Driverlink client device context
 * @type: Type (unicast or multicast) of kernel block to insert
 *
 * This increments the kernel block count for the client.  So long as
 * any client has a non-zero count, all filters with priority HINT or
 * AUTO will be removed (or pointed to a drop queue).  The kernel
 * stack and upper devices will not receive packets except through
 * explicit configuration (e.g. ethtool -U or PTP on Siena).  The net
 * driver's loopback self-test will also fail.
 */
int efx_dl_filter_block_kernel(struct efx_dl_device *dl_dev,
			       enum efx_dl_filter_block_kernel_type block);

/**
 * efx_dl_filter_unblock_kernel - Reverse efx_filter_block_kernel()
 * @dl_dev: Driverlink client device context
 * @type: Type (unicast or multicast) of kernel block to insert
 *
 * This decrements the kernel block count for the client.
 */
void efx_dl_filter_unblock_kernel(struct efx_dl_device *dl_dev,
				  enum efx_dl_filter_block_kernel_type type);

/**
 * efx_dl_mcdi_rpc - Issue an MCDI command and wait for completion
 * @dl_dev: Driverlink client device context
 * @cmd: Command type number
 * @inbuf: Command parameters
 * @inlen: Length of command parameters, in bytes.  Must be a multiple
 *	of 4 and no greater than %MC_SMEM_PDU_LEN.
 * @outbuf: Response buffer.  May be %NULL if @outlen is 0.
 * @outlen: Length of response buffer, in bytes.  If the actual
 *	reponse is longer than @outlen & ~3, it will be truncated
 *	to that length.
 * @outlen_actual: Pointer through which to return the actual response
 *	length.  May be %NULL if this is not needed.
 *
 * This function may sleep and therefore must be called in process
 * context.  Defined from API version 6.
 */
int efx_dl_mcdi_rpc(struct efx_dl_device *dl_dev, unsigned int cmd,
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
 *		if (res->flags & EFX_DL_FALCON_HAVE_RSS_CHANNEL_COUNT)
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
