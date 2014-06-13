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
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2011 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_KERNEL_COMPAT_H
#define EFX_KERNEL_COMPAT_H

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
#include <linux/autoconf.h>
#endif
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/i2c.h>
#include <linux/sysfs.h>
#include <linux/stringify.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/cpumask.h>
#include <linux/topology.h>
#include <linux/ethtool.h>
#include <linux/vmalloc.h>
#include <linux/if_vlan.h>
#include <linux/time.h>
#include <net/ip.h>

/**************************************************************************
 *
 * Autoconf compatability
 *
 **************************************************************************/

#include "autocompat.h"

/**************************************************************************
 *
 * Resolve conflicts between feature switches and compatibility flags
 *
 **************************************************************************/

#ifndef EFX_HAVE_GRO
	#undef EFX_USE_GRO
#endif

#ifdef CONFIG_SFC_PRIVATE_MDIO
	#undef EFX_HAVE_LINUX_MDIO_H
#endif

/**************************************************************************
 *
 * Version/config/architecture compatability.
 *
 **************************************************************************
 *
 * The preferred kernel compatability mechanism is through the autoconf
 * layer above. The following definitions are all deprecated
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
	#error "This kernel version is now unsupported"
#endif

#if defined(EFX_HAVE_COMPOUND_PAGES) || defined(CONFIG_HUGETLB_PAGE)
	#define EFX_USE_COMPOUND_PAGES yes
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16) && defined(EFX_USE_COMPOUND_PAGES)
	#define EFX_NEED_COMPOUND_PAGE_FIX
#endif

/* debugfs only supports sym-links from 2.6.21 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21) && defined(CONFIG_DEBUG_FS)
	#define EFX_USE_DEBUGFS yes
#endif

/* netif_device_{detach,attach}() were missed in multiqueue transition */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30) && defined(EFX_USE_TX_MQ)
	#define EFX_NEED_NETIF_DEVICE_DETACH_ATTACH_MQ yes
#endif

#if defined(EFX_USE_IOCTL_RESET_FLAGS) && defined(EFX_HAVE_LINUX_MDIO_H)
	/* mdio module has some bugs in pause frame advertising */
	#define EFX_NEED_MDIO45_FLOW_CONTROL_HACKS yes
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36) && \
	!defined(EFX_NEED_UNMASK_MSIX_VECTORS)
	/* Fixing that bug introduced a different one, fixed in 2.6.36 */
	#define EFX_NEED_SAVE_MSIX_MESSAGES yes
#endif

#ifdef CONFIG_PPC64
	/* __raw_writel and friends are broken on ppc64 */
	#define EFX_NEED_RAW_READ_AND_WRITE_FIX yes
#endif

/**************************************************************************
 *
 * Definitions of missing constants, types, functions and macros
 *
 **************************************************************************
 *
 */

#ifndef spin_trylock_irqsave
	#define spin_trylock_irqsave(lock, flags)	\
	({						\
		local_irq_save(flags);			\
		spin_trylock(lock) ?			\
		1 : ({local_irq_restore(flags); 0;});	\
	})
#endif

#ifndef raw_smp_processor_id
	#define raw_smp_processor_id() (current_thread_info()->cpu)
#endif

#ifndef NETIF_F_GEN_CSUM
	#define NETIF_F_GEN_CSUM (NETIF_F_NO_CSUM | NETIF_F_HW_CSUM)
#endif
#ifndef NETIF_F_V4_CSUM
	#define NETIF_F_V4_CSUM (NETIF_F_GEN_CSUM | NETIF_F_IP_CSUM)
#endif
#ifndef NETIF_F_V6_CSUM
	#define NETIF_F_V6_CSUM  NETIF_F_GEN_CSUM
#endif
#ifndef NETIF_F_ALL_CSUM
	#define NETIF_F_ALL_CSUM (NETIF_F_V4_CSUM | NETIF_F_V6_CSUM)
#endif

#ifdef NETIF_F_RXHASH
	#define EFX_HAVE_RXHASH_SUPPORT yes
#else
	/* This reduces the need for #ifdefs */
	#define NETIF_F_RXHASH 0
	#define ETH_FLAG_RXHASH 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
	/* Prior to Linux 3.0, NETIF_F_NTUPLE was taken to mean that
	 * ethtool_ops::set_rx_ntuple was set, which is not the case in
	 * this driver.  Therefore, we prevent the feature from being
	 * set even if it is defined.
	 */
	#undef NETIF_F_NTUPLE
	#define NETIF_F_NTUPLE 0
	#undef ETH_FLAG_NTUPLE
	#define ETH_FLAG_NTUPLE 0
#endif

#ifndef NETIF_F_RXCSUM
	/* This reduces the need for #ifdefs */
	#define NETIF_F_RXCSUM 0
#endif

/* This reduces the need for #ifdefs */
#ifndef NETIF_F_TSO6
	#define NETIF_F_TSO6 0
#endif
#ifndef NETIF_F_TSO_ECN
	#define NETIF_F_TSO_ECN 0
#endif
#ifndef NETIF_F_ALL_TSO
	#define NETIF_F_ALL_TSO (NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_TSO_ECN)
#endif

/* Cope with small changes in PCI constants between minor kernel revisions */
#if PCI_X_STATUS != 4
	#undef PCI_X_STATUS
	#define PCI_X_STATUS 4
	#undef PCI_X_STATUS_MAX_SPLIT
	#define PCI_X_STATUS_MAX_SPLIT 0x03800000
#endif

#ifndef __GFP_COMP
	#define __GFP_COMP 0
#endif

#ifndef __iomem
	#define __iomem
#endif

#ifndef NET_IP_ALIGN
	#define NET_IP_ALIGN 2
#endif

#ifndef PCI_EXP_FLAGS
	#define PCI_EXP_FLAGS		2	/* Capabilities register */
	#define PCI_EXP_FLAGS_TYPE	0x00f0	/* Device/Port type */
	#define  PCI_EXP_TYPE_ENDPOINT	0x0	/* Express Endpoint */
	#define  PCI_EXP_TYPE_LEG_END	0x1	/* Legacy Endpoint */
	#define  PCI_EXP_TYPE_ROOT_PORT 0x4	/* Root Port */
#endif

#ifndef PCI_EXP_DEVCAP
	#define PCI_EXP_DEVCAP		4	/* Device capabilities */
	#define  PCI_EXP_DEVCAP_PAYLOAD	0x07	/* Max_Payload_Size */
	#define  PCI_EXP_DEVCAP_PWR_VAL	0x3fc0000 /* Slot Power Limit Value */
	#define  PCI_EXP_DEVCAP_PWR_SCL	0xc000000 /* Slot Power Limit Scale */
#endif

#ifndef PCI_EXP_DEVCTL
	#define PCI_EXP_DEVCTL		8	/* Device Control */
	#define  PCI_EXP_DEVCTL_PAYLOAD	0x00e0	/* Max_Payload_Size */
	#define  PCI_EXP_DEVCTL_READRQ	0x7000	/* Max_Read_Request_Size */
#endif

#ifndef PCI_EXP_LNKSTA
	#define PCI_EXP_LNKSTA		18	/* Link Status */
#endif
#ifndef PCI_EXP_LNKSTA_CLS
	#define  PCI_EXP_LNKSTA_CLS	0x000f	/* Current Link Speed */
#endif
#ifndef PCI_EXP_LNKSTA_NLW
	#define  PCI_EXP_LNKSTA_NLW	0x03f0	/* Nogotiated Link Width */
#endif

#ifndef PCI_VENDOR_ID_SOLARFLARE
	#define PCI_VENDOR_ID_SOLARFLARE	0x1924
	#define PCI_DEVICE_ID_SOLARFLARE_SFC4000A_0	0x0703
	#define PCI_DEVICE_ID_SOLARFLARE_SFC4000A_1	0x6703
	#define PCI_DEVICE_ID_SOLARFLARE_SFC4000B	0x0710
#endif

#ifndef __force
	#define __force
#endif

#if ! defined(for_each_cpu_mask) && ! defined(CONFIG_SMP)
	#define for_each_cpu_mask(cpu, mask)            \
		for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#endif

#ifndef IRQF_PROBE_SHARED
	#ifdef SA_PROBEIRQ
		#define IRQF_PROBE_SHARED  SA_PROBEIRQ
	#else
		#define IRQF_PROBE_SHARED  0
	#endif
#endif

#ifndef IRQF_SHARED
	#define IRQF_SHARED	   SA_SHIRQ
#endif

#ifdef EFX_NEED_MMIOWB
	#if defined(__i386__) || defined(__x86_64__)
		#define mmiowb()
	#elif defined(__ia64__)
		#ifndef ia64_mfa
			#define ia64_mfa() asm volatile ("mf.a" ::: "memory")
		#endif
		#define mmiowb ia64_mfa
	#else
		#error "Need definition for mmiowb()"
	#endif
#endif

#ifndef CHECKSUM_PARTIAL
	#define CHECKSUM_PARTIAL CHECKSUM_HW
#endif

#ifndef DMA_BIT_MASK
	#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))
#endif

#if defined(__GNUC__) && !defined(inline)
	#define inline inline __attribute__ ((always_inline))
#endif

#if defined(__GNUC__) && !defined(__packed)
	#define __packed __attribute__((packed))
#endif

#ifndef DIV_ROUND_UP
	#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif

#ifndef __ATTR
	#define __ATTR(_name,_mode,_show,_store) {			\
		.attr = {.name = __stringify(_name), .mode = _mode },	\
		.show   = _show,					\
		.store  = _store,					\
	}
#endif

#ifndef DEVICE_ATTR
	#define DEVICE_ATTR(_name, _mode, _show, _store)		\
		struct device_attribute dev_attr_ ## _name =		\
			__ATTR(_name, _mode, _show, _store)
#endif

#ifndef sysfs_attr_init
	#define sysfs_attr_init(attr) do {} while(0)
#endif

#ifndef to_i2c_adapter
	#define to_i2c_adapter dev_to_i2c_adapter
#endif

#if defined(CONFIG_X86) && !defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#endif

#ifndef BUILD_BUG_ON_ZERO
	#define BUILD_BUG_ON_ZERO(e) (sizeof(char[1 - 2 * !!(e)]) - 1)
#endif

#ifndef __bitwise
	#define __bitwise
#endif

#ifdef EFX_NEED_ATOMIC_CMPXCHG
	#define atomic_cmpxchg(v, old, new) ((int)cmpxchg(&((v)->counter), old, new))
#endif

#ifndef cpumask_of
	/* This is an absolute nightmare. In old kernels, cpumask_of_cpu() is
	 * a macro closure, so we can't use &cpumask_of_cpu(). This should
	 * always be safe, and should provide some protection against
	 * inter-file use of cpumask_of()
	 */
	static inline cpumask_t *cpumask_of(int cpu)
	{
		static cpumask_t var;

		var = cpumask_of_cpu(cpu);
		return &var;
	}
#endif

#ifndef KBUILD_STR
	/* KBUILD_MODNAME is not a string */
	#define __KBUILD_STR(s) #s
	#define KBUILD_STR(s) __KBUILD_STR(s)
	static char efx_kbuild_modname[] __attribute__((unused)) =
		KBUILD_STR(KBUILD_MODNAME);
	#undef KBUILD_MODNAME
	#define KBUILD_MODNAME efx_kbuild_modname
#endif

#ifndef VLAN_PRIO_SHIFT
	#define VLAN_PRIO_SHIFT         13
#endif

#ifndef ACCESS_ONCE
	#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif

/**************************************************************************/

#ifdef EFX_NEED_IRQ_HANDLER_T
	typedef irqreturn_t (*irq_handler_t)(int, void *, struct pt_regs *);
#endif

/* linux_mdio.h needs this */
#ifdef EFX_NEED_BOOL
	typedef _Bool bool;
	enum { false, true };
#endif

#ifdef EFX_NEED_BYTEORDER_TYPES
	typedef __u16 __be16;
	typedef __u32 __be32;
	typedef __u64 __be64;
	typedef __u16 __le16;
	typedef __u32 __le32;
	typedef __u64 __le64;
#endif

#ifdef EFX_HAVE_LINUX_MDIO_H
	#include <linux/mdio.h>
#else
	#include "linux_mdio.h"
#endif

#ifdef EFX_NEED_MII_CONSTANTS
	#define BMCR_SPEED1000		0x0040
	#define ADVERTISE_PAUSE_ASYM	0x0800
	#define ADVERTISE_PAUSE_CAP	0x0400
#endif

#ifdef EFX_NEED_ETHTOOL_CONSTANTS
	#define ADVERTISED_Pause	(1 << 13)
	#define ADVERTISED_Asym_Pause	(1 << 14)
#endif

#ifndef ETH_RESET_SHARED_SHIFT
	enum ethtool_reset_flags {
		/* These flags represent components dedicated to the interface
		 * the command is addressed to.  Shift any flag left by
		 * ETH_RESET_SHARED_SHIFT to reset a shared component of the
		 * same type.
		 */
	  	ETH_RESET_MGMT		= 1 << 0,	/* Management processor */
		ETH_RESET_IRQ		= 1 << 1,	/* Interrupt requester */
		ETH_RESET_DMA		= 1 << 2,	/* DMA engine */
		ETH_RESET_FILTER	= 1 << 3,	/* Filtering/flow direction */
		ETH_RESET_OFFLOAD	= 1 << 4,	/* Protocol offload */
		ETH_RESET_MAC		= 1 << 5,	/* Media access controller */
		ETH_RESET_PHY		= 1 << 6,	/* Transceiver/PHY */
		ETH_RESET_RAM		= 1 << 7,	/* RAM shared between
							 * multiple components */

		ETH_RESET_DEDICATED	= 0x0000ffff,	/* All components dedicated to
							 * this interface */
		ETH_RESET_ALL		= 0xffffffff,	/* All components used by this
							 * interface, even if shared */
	};
	#define ETH_RESET_SHARED_SHIFT	16
	#define ETHTOOL_RESET		0x00000034
#endif

#ifndef ETHTOOL_GRXFH
	#define ETHTOOL_GRXFH		0x00000029
#endif

#ifdef ETHTOOL_GRXRINGS
	#define EFX_HAVE_ETHTOOL_RXNFC yes
#else
	#define ETHTOOL_GRXRINGS	0x0000002d
#endif

#ifndef TCP_V4_FLOW
	#define	TCP_V4_FLOW	0x01
	#define	UDP_V4_FLOW	0x02
	#define	SCTP_V4_FLOW	0x03
	#define	AH_ESP_V4_FLOW	0x04
	#define	TCP_V6_FLOW	0x05
	#define	UDP_V6_FLOW	0x06
	#define	SCTP_V6_FLOW	0x07
	#define	AH_ESP_V6_FLOW	0x08
#endif
#ifndef AH_V4_FLOW
	#define	AH_V4_FLOW	0x09
	#define	ESP_V4_FLOW	0x0a
	#define	AH_V6_FLOW	0x0b
	#define	ESP_V6_FLOW	0x0c
	#define	IP_USER_FLOW	0x0d
#endif
#ifndef IPV4_FLOW
	#define	IPV4_FLOW	0x10
	#define	IPV6_FLOW	0x11
#endif
#ifndef ETHER_FLOW
	#define ETHER_FLOW	0x12
#endif
#ifndef FLOW_EXT
	#define	FLOW_EXT	0x80000000
#endif
#ifndef RXH_L2DA
	#define	RXH_L2DA	(1 << 1)
	#define	RXH_VLAN	(1 << 2)
	#define	RXH_L3_PROTO	(1 << 3)
	#define	RXH_IP_SRC	(1 << 4)
	#define	RXH_IP_DST	(1 << 5)
	#define	RXH_L4_B_0_1	(1 << 6)
	#define	RXH_L4_B_2_3	(1 << 7)
	#define	RXH_DISCARD	(1 << 31)
#endif

#ifndef ETHTOOL_GRXCLSRULE
	struct ethtool_tcpip4_spec {
		__be32	ip4src;
		__be32	ip4dst;
		__be16	psrc;
		__be16	pdst;
		__u8    tos;
	};

	#define RX_CLS_FLOW_DISC	0xffffffffffffffffULL

	#define ETHTOOL_GRXCLSRLCNT	0x0000002e
	#define ETHTOOL_GRXCLSRULE	0x0000002f
	#define ETHTOOL_GRXCLSRLALL	0x00000030
	#define ETHTOOL_SRXCLSRLDEL     0x00000031
	#define ETHTOOL_SRXCLSRLINS	0x00000032
#endif

/* We want to use the latest definition of ethtool_rxnfc, even if the
 * kernel headers don't define all the fields in it.  Use our own name
 * and cast as necessary.
 */
#ifndef EFX_HAVE_EFX_ETHTOOL_RXNFC
	union efx_ethtool_flow_union {
		struct ethtool_tcpip4_spec		tcp_ip4_spec;
		struct ethtool_tcpip4_spec		udp_ip4_spec;
		struct ethtool_tcpip4_spec		sctp_ip4_spec;
		struct ethhdr				ether_spec;
		/* unneeded members omitted... */
		__u8					hdata[60];
	};
	struct efx_ethtool_flow_ext {
		__be16	vlan_etype;
		__be16	vlan_tci;
		__be32	data[2];
	};
	struct efx_ethtool_rx_flow_spec {
		__u32		flow_type;
		union efx_ethtool_flow_union h_u;
		struct efx_ethtool_flow_ext h_ext;
		union efx_ethtool_flow_union m_u;
		struct efx_ethtool_flow_ext m_ext;
		__u64		ring_cookie;
		__u32		location;
	};
	struct efx_ethtool_rxnfc {
		__u32				cmd;
		__u32				flow_type;
		__u64				data;
		struct efx_ethtool_rx_flow_spec	fs;
		__u32				rule_cnt;
		__u32				rule_locs[0];
	};
	#define EFX_HAVE_EFX_ETHTOOL_RXNFC yes
#endif

#ifndef RX_CLS_LOC_SPECIAL
	#define RX_CLS_LOC_SPECIAL	0x80000000
	#define RX_CLS_LOC_ANY		0xffffffff
	#define RX_CLS_LOC_FIRST	0xfffffffe
	#define RX_CLS_LOC_LAST		0xfffffffd
#endif

#ifdef ETHTOOL_GRXFHINDIR
	#define EFX_HAVE_ETHTOOL_RXFH_INDIR yes
#else
	struct ethtool_rxfh_indir {
		__u32	cmd;
		/* On entry, this is the array size of the user buffer.  On
		 * return from ETHTOOL_GRXFHINDIR, this is the array size of
		 * the hardware indirection table. */
		__u32	size;
		__u32	ring_index[0];	/* ring/queue index for each hash value */
	};
	#define ETHTOOL_GRXFHINDIR	0x00000038
	#define ETHTOOL_SRXFHINDIR	0x00000039
#endif

#ifdef EFX_NEED_ETHTOOL_RXFH_INDIR_DEFAULT
	static inline u32 ethtool_rxfh_indir_default(u32 index, u32 n_rx_rings)
	{
		return index % n_rx_rings;
	}
#endif

#ifndef EFX_HAVE_ETHTOOL_SET_PHYS_ID
	enum ethtool_phys_id_state {
		ETHTOOL_ID_INACTIVE,
		ETHTOOL_ID_ACTIVE,
		ETHTOOL_ID_ON,
		ETHTOOL_ID_OFF
	};
#endif

#ifdef EFX_NEED_ETHTOOL_CMD_SPEED
	static inline void ethtool_cmd_speed_set(struct ethtool_cmd *ep,
						 u32 speed)
	{
		ep->speed = speed;
		/* speed_hi is at offset 28 (architecture-independent) */
		((u16 *)ep)[14] = speed >> 16;
	}

	static inline u32 ethtool_cmd_speed(const struct ethtool_cmd *ep)
	{
		return ((u16 *)ep)[14] << 16 | ep->speed;
	}
#endif

#ifdef ETHTOOL_GMODULEEEPROM
	#define EFX_HAVE_ETHTOOL_GMODULEEEPROM yes
#else
	struct ethtool_modinfo {
		__u32   cmd;
		__u32   type;
		__u32   eeprom_len;
		__u32   reserved[8];
	};

	#define ETH_MODULE_SFF_8079     0x1
	#define ETH_MODULE_SFF_8079_LEN 256
	#define ETH_MODULE_SFF_8472     0x2
	#define ETH_MODULE_SFF_8472_LEN 512

	#define ETHTOOL_GMODULEINFO     0x00000042
	#define ETHTOOL_GMODULEEEPROM   0x00000043
#endif

#ifndef FLOW_CTRL_TX
	#define FLOW_CTRL_TX		0x01
	#define FLOW_CTRL_RX		0x02
#endif

#ifdef EFX_NEED_MII_RESOLVE_FLOWCTRL_FDX
	/**
	 * mii_resolve_flowctrl_fdx
	 * @lcladv: value of MII ADVERTISE register
	 * @rmtadv: value of MII LPA register
	 *
	 * Resolve full duplex flow control as per IEEE 802.3-2005 table 28B-3
	 */
	static inline u8 mii_resolve_flowctrl_fdx(u16 lcladv, u16 rmtadv)
	{
		u8 cap = 0;

		if (lcladv & rmtadv & ADVERTISE_PAUSE_CAP) {
			cap = FLOW_CTRL_TX | FLOW_CTRL_RX;
		} else if (lcladv & rmtadv & ADVERTISE_PAUSE_ASYM) {
			if (lcladv & ADVERTISE_PAUSE_CAP)
				cap = FLOW_CTRL_RX;
			else if (rmtadv & ADVERTISE_PAUSE_CAP)
				cap = FLOW_CTRL_TX;
		}

		return cap;
	}
#endif

#ifdef EFX_NEED_MII_ADVERTISE_FLOWCTRL
	/**
	 * mii_advertise_flowctrl - get flow control advertisement flags
	 * @cap: Flow control capabilities (FLOW_CTRL_RX, FLOW_CTRL_TX or both)
	 */
	static inline u16 mii_advertise_flowctrl(int cap)
	{
		u16 adv = 0;

		if (cap & FLOW_CTRL_RX)
			adv = ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM;
		if (cap & FLOW_CTRL_TX)
			adv ^= ADVERTISE_PAUSE_ASYM;

		return adv;
	}
#endif

#ifndef PORT_OTHER
	#define PORT_OTHER		0xff
#endif

#ifndef SUPPORTED_Pause
	#define SUPPORTED_Pause			(1 << 13)
	#define SUPPORTED_Asym_Pause		(1 << 14)
#endif

#ifndef SUPPORTED_Backplane
	#define SUPPORTED_Backplane		(1 << 16)
	#define SUPPORTED_1000baseKX_Full	(1 << 17)
	#define SUPPORTED_10000baseKX4_Full	(1 << 18)
	#define SUPPORTED_10000baseKR_Full	(1 << 19)
	#define SUPPORTED_10000baseR_FEC	(1 << 20)
#endif

#ifdef EFX_NEED_SKB_HEADER_MACROS
	#define skb_mac_header(skb)	((skb)->mac.raw)
	#define skb_network_header(skb) ((skb)->nh.raw)
	#define skb_tail_pointer(skb)   ((skb)->tail)
	#define skb_set_mac_header(skb, offset)			\
		((skb)->mac.raw = (skb)->data + (offset))
	#define skb_transport_header(skb) ((skb)->h.raw)
#endif

#ifdef EFX_NEED_SKB_RECORD_RX_QUEUE
	#define skb_record_rx_queue(_skb, _channel)
#endif

#ifdef EFX_NEED_TCP_HDR
	#define tcp_hdr(skb)		((skb)->h.th)
#endif

#ifdef EFX_NEED_UDP_HDR
	#define udp_hdr(skb)		((skb)->h.uh)
#endif

#ifdef EFX_NEED_IP_HDR
	#define ip_hdr(skb)		((skb)->nh.iph)
#endif

#ifdef EFX_NEED_IPV6_HDR
	#define ipv6_hdr(skb)		((skb)->nh.ipv6h)
#endif

#ifdef EFX_NEED_RAW_READ_AND_WRITE_FIX
	#include <asm/io.h>
	static inline void
	efx_raw_writeb(u8 value, volatile void __iomem *addr)
	{
		writeb(value, addr);
	}
	static inline void
	efx_raw_writew(u16 value, volatile void __iomem *addr)
	{
		writew(le16_to_cpu(value), addr);
	}
	static inline void
	efx_raw_writel(u32 value, volatile void __iomem *addr)
	{
		writel(le32_to_cpu(value), addr);
	}
	static inline void
	efx_raw_writeq(u64 value, volatile void __iomem *addr)
	{
		writeq(le64_to_cpu(value), addr);
	}
	static inline u8
	efx_raw_readb(const volatile void __iomem *addr)
	{
		return readb(addr);
	}
	static inline u16
	efx_raw_readw(const volatile void __iomem *addr)
	{
		return cpu_to_le16(readw(addr));
	}
	static inline u32
	efx_raw_readl(const volatile void __iomem *addr)
	{
		return cpu_to_le32(readl(addr));
	}
	static inline u64
	efx_raw_readq(const volatile void __iomem *addr)
	{
		return cpu_to_le64(readq(addr));
	}

	#undef __raw_writeb
	#undef __raw_writew
	#undef __raw_writel
	#undef __raw_writeq
	#undef __raw_readb
	#undef __raw_readw
	#undef __raw_readl
	#undef __raw_readq
	#define __raw_writeb efx_raw_writeb
	#define __raw_writew efx_raw_writew
	#define __raw_writel efx_raw_writel
	#define __raw_writeq efx_raw_writeq
	#define __raw_readb efx_raw_readb
	#define __raw_readw efx_raw_readw
	#define __raw_readl efx_raw_readl
	#define __raw_readq efx_raw_readq
#endif

#ifdef EFX_NEED_SCHEDULE_TIMEOUT_INTERRUPTIBLE
	static inline signed long
	schedule_timeout_interruptible(signed long timeout)
	{
		set_current_state(TASK_INTERRUPTIBLE);
		return schedule_timeout(timeout);
	}
#endif

#ifdef EFX_NEED_SCHEDULE_TIMEOUT_UNINTERRUPTIBLE
	static inline signed long
	schedule_timeout_uninterruptible(signed long timeout)
	{
		set_current_state(TASK_UNINTERRUPTIBLE);
		return schedule_timeout(timeout);
	}
#endif

#ifdef EFX_NEED_KZALLOC
	static inline void *kzalloc(size_t size, int flags)
	{
		void *buf = kmalloc(size, flags);
		if (buf)
			memset(buf, 0,size);
		return buf;
	}
#endif

#ifdef EFX_NEED_KCALLOC
	static inline void *kcalloc(size_t n, size_t size, int flags)
	{
		if (size != 0 && n > ULONG_MAX / size)
			return NULL;
		return kzalloc(n * size, flags);
	}
#endif

#ifdef EFX_NEED_VZALLOC
	static inline void *vzalloc(unsigned long size)
	{
		void *buf = vmalloc(size);
		if (buf)
			memset(buf, 0, size);
		return buf;
	}
#endif

#ifdef EFX_NEED_SETUP_TIMER
	static inline void setup_timer(struct timer_list * timer,
				       void (*function)(unsigned long),
				       unsigned long data)
	{
		timer->function = function;
		timer->data = data;
		init_timer(timer);
	}
#endif

#ifdef EFX_NEED_MUTEX
	#define EFX_DEFINE_MUTEX(x) DECLARE_MUTEX(x)
	#undef DEFINE_MUTEX
	#define DEFINE_MUTEX EFX_DEFINE_MUTEX

	#define efx_mutex semaphore
	#undef mutex
	#define mutex efx_mutex

	#define efx_mutex_init(x) init_MUTEX(x)
	#undef mutex_init
	#define mutex_init efx_mutex_init

	#define efx_mutex_destroy(x) do { } while(0)
	#undef mutex_destroy
	#define mutex_destroy efx_mutex_destroy

	#define efx_mutex_lock(x) down(x)
	#undef mutex_lock
	#define mutex_lock efx_mutex_lock

	#define efx_mutex_lock_interruptible(x) down_interruptible(x)
	#undef mutex_lock_interruptible
	#define mutex_lock_interruptible efx_mutex_lock_interruptible

	#define efx_mutex_unlock(x) up(x)
	#undef mutex_unlock
	#define mutex_unlock efx_mutex_unlock

	#define efx_mutex_trylock(x) (!down_trylock(x))
	#undef mutex_trylock
	#define mutex_trylock efx_mutex_trylock

	static inline int efx_mutex_is_locked(struct efx_mutex *m)
	{
		/* NB. This is quite inefficient, but it's the best we
		 * can do with the semaphore API. */
		if ( down_trylock(m) )
			return 1;
		/* Undo the effect of down_trylock. */
		up(m);
		return 0;
	}
	#undef mutex_is_locked
	#define mutex_is_locked efx_mutex_is_locked
#else
	#include <linux/mutex.h>
#endif

#ifndef NETIF_F_GSO
	#define efx_gso_size tso_size
	#undef gso_size
	#define gso_size efx_gso_size
	#define efx_gso_segs tso_segs
	#undef gso_segs
	#define gso_segs efx_gso_segs
#endif

#ifndef GSO_MAX_SIZE
	#define GSO_MAX_SIZE 65536
#endif

#ifdef EFX_NEED_NETDEV_ALLOC_SKB
	#ifndef NET_SKB_PAD
		#define NET_SKB_PAD 16
	#endif

	static inline
	struct sk_buff *netdev_alloc_skb(struct net_device *dev,
					 unsigned int length)
	{
		struct sk_buff *skb = alloc_skb(length + NET_SKB_PAD,
						GFP_ATOMIC | __GFP_COLD);
		if (likely(skb)) {
			skb_reserve(skb, NET_SKB_PAD);
			skb->dev = dev;
		}
		return skb;
	}
#endif

#ifdef EFX_NEED_NETDEV_TX_T
	typedef int netdev_tx_t;
	#ifndef NETDEV_TX_OK
		#define NETDEV_TX_OK 0
	#endif
	#ifndef NETDEV_TX_BUSY
		#define NETDEV_TX_BUSY 1
	#endif
#endif

#ifndef netdev_for_each_mc_addr
	#define netdev_for_each_mc_addr(mclist, dev) \
		for (mclist = dev->mc_list; mclist; mclist = mclist->next)
#endif

#ifdef EFX_NEED_ALLOC_ETHERDEV_MQ
	#define alloc_etherdev_mq(sizeof_priv, queue_count) 		\
		({							\
			BUILD_BUG_ON((queue_count) != 1);		\
			alloc_etherdev(sizeof_priv);			\
		})
#endif

#ifdef EFX_NEED_TX_MQ_API
	#define netdev_get_tx_queue(dev, index) (dev)
	#define netif_tx_stop_queue netif_stop_queue
	#define netif_tx_stop_all_queues netif_stop_queue
	#define netif_tx_start_queue netif_start_queue
	#define netif_tx_wake_queue netif_wake_queue
	#define netif_tx_wake_all_queues netif_wake_queue
	#define netif_tx_queue_stopped netif_queue_stopped
	#define skb_get_queue_mapping(skb) 0
	#define netdev_queue net_device

	#define __netif_tx_lock(_dev, _cpu)		\
		netif_tx_lock((_dev))
	#define __netif_tx_lock_bh(_dev)		\
		netif_tx_lock_bh(_dev)
	#define __netif_tx_unlock(_dev)			\
		netif_tx_unlock((_dev))
	#define __netif_tx_unlock_bh(_dev)		\
		netif_tx_unlock_bh(_dev)
#endif

#ifdef EFX_NEED_NETIF_SET_REAL_NUM_TX_QUEUES
	static inline void
	netif_set_real_num_tx_queues(struct net_device *dev, unsigned int txq)
	{
#ifdef EFX_USE_TX_MQ
		dev->real_num_tx_queues = txq;
#endif
	}
#endif

#ifdef EFX_NEED_NETIF_SET_REAL_NUM_RX_QUEUES
	static inline void
	netif_set_real_num_rx_queues(struct net_device *dev, unsigned int rxq)
	{
#ifdef CONFIG_RPS
		dev->num_rx_queues = rxq;
#endif
	}
#endif

#ifdef EFX_HAVE_NONCONST_ETHTOOL_OPS
	#undef SET_ETHTOOL_OPS
	#define SET_ETHTOOL_OPS(netdev, ops)				\
		((netdev)->ethtool_ops = (struct ethtool_ops *)(ops))
#endif

#ifdef EFX_NEED_RTNL_TRYLOCK
	static inline int rtnl_trylock(void) {
		return !rtnl_shlock_nowait();
	}
#endif

#ifdef EFX_NEED_NETIF_TX_LOCK
	static inline void netif_tx_lock(struct net_device *dev)
	{
		spin_lock(&dev->xmit_lock);
		dev->xmit_lock_owner = smp_processor_id();
	}
	static inline void netif_tx_lock_bh(struct net_device *dev)
	{
		spin_lock_bh(&dev->xmit_lock);
		dev->xmit_lock_owner = smp_processor_id();
	}
	static inline void netif_tx_unlock_bh(struct net_device *dev)
	{
		dev->xmit_lock_owner = -1;
		spin_unlock_bh(&dev->xmit_lock);
	}
	static inline void netif_tx_unlock(struct net_device *dev)
	{
		dev->xmit_lock_owner = -1;
		spin_unlock(&dev->xmit_lock);
	}
#endif

#ifdef EFX_NEED_NETIF_ADDR_LOCK
	static inline void netif_addr_lock(struct net_device *dev)
	{
		netif_tx_lock(dev);
	}
	static inline void netif_addr_lock_bh(struct net_device *dev)
	{
		netif_tx_lock_bh(dev);
	}
	static inline void netif_addr_unlock_bh(struct net_device *dev)
	{
		netif_tx_unlock_bh(dev);
	}
	static inline void netif_addr_unlock(struct net_device *dev)
	{
		netif_tx_unlock(dev);
	}
#endif

#ifdef EFX_NEED_DEV_GET_STATS
	static inline const struct net_device_stats *
	dev_get_stats(struct net_device *dev)
	{
		return dev->get_stats(dev);
	}
#endif

#ifdef EFX_HAVE_OLD_IP_FAST_CSUM
	#include <net/checksum.h>
	#define ip_fast_csum(iph, ihl) ip_fast_csum((unsigned char *)iph, ihl)
#endif

#ifdef EFX_HAVE_OLD_CSUM
	typedef u16 __sum16;
	typedef u32 __wsum;
	#define csum_unfold(x) ((__force __wsum) x)
#endif

#ifdef EFX_NEED_HEX_DUMP
	enum {
		DUMP_PREFIX_NONE,
		DUMP_PREFIX_ADDRESS,
		DUMP_PREFIX_OFFSET
	};
#endif

#if defined(EFX_NEED_PRINT_MAC) && !defined(DECLARE_MAC_BUF)
	#define DECLARE_MAC_BUF(var) char var[18] __attribute__((unused))
#endif

#ifdef EFX_NEED_GFP_T
	typedef unsigned int gfp_t;
#endif

#ifdef EFX_NEED_SAFE_LISTS
	#define list_for_each_entry_safe_reverse(pos, n, head, member)	     \
		for (pos = list_entry((head)->prev, typeof(*pos), member),   \
		     n = list_entry(pos->member.prev, typeof(*pos), member); \
		     &pos->member != (head);				     \
		     pos = n,						     \
		     n = list_entry(n->member.prev, typeof(*n), member))
#endif

#ifdef EFX_NEED_DEV_NOTICE
	#define dev_notice dev_warn
#endif

#ifdef EFX_NEED_DEV_CREATE_FIX
	#define efx_device_create(cls, parent, devt, drvdata, fmt, _args...) \
			device_create(cls, parent, devt, fmt ## _args)
#else
	#define efx_device_create(cls, parent, devt, drvdata, fmt, _args...) \
			device_create(cls, parent, devt, drvdata, fmt ## _args)
#endif

#ifdef EFX_NEED_RESOURCE_SIZE_T
	typedef unsigned long resource_size_t;
#endif

#ifdef EFX_USE_I2C_LEGACY
	#ifndef I2C_BOARD_INFO
		struct i2c_board_info {
			char type[I2C_NAME_SIZE];
			unsigned short flags;
			unsigned short addr;
			void *platform_data;
			int irq;
		};
		#define I2C_BOARD_INFO(dev_type, dev_addr) \
			.type = (dev_type), .addr = (dev_addr)
	#endif
	struct i2c_client *
	i2c_new_device(struct i2c_adapter *adap, const struct i2c_board_info *info);
	struct i2c_client *
	i2c_new_probed_device(struct i2c_adapter *adap,
			      const struct i2c_board_info *info,
			      const unsigned short *addr_list);
	void i2c_unregister_device(struct i2c_client *);
	struct i2c_device_id;
#endif

#ifdef EFX_NEED_I2C_NEW_DUMMY
	extern struct i2c_driver efx_i2c_dummy_driver;
	struct i2c_client *
	efx_i2c_new_dummy(struct i2c_adapter *adap, u16 address);
	#undef i2c_new_dummy
	#define i2c_new_dummy efx_i2c_new_dummy
#endif

#ifdef EFX_HAVE_OLD_I2C_NEW_DUMMY
	static inline struct i2c_client *
	efx_i2c_new_dummy(struct i2c_adapter *adap, u16 address)
	{
		return i2c_new_dummy(adap, address, "dummy");
	}
	#undef i2c_new_dummy
	#define i2c_new_dummy efx_i2c_new_dummy
#endif

#ifdef EFX_NEED_I2C_LOCK_ADAPTER
	#ifdef EFX_USE_I2C_BUS_SEMAPHORE
		static inline void i2c_lock_adapter(struct i2c_adapter *adap)
		{
			down(&adap->bus_lock);
		}
		static inline void i2c_unlock_adapter(struct i2c_adapter *adap)
		{
			up(&adap->bus_lock);
		}
	#else
		static inline void i2c_lock_adapter(struct i2c_adapter *adap)
		{
			mutex_lock(&adap->bus_lock);
		}
		static inline void i2c_unlock_adapter(struct i2c_adapter *adap)
		{
			mutex_unlock(&adap->bus_lock);
		}
	#endif
#endif

#ifdef EFX_HAVE_OLD_DMA_MAPPING_ERROR
	static inline int
	efx_dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
	{
        	return dma_mapping_error(dma_addr);
	}
	#undef dma_mapping_error
	#define dma_mapping_error efx_dma_mapping_error
#endif

#ifdef EFX_NEED_DMA_SET_COHERENT_MASK
	static inline int dma_set_coherent_mask(struct device *dev, u64 mask)
	{
		return pci_set_consistent_dma_mask(to_pci_dev(dev), mask);
	}
#endif

#ifdef EFX_NEED_FOR_EACH_PCI_DEV
	#define for_each_pci_dev(d)				\
		while ((d = pci_get_device(PCI_ANY_ID,		\
			PCI_ANY_ID, d)) != NULL)
#endif

#ifndef DEFINE_PCI_DEVICE_TABLE
	#define DEFINE_PCI_DEVICE_TABLE(_table) \
		const struct pci_device_id _table[] __devinitdata
#endif

#ifdef EFX_NEED_LM87_DRIVER
#ifdef EFX_HAVE_OLD_I2C_DRIVER_PROBE
int efx_lm87_probe(struct i2c_client *client);
#else
int efx_lm87_probe(struct i2c_client *client, const struct i2c_device_id *);
#endif
extern struct i2c_driver efx_lm87_driver;
#endif

#ifdef EFX_NEED_LM90_DRIVER
#ifdef EFX_HAVE_OLD_I2C_DRIVER_PROBE
int efx_lm90_probe(struct i2c_client *client);
#else
int efx_lm90_probe(struct i2c_client *client, const struct i2c_device_id *);
#endif
extern struct i2c_driver efx_lm90_driver;
#endif

/*
 * Recent mainline kernels can be configured so that the resulting
 * image will run both on 'bare metal' and in a Xen domU.
 * xen_domain() or xen_start_info tells us which is the case at
 * run-time.  If neither is defined, assume that CONFIG_XEN tells us
 * at compile-time.
 */
#if defined(EFX_HAVE_XEN_XEN_H)
	#include <xen/xen.h>
#elif defined(CONFIG_XEN) && defined(EFX_HAVE_XEN_START_INFO)
	/* We should be able to include <asm/xen/hypervisor.h> but that
	 * is broken (#includes other headers that are not installed) in
	 * Fedora 10. */
	extern struct start_info *xen_start_info;
	#define xen_domain() (xen_start_info ? 1 : 0)
#endif
#ifndef xen_domain
	#ifdef CONFIG_XEN
		#define xen_domain() 1
	#else
		#define xen_domain() 0
	#endif
#endif

#ifndef IS_ALIGNED
	#define IS_ALIGNED(x, a) (((x) & ((typeof(x))(a) - 1)) == 0)
#endif

#ifndef netif_printk

	/* A counterpart to SET_NETDEV_DEV */
	#ifdef EFX_USE_NETDEV_DEV
		#define EFX_GET_NETDEV_DEV(netdev) ((netdev)->dev.parent)
	#else
		#define EFX_GET_NETDEV_DEV(netdev) ((netdev)->class_dev.dev)
	#endif

	static inline const char *netdev_name(const struct net_device *dev)
	{
		if (dev->reg_state != NETREG_REGISTERED)
			return "(unregistered net_device)";
		return dev->name;
	}

	#define netdev_printk(level, netdev, format, args...)		\
		dev_printk(level, EFX_GET_NETDEV_DEV(netdev),		\
			   "%s: " format,				\
			   netdev_name(netdev), ##args)

	#define netif_printk(priv, type, level, dev, fmt, args...)	\
	do {					  			\
		if (netif_msg_##type(priv))				\
			netdev_printk(level, (dev), fmt, ##args);	\
	} while (0)

	#define netif_emerg(priv, type, dev, fmt, args...)		\
		netif_printk(priv, type, KERN_EMERG, dev, fmt, ##args)
	#define netif_alert(priv, type, dev, fmt, args...)		\
		netif_printk(priv, type, KERN_ALERT, dev, fmt, ##args)
	#define netif_crit(priv, type, dev, fmt, args...)		\
		netif_printk(priv, type, KERN_CRIT, dev, fmt, ##args)
	#define netif_err(priv, type, dev, fmt, args...)		\
		netif_printk(priv, type, KERN_ERR, dev, fmt, ##args)
	#define netif_warn(priv, type, dev, fmt, args...)		\
		netif_printk(priv, type, KERN_WARNING, dev, fmt, ##args)
	#define netif_notice(priv, type, dev, fmt, args...)		\
		netif_printk(priv, type, KERN_NOTICE, dev, fmt, ##args)
	#define netif_info(priv, type, dev, fmt, args...)		\
		netif_printk(priv, type, KERN_INFO, (dev), fmt, ##args)

	#if defined(DEBUG)
	#define netif_dbg(priv, type, dev, format, args...)		\
		netif_printk(priv, type, KERN_DEBUG, dev, format, ##args)
	#elif defined(CONFIG_DYNAMIC_DEBUG)
	#define netif_dbg(priv, type, netdev, format, args...)		\
	do {								\
		if (netif_msg_##type(priv))				\
			dynamic_dev_dbg((netdev)->dev.parent,		\
					"%s: " format,			\
					netdev_name(netdev), ##args);	\
	} while (0)
	#else
	#define netif_dbg(priv, type, dev, format, args...)		\
	({								\
		if (0)							\
			netif_printk(priv, type, KERN_DEBUG, dev,	\
				     format, ##args);			\
		0;							\
	})
	#endif

#endif

/* netif_vdbg may be defined wrongly */
#undef netif_vdbg
#if defined(VERBOSE_DEBUG)
#define netif_vdbg	netif_dbg
#else
#define netif_vdbg(priv, type, dev, format, args...)		\
({								\
	if (0)							\
		netif_printk(priv, type, KERN_DEBUG, dev,	\
			     format, ##args);			\
	0;							\
})
#endif

#ifndef pr_err
	#define pr_err(fmt, arg...) \
		printk(KERN_ERR fmt, ##arg)
#endif
#ifndef pr_warning
	#define pr_warning(fmt, arg...) \
		printk(KERN_WARNING fmt, ##arg)
#endif

#ifndef __always_unused
	#define __always_unused __attribute__((unused))
#endif

#ifdef EFX_NEED_IS_ZERO_ETHER_ADDR
	static inline int is_zero_ether_addr(const u8 *addr)
	{
		return !(addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]);
	}
#endif

#ifdef EFX_NEED_IS_BROADCAST_ETHER_ADDR
	static inline int is_broadcast_ether_addr(const u8 *addr)
	{
        	return (addr[0] & addr[1] & addr[2] & addr[3] & addr[4] & addr[5]) == 0xff;
	}
#endif

#ifdef EFX_NEED_IS_MULTICAST_ETHER_ADDR
	static inline int is_multicast_ether_addr(const u8 *addr)
	{
        	return addr[0] & 0x01;
	}
#endif

#ifdef EFX_NEED_COMPARE_ETHER_ADDR
	static inline unsigned
	compare_ether_addr(const u8 *addr1, const u8 *addr2)
	{
	        const u16 *a = (const u16 *) addr1;
	        const u16 *b = (const u16 *) addr2;

	        BUILD_BUG_ON(ETH_ALEN != 6);
	        return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) != 0;
	}
#endif

#ifdef EFX_NEED_ETHER_ADDR_EQUAL
	static inline bool ether_addr_equal(const u8 *addr1, const u8 *addr2)
	{
		return !compare_ether_addr(addr1, addr2);
	}
#endif

#ifdef EFX_NEED_IP_IS_FRAGMENT
	static inline bool ip_is_fragment(const struct iphdr *iph)
	{
		return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
	}
#endif

#ifdef EFX_NEED_NETDEV_FEATURES_T
	typedef u32 netdev_features_t;
#endif

#ifdef EFX_NEED_SKB_FILL_PAGE_DESC
	static inline void
	skb_fill_page_desc(struct sk_buff *skb, int i, struct page *page,
			   int off, int size)
	{
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		frag->page = page;
		frag->page_offset = off;
		frag->size = size;
		skb_shinfo(skb)->nr_frags = i+1;
	}
#endif

#ifdef EFX_NEED_SKB_FRAG_DMA_MAP
	static inline dma_addr_t skb_frag_dma_map(struct device *dev,
						  const skb_frag_t *frag,
						  size_t offset, size_t size,
						  enum dma_data_direction dir)
	{
		return dma_map_page(dev, frag->page,
				    frag->page_offset + offset, size, dir);
	}
#endif

#ifdef EFX_NEED_SKB_FRAG_SIZE
	static inline unsigned int skb_frag_size(const skb_frag_t *frag)
	{
		return frag->size;
	}
#endif

#if defined(CONFIG_COMPAT) && defined(EFX_NEED_COMPAT_U64)
	#if defined(CONFIG_X86_64) || defined(CONFIG_IA64)
		typedef u64 __attribute__((aligned(4))) compat_u64;
	#else
		typedef u64 compat_u64;
	#endif
#endif

#ifdef EFX_NEED___CPU_TO_LE32_CONSTANT_FIX
	#ifdef __BIG_ENDIAN
		#undef __cpu_to_le32
		#define __cpu_to_le32(x)		\
		(__builtin_constant_p((__u32)(x)) ?	\
		 ___constant_swab32((x)) :		\
		 __fswab32((x)))
	#endif
#endif

#ifdef EFX_NEED_BYTE_QUEUE_LIMITS
static inline void netdev_tx_sent_queue(struct netdev_queue *dev_queue,
					unsigned int bytes)
{}
static inline void netdev_tx_completed_queue(struct netdev_queue *dev_queue,
					     unsigned pkts, unsigned bytes)
{}
static inline void netdev_tx_reset_queue(struct netdev_queue *q) {}
#endif

#ifdef EFX_NEED_IS_COMPAT_TASK
	static inline int is_compat_task(void)
	{
	#if !defined(CONFIG_COMPAT)
		return 0;
	#elif defined(CONFIG_X86_64)
		return test_thread_flag(TIF_IA32);
	#elif defined(CONFIG_PPC64)
		return test_thread_flag(TIF_32BIT);
	#else
	#error "cannot define is_compat_task() for this architecture"
	#endif
	}
#endif

#ifdef EFX_NEED_SKB_CHECKSUM_NONE_ASSERT
static inline void skb_checksum_none_assert(const struct sk_buff *skb)
{
#ifdef DEBUG
	BUG_ON(skb->ip_summed != CHECKSUM_NONE);
#endif
}
#endif

#ifdef EFX_NEED_SKB_HEADER_CLONED
	/* This is a bit pessimistic but it's the best we can do */
	#define skb_header_cloned skb_cloned
#endif

#ifndef __read_mostly
	#define __read_mostly
#endif

#ifndef NETIF_F_HW_VLAN_CTAG_TX
	#define NETIF_F_HW_VLAN_CTAG_TX NETIF_F_HW_VLAN_TX
#endif

/**************************************************************************
 *
 * Missing functions provided by kernel_compat.c
 *
 **************************************************************************
 *
 */
#ifdef EFX_NEED_UNREGISTER_NETDEVICE_NOTIFIER_FIX
	/* unregister_netdevice_notifier() does not wait for the notifier
	 * to be unused before 2.6.17 */
	static inline int efx_unregister_netdevice_notifier(struct notifier_block *nb)
	{
		int res;

		res = unregister_netdevice_notifier(nb);
		rtnl_lock();
		rtnl_unlock();
		return res;
	}
	#define unregister_netdevice_notifier		 \
		efx_unregister_netdevice_notifier
#endif

#if defined(EFX_NEED_PRINT_MAC)
	extern char *print_mac(char *buf, const u8 *addr);
#endif

#ifdef EFX_NEED_COMPOUND_PAGE_FIX
	extern void efx_compound_page_destructor(struct page *page);
#endif

#ifdef EFX_NEED_HEX_DUMP
	extern void
	print_hex_dump(const char *level, const char *prefix_str,
		       int prefix_type, int rowsize, int groupsize,
		       const void *buf, size_t len, int ascii);
#endif

#ifdef EFX_NEED_PCI_CLEAR_MASTER
	extern void pci_clear_master(struct pci_dev *dev);
#endif

#ifdef EFX_NEED_PCI_WAKE_FROM_D3
	extern int pci_wake_from_d3(struct pci_dev *dev, bool enable);
#endif

#ifdef EFX_NEED_MDELAY
	#include <linux/delay.h>
	#undef mdelay
	#define mdelay(_n)				\
		do {					\
			unsigned long __ms = _n;	\
			while (__ms--) udelay(1000);	\
		} while (0);
#endif

#if (defined(EFX_NEED_UNMASK_MSIX_VECTORS) || \
     defined(EFX_NEED_SAVE_MSIX_MESSAGES)) && \
	!defined(EFX_HAVE_MSIX_TABLE_RESERVED)

	#if defined(EFX_NEED_SAVE_MSIX_MESSAGES)
		#include <linux/msi.h>
	#endif

	extern int efx_pci_save_state(struct pci_dev *dev);
	#define pci_save_state efx_pci_save_state

	extern void efx_pci_restore_state(struct pci_dev *dev);
	#define pci_restore_state efx_pci_restore_state

#endif

#if defined(EFX_NEED_NEW_CPUMASK_API)

	static inline void cpumask_clear(cpumask_t *dstp)
	{
		cpus_clear(*dstp);
	}

	static inline void cpumask_copy(cpumask_t *dstp, const cpumask_t *srcp)
	{
		*dstp = *srcp;
	}

	#define cpumask_test_cpu(cpu, mask) cpu_isset(cpu, *(mask))

	#define cpumask_set_cpu(cpu, mask) cpu_set(cpu, *(mask))

	static inline void cpumask_or(cpumask_t *dstp, const cpumask_t *src1p,
				      const cpumask_t *src2p)
	{
		cpus_or(*dstp, *src1p, *src2p);
	}

	static inline unsigned int cpumask_weight(const cpumask_t *srcp)
	{
		return cpus_weight(*srcp);
	}

	#undef for_each_cpu
	#define for_each_cpu(cpu, mask) for_each_cpu_mask(cpu, *(mask))

	#undef for_each_possible_cpu
	#define for_each_possible_cpu(CPU)			\
		for_each_cpu_mask((CPU), cpu_possible_map)

	typedef cpumask_t cpumask_var_t[1];

	static inline bool alloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
	{
		return true;
	}

	static inline bool zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
	{
		cpumask_clear(*mask);
		return true;
	}

	static inline void free_cpumask_var(cpumask_t *mask) {}

	#ifdef topology_core_siblings
		#define topology_core_cpumask(cpu)		\
			(&(topology_core_siblings(cpu)))
	#endif

	#ifdef topology_thread_siblings
		#define topology_thread_cpumask(cpu)		\
			(&(topology_thread_siblings(cpu)))
	#endif

	#if defined(cpumask_parse)
		#define cpumask_parse_user(ubuf, ulen, src)	 \
			__cpumask_parse(ubuf, ulen, src, NR_CPUS)
	#elif defined(cpumask_parse_user)
		#undef cpumask_parse_user
		#define cpumask_parse_user(ubuf, ulen, src)	\
			__cpumask_parse_user(ubuf, ulen, src, NR_CPUS)
	#endif

#elif defined(EFX_NEED_ZALLOC_CPUMASK_VAR)

	#ifdef CONFIG_CPUMASK_OFFSTACK
		static inline bool
		zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
		{
			return alloc_cpumask_var(mask, flags | __GFP_ZERO);
		}
	#else
		static inline bool
		zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
		{
			cpumask_clear(*mask);
			return true;
		}
	#endif

#endif

#ifndef EFX_HAVE_CPUMASK_OF_NODE
# ifdef node_to_cpumask_ptr
#  define cpumask_of_node(NODE)				\
	({						\
		node_to_cpumask_ptr(result, NODE);	\
		result;					\
	})
#  define EFX_HAVE_CPUMASK_OF_NODE yes
# elif LINUX_VERSION_CODE != KERNEL_VERSION(2,6,25)
#  define cpumask_of_node(NODE) &(node_to_cpumask(NODE))
#  define EFX_HAVE_CPUMASK_OF_NODE yes
# endif
#endif

#if defined(EFX_NEED_SET_CPUS_ALLOWED_PTR) && !defined(set_cpus_allowed_ptr)
	/* kernel_compat.sh uses nexport for set_cpus_allowed_ptr() because of
	 * redhat backport madness, but on !SMP machines it's a macro */
	#define set_cpus_allowed_ptr efx_set_cpus_allowed_ptr
	static inline int efx_set_cpus_allowed_ptr(struct task_struct *p,
						   const cpumask_t *new_mask)
	{
	#if !defined(CONFIG_SMP)
		/* Don't use set_cpus_allowed() if present, because 2.6.11-2.6.15
		 * define it using an unexported symbol */
		if (!cpu_isset(0, *new_mask))
			return -EINVAL;
		return 0;
	#else
       		return set_cpus_allowed(p, *new_mask);
	#endif
	}
#endif

#ifdef EFX_NEED_KOBJECT_INIT_AND_ADD
	#define kobject_init_and_add efx_kobject_init_and_add
	extern int
	efx_kobject_init_and_add(struct kobject *kobj, struct kobj_type *ktype,
	 			 struct kobject *parent, const char *fmt, ...);
#endif

#ifdef EFX_NEED_KOBJECT_SET_NAME_VARGS
	#define kobject_set_name_vargs efx_kobject_set_name_vargs
	extern int
	efx_kobject_set_name_vargs(struct kobject *kobj, const char *fmt, va_list vargs);
#endif


/**************************************************************************
 *
 * Wrappers to fix bugs and parameter changes
 *
 **************************************************************************
 *
 */
#ifdef EFX_NEED_PCI_SAVE_RESTORE_WRAPPERS
	#define pci_save_state(_dev)					\
		pci_save_state(_dev, (_dev)->saved_config_space)

	#define pci_restore_state(_dev)					\
		pci_restore_state(_dev, (_dev)->saved_config_space)
#endif

#ifdef EFX_NEED_PCI_MATCH_ID
	#define pci_match_id pci_match_device
#endif

#ifdef EFX_NEED_WORK_API_WRAPPERS
	#define delayed_work work_struct
	#undef INIT_DELAYED_WORK
	#define INIT_DELAYED_WORK INIT_WORK
	#undef EFX_USE_CANCEL_DELAYED_WORK_SYNC /* we can't */

	/**
	 * The old and new work-function prototypes just differ
	 * in the type of the pointer returned, so it's safe
	 * to cast between the prototypes.
	 */
	typedef void (*efx_old_work_func_t)(void *p);

	#undef INIT_WORK
	#define INIT_WORK(_work, _func)					\
		do {							\
			INIT_LIST_HEAD(&(_work)->entry);		\
			(_work)->pending = 0;				\
			PREPARE_WORK((_work),				\
				     (efx_old_work_func_t) (_func),	\
				     (_work));				\
	                init_timer(&(_work)->timer);                    \
		} while (0)
#endif

#if defined(EFX_HAVE_OLD_NAPI)

	#ifndef EFX_USE_GRO
		struct efx_napi_dummy {};
		#define napi_struct efx_napi_dummy
		#define napi_gro_flush(napi)
	#endif

	static inline void netif_napi_add(struct net_device *dev,
					  struct napi_struct *napi,
					  int (*poll) (struct net_device *,
						       int *),
					  int weight)
	{
		INIT_LIST_HEAD(&dev->poll_list);
		dev->weight = weight;
		dev->poll = poll;
		set_bit(__LINK_STATE_RX_SCHED, &dev->state);
	}
	static inline void netif_napi_del(struct napi_struct *napi) {}

	#define efx_napi_get_device(napi)				\
		(container_of(napi, struct efx_channel, napi_str)->napi_dev)

	#define napi_enable(napi) netif_poll_enable(efx_napi_get_device(napi))
	#define napi_disable(napi) netif_poll_disable(efx_napi_get_device(napi))
	#define napi_complete(napi)					\
		do {							\
			napi_gro_flush(napi);				\
			netif_rx_complete(efx_napi_get_device(napi));	\
		} while (0)

	static inline void efx_napi_schedule(struct net_device *dev)
	{
		if (!test_and_set_bit(__LINK_STATE_RX_SCHED, &dev->state))
			__netif_rx_schedule(dev);
	}
	#define napi_schedule(napi)					\
		efx_napi_schedule(efx_napi_get_device(napi))

#elif defined(EFX_NEED_NETIF_NAPI_DEL)
	static inline void netif_napi_del(struct napi_struct *napi)
	{
	#ifdef CONFIG_NETPOLL
        	list_del(&napi->dev_list);
	#endif
	}
#endif

#if defined(EFX_USE_GRO) && defined(EFX_HAVE_NAPI_GRO_RECEIVE_GR)
	/* Redhat backports of functions returning gro_result_t */
	#define napi_gro_frags napi_gro_frags_gr
	#define napi_gro_receive napi_gro_receive_gr
#elif defined(EFX_USE_GRO) && defined(EFX_NEED_GRO_RESULT_T)
	typedef int gro_result_t;

	#define napi_gro_frags(_napi)				\
		({ napi_gro_frags(_napi);			\
		   GRO_MERGED; })
	#define napi_gro_receive(_napi, _skb)			\
		({ napi_gro_receive(_napi, _skb);		\
		   GRO_MERGED; })
#endif
#if defined(EFX_USE_GRO) && (defined(EFX_HAVE_NAPI_GRO_RECEIVE_GR) || defined(EFX_NEED_GRO_RESULT_T))
	/* vlan_gro_{frags,receive} won't return gro_result_t in
	 * either of the above cases.
	 */
	#define vlan_gro_frags(_napi, _group, _tag)		\
		({ vlan_gro_frags(_napi, _group, _tag);		\
		   GRO_MERGED; })
	#define vlan_gro_receive(_napi, _group, _tag, _skb)	\
		({ vlan_gro_receive(_napi, _group, _tag, _skb);	\
		   GRO_MERGED; })
#endif

#ifdef EFX_NEED_COMPOUND_PAGE_FIX
	static inline
	struct page *efx_alloc_pages(gfp_t flags, unsigned int order)
	{
		struct page *p = alloc_pages(flags, order);
		if ((flags & __GFP_COMP) && (p != NULL) && (order > 0))
			p[1].mapping = (void *)efx_compound_page_destructor;
		return p;
	}
	#undef alloc_pages
	#define alloc_pages efx_alloc_pages

	static inline
	void efx_free_pages(struct page *p, unsigned int order)
	{
		if ((order > 0) && (page_count(p) == 1))
			p[1].mapping = NULL;
		__free_pages(p, order);
	}
	#define __free_pages efx_free_pages
#endif

#ifdef EFX_NEED_HEX_DUMP_CONST_FIX
	#define print_hex_dump(v,s,t,r,g,b,l,a) \
		print_hex_dump((v),(s),(t),(r),(g),(void*)(b),(l),(a))
#endif

#ifndef EFX_HAVE_HWMON_H
	static inline struct device *hwmon_device_register(struct device *dev)
	{
		return dev;
	}
	static inline void hwmon_device_unregister(struct device *cdev)
	{
	}
#endif

#ifdef EFX_NEED_HWMON_VID
	#include <linux/i2c-vid.h>
	static inline u8 efx_vid_which_vrm(void)
	{
		/* we don't use i2c on the cpu */
		return 0;
	}
	#define vid_which_vrm efx_vid_which_vrm
#endif

#ifdef EFX_HAVE_OLD_DEVICE_ATTRIBUTE
	/*
	 * show and store methods do not receive a pointer to the
	 * device_attribute.  We have to add wrapper functions.
	 */

	#undef DEVICE_ATTR
	#define DEVICE_ATTR(_name, _mode, _show, _store)		\
		/*static*/ ssize_t __##_name##_##show(struct device *dev, \
						      char *buf)	\
		{							\
			ssize_t (*fn)(struct device *dev,		\
				      struct device_attribute *attr,	\
				      char *buf) = _show;		\
			return fn ? fn(dev, NULL, buf) : 0;		\
		}							\
		static ssize_t __##_name##_##store(struct device *dev,	\
						   const char *buf,	\
						   size_t count)	\
		{							\
			ssize_t (*fn)(struct device *dev,		\
				      struct device_attribute *attr,	\
				      const char *buf,			\
				      size_t count) = _store;		\
			return fn ? fn(dev, NULL, buf, count) : 0;	\
		}							\
		static struct device_attribute dev_attr_##_name =	\
			__ATTR(_name, _mode, __##_name##_##show,	\
			       __##_name##_##store)

	struct sensor_device_attribute {
		struct device_attribute dev_attr;
		int index;
	};

	#define SENSOR_ATTR(_name, _mode, _show, _store, _index)        \
	{ .dev_attr = __ATTR(_name, _mode, _show, _store),		\
	  .index = _index }

	#define SENSOR_DEVICE_ATTR(_name, _mode, _show,	\
				   _store, _index)			\
		/*static*/ ssize_t __##_name##_show_##_index(struct device *dev, \
							     char *buf)	\
		{							\
			struct sensor_device_attribute attr;		\
			attr.index = _index;				\
			return _show(dev, &attr.dev_attr, buf);		\
		}							\
		static ssize_t __##_name##_store_##_index(struct device *dev, \
							  const char *buf, \
							  size_t count)	\
		{							\
			ssize_t (*fn)(struct device *dev,		\
				      struct device_attribute *attr,	\
				      const char *buf,			\
				      size_t count) = _store;		\
			struct sensor_device_attribute attr;		\
			attr.index = _index;				\
			return fn(dev, &attr.dev_attr, buf, count);	\
		}							\
		static ssize_t __##_name##_store_##_index(struct device *, \
							  const char *, size_t) \
			__attribute__((unused));			\
		static struct sensor_device_attribute			\
			sensor_dev_attr_##_name =			\
			SENSOR_ATTR(_name, _mode,			\
				    __##_name##_show_##_index,		\
				    __builtin_choose_expr		\
				    (__builtin_constant_p(_store) && _store == NULL, \
				     NULL, __##_name##_store_##_index), \
				    _index)

	#define to_sensor_dev_attr(_dev_attr) \
		container_of(_dev_attr, struct sensor_device_attribute,	\
			     dev_attr)

#endif


#ifdef EFX_NEED_SCSI_SGLIST
	#include <scsi/scsi.h>
	#include <scsi/scsi_cmnd.h>
	#define scsi_sglist(sc)    ((struct scatterlist *)((sc)->request_buffer))
	#define scsi_bufflen(sc)   ((sc)->request_bufflen)
	#define scsi_sg_count(sc)  ((sc)->use_sg)
	static inline void scsi_set_resid(struct scsi_cmnd *sc, int resid)
	{
		sc->resid = resid;
	}
	static inline int scsi_get_resid(struct scsi_cmnd *sc)
	{
		return sc->resid;
	}
#endif


#ifdef EFX_NEED_SG_NEXT
	#define sg_page(sg) ((sg)->page)
	#define sg_next(sg) ((sg) + 1)
	#define for_each_sg(sglist, sg, nr, __i) \
	  for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))
#endif

#ifdef EFX_NEED_WARN_ON
	#undef WARN_ON
	#define WARN_ON(condition) ({				\
		typeof(condition) __ret_warn_on = (condition);	\
		if (unlikely(__ret_warn_on)) {			\
			printk("BUG: warning at %s:%d/%s()\n",	\
			__FILE__, __LINE__, __FUNCTION__);	\
				dump_stack();			\
		}						\
		unlikely(__ret_warn_on);			\
	})
#endif

#ifdef EFX_NEED_VMALLOC_NODE
	static inline void *vmalloc_node(unsigned long size, int node)
	{
		return vmalloc(size);
	}
#endif

#ifdef EFX_NEED_VMALLOC_TO_PFN
	static inline unsigned long vmalloc_to_pfn(const void *addr)
	{
		return page_to_pfn(vmalloc_to_page((void*)addr));
	}
#endif

#ifdef EFX_NEED_KVEC
	struct kvec {
		struct iovec iov;
	};
#endif

#ifdef EFX_NEED_KERNEL_SENDMSG
	static inline int kernel_sendmsg(struct socket *sock,
					 struct msghdr *msg,
					 struct kvec *vec, size_t num,
					 size_t size)
	{
		mm_segment_t oldfs = get_fs();
		int result;

		set_fs(KERNEL_DS);
		/* the following is safe, since for compiler definitions of
		 * kvec and iovec are identical, yielding the same in-core
		 * layout and alignment. */
		msg->msg_iov = (struct iovec *)vec;
		msg->msg_iovlen = num;
		result = sock_sendmsg(sock, msg, size);
		set_fs(oldfs);
		return result;
	}
#endif

#ifdef EFX_NEED_ROUNDDOWN_POW_OF_TWO
static inline unsigned long __attribute_const__ rounddown_pow_of_two(unsigned long x)
{
	return 1UL << (fls(x) - 1);
}
#endif

#ifndef order_base_2
#define order_base_2(x) fls((x) - 1)
#endif

#ifdef EFX_NEED_ON_EACH_CPU_WRAPPER
static inline int efx_on_each_cpu(void (*func) (void *info), void *info, int wait)
{
	return on_each_cpu(func, info, 0, wait);
}
#undef on_each_cpu
#define on_each_cpu efx_on_each_cpu
#endif

#ifndef EFX_HAVE_LIST_SPLICE_TAIL_INIT
	static inline void list_splice_tail_init(struct list_head *list,
						 struct list_head *head)
	{
		if (!list_empty(list)) {
			struct list_head *first = list->next;
			struct list_head *last = list->prev;
			struct list_head *prev = head->prev;

			first->prev = prev;
			prev->next = first;
			last->next = head;
			head->prev = last;

			INIT_LIST_HEAD(list);
		}
	}
#endif

#ifdef EFX_NEED_NETIF_DEVICE_DETACH_ATTACH_MQ
	static inline void efx_netif_device_detach(struct net_device *dev)
	{
		if (test_and_clear_bit(__LINK_STATE_PRESENT, &dev->state) &&
		    netif_running(dev)) {
			netif_tx_stop_all_queues(dev);
		}
	}
	#define netif_device_detach efx_netif_device_detach

	static inline void efx_netif_device_attach(struct net_device *dev)
	{
		/* __netdev_watchdog_up() is not exported, so we have
		 * to call the broken implementation and then start
		 * the remaining queues.
		 */
		if (!test_bit(__LINK_STATE_PRESENT, &dev->state) &&
		    netif_running(dev)) {
			netif_device_attach(dev);
			netif_tx_wake_all_queues(dev);
		}
	}
	#define netif_device_attach efx_netif_device_attach
#endif

#ifdef EFX_NEED___SKB_QUEUE_HEAD_INIT
	static inline void __skb_queue_head_init(struct sk_buff_head *list)
	{
		list->prev = list->next = (struct sk_buff *)list;
		list->qlen = 0;
	}
#endif

#ifdef EFX_NEED_LIST_FIRST_ENTRY
	#define list_first_entry(ptr, type, member) \
 		list_entry((ptr)->next, type, member)
#endif

#ifdef EFX_NEED_SKB_COPY_FROM_LINEAR_DATA
	static inline void skb_copy_from_linear_data(const struct sk_buff *skb,
			void *to, const unsigned int len)
		{
			memcpy(to, skb->data, len);
		}
#endif

#ifdef EFX_NEED_NS_TO_TIMESPEC
	struct timespec ns_to_timespec(const s64 nsec);
#endif

#ifndef EFX_NEED_KTIME
	#include <linux/ktime.h>
#else
	typedef union {
		s64	tv64;
	#if BITS_PER_LONG != 64
	        struct {
	# ifdef __BIG_ENDIAN
	        s32	sec, nsec;
	# else
	        s32	nsec, sec;
	# endif
		} tv;
	#endif
	} ktime_t;

	#if BITS_PER_LONG == 64

	static inline ktime_t
	ktime_set(const long secs, const unsigned long nsecs)
	{
        	return (ktime_t) { .tv64 = ((s64)secs * NSEC_PER_SEC +
					    (s64)nsecs) };
	}

	#define ktime_sub(lhs, rhs)					\
		({ (ktime_t){ .tv64 = (lhs).tv64 - (rhs).tv64 }; })

	#define ktime_add(lhs, rhs)					\
                ({ (ktime_t){ .tv64 = (lhs).tv64 + (rhs).tv64 }; })

	#define ktime_to_timespec(kt)		ns_to_timespec((kt).tv64)

	#define ktime_to_ns(kt)			((kt).tv64)

	#else /* BITS_PER_LONG == 32 */

	static inline ktime_t
	ktime_set(const long secs, const unsigned long nsecs)
	{
        	return (ktime_t) { .tv = { .sec = secs, .nsec = nsecs } };
	}

	static inline ktime_t ktime_sub(const ktime_t lhs, const ktime_t rhs)
	{
        	ktime_t res;

	        res.tv64 = lhs.tv64 - rhs.tv64;
        	if (res.tv.nsec < 0)
                	res.tv.nsec += NSEC_PER_SEC;

	        return res;
	}

	static inline ktime_t ktime_add(const ktime_t add1, const ktime_t add2)
	{
        	ktime_t res;

	        res.tv64 = add1.tv64 + add2.tv64;
	        /*
	         * performance trick: the (u32) -NSEC gives 0x00000000Fxxxxxxx
	         * so we subtract NSEC_PER_SEC and add 1 to the upper 32 bit.
		 *
		 * it's equivalent to:
		 *   tv.nsec -= NSEC_PER_SEC
		 *   tv.sec ++;
		 */
		if (res.tv.nsec >= NSEC_PER_SEC)
			res.tv64 += (u32)-NSEC_PER_SEC;

		return res;
	}

	static inline struct timespec ktime_to_timespec(const ktime_t kt)
	{
        	return (struct timespec) { .tv_sec = (time_t) kt.tv.sec,
                	                   .tv_nsec = (long) kt.tv.nsec };
	}

	static inline u64 ktime_to_ns(const ktime_t kt)
	{
        	return (u64) kt.tv.sec * NSEC_PER_SEC + kt.tv.nsec;
	}

	#endif /* BITS_PER_LONG */
#endif

#ifdef EFX_HAVE_NET_TSTAMP
	#include <linux/net_tstamp.h>
#else
	#include <linux/in.h>
	#include <linux/ip.h>
	#include <linux/udp.h>
	/**
	 * struct efx_ptp_timestamp - Time stamps of received packets.
	 * @hwtstamp: Hardware (NIC) timestamp
	 * @syststamp: System timestamp
	 */
	struct skb_shared_hwtstamps {
		ktime_t	hwtstamp;
		ktime_t	syststamp;
	};

	static inline struct skb_shared_hwtstamps * skb_hwtstamps(struct sk_buff *skb)
	{
		return (struct skb_shared_hwtstamps *) skb->cb;
	}
#endif

#ifdef EFX_NEED_TIMESPEC_ADD_NS
	static inline void timespec_add_ns(struct timespec *a, u64 ns)
	{
		ns += a->tv_nsec;
		while(unlikely(ns >= NSEC_PER_SEC)) {
			ns -= NSEC_PER_SEC;
			a->tv_sec++;
		}
		a->tv_nsec = ns;
	}
#endif
#ifdef EFX_NEED_TIMESPEC_SUB
	static inline struct timespec timespec_sub(struct timespec lhs,
		struct timespec rhs)
	{
		struct timespec ts_delta;
		set_normalized_timespec(&ts_delta, lhs.tv_sec - rhs.tv_sec,
		lhs.tv_nsec - rhs.tv_nsec);
		return ts_delta;
	}

#endif

#ifdef EFX_NEED_TIMESPEC_COMPARE
	static inline int
	timespec_compare(struct timespec *lhs, struct timespec *rhs)
	{
		if (lhs->tv_sec < rhs->tv_sec)
			return -1;
		if (lhs->tv_sec > rhs->tv_sec)
			return 1;
		return lhs->tv_nsec - rhs->tv_nsec;
	}
#endif

#ifdef EFX_HAVE_OLD_SKB_LINEARIZE
	static inline int efx_skb_linearize(struct sk_buff *skb)
	{
		return skb_linearize(skb, GFP_ATOMIC);
	}
	#define skb_linearize efx_skb_linearize
#endif

#ifdef EFX_HAVE_OLD_SKB_CHECKSUM_HELP
	static inline int efx_skb_checksum_help(struct sk_buff *skb)
	{
		return skb_checksum_help(skb, 0);
	}
	#define skb_checksum_help efx_skb_checksum_help
#endif

#ifdef EFX_HAVE_OLDER_SKB_CHECKSUM_HELP
	static inline int efx_skb_checksum_help(struct sk_buff *skb)
	{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
		/* No way we can wrap around this behaviour */
		#error "skb_checksum_help() may reallocate skb"
	#endif
		return skb_checksum_help(&skb, 0);
	}
	#define skb_checksum_help efx_skb_checksum_help
#endif

#ifndef EFX_HAVE_FDTABLE
#define fdtable files_struct
#define files_fdtable(files) (files)
#endif

#ifndef EFX_HAVE_REMAP_PFN_RANGE
#define remap_pfn_range remap_page_range
#endif

#ifdef EFX_NEED_GETNSTIMEOFDAY
	static inline void efx_getnstimeofday(struct timespec *tv)
	{
		struct timeval x;
		do_gettimeofday(&x);
		tv->tv_sec = x.tv_sec;
		tv->tv_nsec = x.tv_usec * NSEC_PER_USEC;
	}
#define getnstimeofday efx_getnstimeofday
#endif

#ifdef EFX_HAVE_PARAM_BOOL_INT
	#define param_ops_bool efx_param_ops_bool
	extern int efx_param_set_bool(const char *val, struct kernel_param *kp);
	#define param_set_bool efx_param_set_bool
	extern int efx_param_get_bool(char *buffer, struct kernel_param *kp);
	#define param_get_bool efx_param_get_bool
	#undef param_check_bool
	#define param_check_bool(name, p) __param_check(name, p, bool)
#endif

#ifdef EFX_HAVE_OLD___VLAN_PUT_TAG
	static inline struct sk_buff *
	efx___vlan_put_tag(struct sk_buff *skb, __be16 vlan_proto, u16 vlan_tci)
	{
		WARN_ON(vlan_proto != htons(ETH_P_8021Q));
		return __vlan_put_tag(skb, vlan_tci);
	}
	#define __vlan_put_tag efx___vlan_put_tag
#endif

#ifdef EFX_NEED_PCI_VPD_LRDT

#define PCI_VPD_LRDT                    0x80    /* Large Resource Data Type */
#define PCI_VPD_LRDT_ID(x)              (x | PCI_VPD_LRDT)

/* Large Resource Data Type Tag Item Names */
#define PCI_VPD_LTIN_ID_STRING          0x02    /* Identifier String */
#define PCI_VPD_LTIN_RO_DATA            0x10    /* Read-Only Data */
#define PCI_VPD_LTIN_RW_DATA            0x11    /* Read-Write Data */

#define PCI_VPD_LRDT_ID_STRING          PCI_VPD_LRDT_ID(PCI_VPD_LTIN_ID_STRING)
#define PCI_VPD_LRDT_RO_DATA            PCI_VPD_LRDT_ID(PCI_VPD_LTIN_RO_DATA)
#define PCI_VPD_LRDT_RW_DATA            PCI_VPD_LRDT_ID(PCI_VPD_LTIN_RW_DATA)

/* Small Resource Data Type Tag Item Names */
#define PCI_VPD_STIN_END                0x78    /* End */

#define PCI_VPD_SRDT_END                PCI_VPD_STIN_END

#define PCI_VPD_SRDT_TIN_MASK           0x78
#define PCI_VPD_SRDT_LEN_MASK           0x07

#define PCI_VPD_LRDT_TAG_SIZE           3
#define PCI_VPD_SRDT_TAG_SIZE           1

#define PCI_VPD_INFO_FLD_HDR_SIZE       3

#define PCI_VPD_RO_KEYWORD_PARTNO       "PN"
#define PCI_VPD_RO_KEYWORD_MFR_ID       "MN"
#define PCI_VPD_RO_KEYWORD_VENDOR0      "V0"
#define PCI_VPD_RO_KEYWORD_CHKSUM       "RV"

static inline u16 efx_pci_vpd_lrdt_size(const u8 *lrdt)
{
	return (u16)lrdt[1] + ((u16)lrdt[2] << 8);
}
#undef pci_vpd_lrdt_size
#define pci_vpd_lrdt_size efx_pci_vpd_lrdt_size

static inline u8 efx_pci_vpd_srdt_size(const u8 *srdt)
{
	return (*srdt) & PCI_VPD_SRDT_LEN_MASK;
}
#undef pci_vpd_srdt_size
#define pci_vpd_srdt_size efx_pci_vpd_srdt_size

static inline u8 efx_pci_vpd_info_field_size(const u8 *info_field)
{
	return info_field[2];
}
#undef pci_vpd_info_field_size
#define pci_vpd_info_field_size efx_pci_vpd_info_field_size

int efx_pci_vpd_find_tag(const u8 *buf, unsigned int off, unsigned int len, u8 rdt);
#undef pci_vpd_find_tag
#define pci_vpd_find_tag efx_pci_vpd_find_tag

int efx_pci_vpd_find_info_keyword(const u8 *buf, unsigned int off,
				  unsigned int len, const char *kw);
#undef pci_vpd_find_info_keyword
#define pci_vpd_find_info_keyword efx_pci_vpd_find_info_keyword

#endif /* EFX_NEED_PCI_VPD_LRDT */

#ifdef EFX_NEED_PCI_READ_VPD
ssize_t efx_pci_read_vpd(struct pci_dev *dev, loff_t pos, size_t count, void *buf);
#undef pci_read_vpd
#define pci_read_vpd efx_pci_read_vpd
#endif

#if defined(EFX_HAVE_FDTABLE_PARTIAL_ACCESSORS) && !defined(EFX_HAVE_FDTABLE_FULL_ACCESSORS)
#include <linux/fdtable.h>
static inline void efx_set_close_on_exec(int fd, struct fdtable *fdt)
{
	__set_bit(fd, fdt->close_on_exec);
}

static inline void efx_clear_close_on_exec(int fd, struct fdtable *fdt)
{
	__clear_bit(fd, fdt->close_on_exec);
}

static inline bool efx_close_on_exec(int fd, const struct fdtable *fdt)
{
	return close_on_exec(fd, fdt);
}

static inline void efx_set_open_fd(int fd, struct fdtable *fdt)
{
	__set_bit(fd, fdt->open_fds);
}

static inline void efx_clear_open_fd(int fd, struct fdtable *fdt)
{
	__clear_bit(fd, fdt->open_fds);
}

static inline bool efx_fd_is_open(int fd, const struct fdtable *fdt)
{
	return fd_is_open(fd, fdt);
}

static inline unsigned long efx_get_open_fds(int fd, const struct fdtable *fdt)
{
	return fdt->open_fds[fd];
}
#elif defined(EFX_HAVE_FDTABLE_FULL_ACCESSORS)
#include <linux/fdtable.h>
static inline void efx_set_close_on_exec(int fd, struct fdtable *fdt)
{
	__set_close_on_exec(fd, fdt);
}

static inline void efx_clear_close_on_exec(int fd, struct fdtable *fdt)
{
	__clear_close_on_exec(fd, fdt);
}

static inline bool efx_close_on_exec(int fd, const struct fdtable *fdt)
{
	return close_on_exec(fd, fdt);
}

static inline void efx_set_open_fd(int fd, struct fdtable *fdt)
{
	__set_open_fd(fd, fdt);
}

static inline void efx_clear_open_fd(int fd, struct fdtable *fdt)
{
	__clear_open_fd(fd, fdt);
}

static inline bool efx_fd_is_open(int fd, const struct fdtable *fdt)
{
	return fd_is_open(fd, fdt);
}

static inline unsigned long efx_get_open_fds(int fd, const struct fdtable *fdt)
{
	return fdt->open_fds[fd];
}
#else
#ifdef EFX_HAVE_FDTABLE_H
#include <linux/fdtable.h>
#else
#include <linux/file.h>
#endif
static inline void efx_set_close_on_exec(unsigned long fd, struct fdtable *fdt)
{
	FD_SET(fd, fdt->close_on_exec);
}

static inline void efx_clear_close_on_exec(unsigned long fd, struct fdtable *fdt)
{
	FD_CLR(fd, fdt->close_on_exec);
}

static inline bool efx_close_on_exec(unsigned long fd, const struct fdtable *fdt)
{
	return FD_ISSET(fd, fdt->close_on_exec);
}

static inline void efx_set_open_fd(unsigned long fd, struct fdtable *fdt)
{
	FD_SET(fd, fdt->open_fds);
}

static inline void efx_clear_open_fd(unsigned long fd, struct fdtable *fdt)
{
	FD_CLR(fd, fdt->open_fds);
}

static inline bool efx_fd_is_open(unsigned long fd, const struct fdtable *fdt)
{
	return FD_ISSET(fd, fdt->open_fds);
}

static inline unsigned long efx_get_open_fds(unsigned long fd, const struct fdtable *fdt)
{
	return fdt->open_fds->fds_bits[fd];
}
#endif

#ifdef EFX_HAVE_ASM_SYSTEM_H
#include <asm/system.h>
#endif

#ifdef EFX_NEED_SKB_FRAG_ADDRESS
static inline void *skb_frag_address(const skb_frag_t *frag)
{
	return page_address(frag->page) + frag->page_offset;
}
#endif

#ifdef EFX_HAVE_PPS_KERNEL
        #include <linux/pps_kernel.h>
#endif

#ifdef EFX_NEED_PPS_EVENT_TIME
	struct pps_event_time {
	#ifdef CONFIG_NTP_PPS
		struct timespec ts_raw;
	#endif /* CONFIG_NTP_PPS */
		struct timespec ts_real;
	};
#endif

#ifdef EFX_NEED_PPS_GET_TS
#ifdef CONFIG_NTP_PPS
	static inline void pps_get_ts(struct pps_event_time *ts)
	{
		getnstime_raw_and_real(&ts->ts_raw, &ts->ts_real);
	}
#else /* CONFIG_NTP_PPS */
	static inline void pps_get_ts(struct pps_event_time *ts)
	{
		getnstimeofday(&ts->ts_real);
	}
#endif /* CONFIG_NTP_PPS */
#endif

#ifdef EFX_NEED_PPS_SUB_TS
	static inline void pps_sub_ts(struct pps_event_time *ts, struct timespec delta)
	{
		ts->ts_real = timespec_sub(ts->ts_real, delta);
	#ifdef CONFIG_NTP_PPS
		ts->ts_raw = timespec_sub(ts->ts_raw, delta);
	#endif
	}
#endif

#ifndef EFX_HAVE_PHC_SUPPORT
	struct ptp_clock_time {
		__s64 sec;
		__u32 nsec;
		__u32 reserved;
	};

	struct ptp_extts_request {
		unsigned int index;
		unsigned int flags;
		unsigned int rsv[2];
	};

	struct ptp_perout_request {
		struct ptp_clock_time start;
		struct ptp_clock_time period;
		unsigned int index;
		unsigned int flags;
		unsigned int rsv[4];
	};

	struct ptp_clock_request {
		enum {
			PTP_CLK_REQ_EXTTS,
			PTP_CLK_REQ_PEROUT,
			PTP_CLK_REQ_PPS,
		} type;
		union {
			struct ptp_extts_request extts;
			struct ptp_perout_request perout;
		};
	};

	struct ptp_clock_info {
		struct module *owner;
		char name[16];
		s32 max_adj;
		int n_alarm;
		int n_ext_ts;
		int n_per_out;
		int pps;
		int (*adjfreq)(struct ptp_clock_info *ptp, s32 delta);
		int (*adjtime)(struct ptp_clock_info *ptp, s64 delta);
		int (*gettime)(struct ptp_clock_info *ptp, struct timespec *ts);
		int (*settime)(struct ptp_clock_info *ptp, const struct timespec *ts);
		int (*enable)(struct ptp_clock_info *ptp,
				struct ptp_clock_request *request, int on);
	};
#else
#include <linux/ptp_clock_kernel.h>
#endif

#ifdef EFX_NEED_PTP_PPS_USR
#define PTP_CLOCK_PPSUSR (PTP_CLOCK_PPS + 1)
#endif

#ifdef EFX_NEED_LE_BIT_OPS
static inline void set_bit_le(unsigned nr, unsigned char *addr)
{
	addr[nr / 8] |= (1 << (nr % 8));
}

static inline void clear_bit_le(unsigned nr, unsigned char *addr)
{
	addr[nr / 8] &= ~(1 << (nr % 8));
}
#endif

#endif /* EFX_KERNEL_COMPAT_H */
