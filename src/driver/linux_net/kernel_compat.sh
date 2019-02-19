#!/bin/bash -eu
######################################################################

me=$(basename "$0")

err  () { echo >&2 "$*";    }
log  () { err "$me: $*";    }
vlog () { $verbose && err "$me: $*"; }
fail () { log "$*"; exit 1; }
try  () { "$@" || fail "'$*' failed"; }
vmsg () { $quiet || log "$@"; }

function usage()
{
    err
    err "usage:"
    err "  $me [options] <symbol1> <symbol2>"
    err
    err "description:"
    err "  Produce a list of kernel compatability macros to match the "
    err "  kernel_compat.c and kernel_compat.h files"
    err
    err "options:"
    err "  -k KPATH        -- Specify the path to the kernel build source tree"
    err "                     defaults to /lib/modules/VERSION/build"
    err "  -r VERSION      -- Specify the kernel version instead to test"
    err '                     defaults to `uname -r`'
    err "  -a ARCH         -- Set the architecture to ARCH"
    err "                     defaults to `uname -m`"
    err "  -m MAP          -- Specify a System map for the build kernel."
    err "                     By default will look in KPATH and /boot"
    err "  -q              -- Quieten the checks"
    err "  -v              -- Verbose output"
    err "  -s              -- Symbol list to use"
    err "  <symbol>        -- Symbol to evaluate."
    err "                     By default every symbol is evaluated"

}

######################################################################
# Symbol definition map

function generate_kompat_symbols() {
    echo "
EFX_HAVE_MTD_TABLE			kver	<	2.6.35
EFX_HAVE_VMALLOC_REG_DUMP_BUF		kver	>=	2.6.37
EFX_USE_ETHTOOL_OP_GET_LINK		kver	>=	2.6.38
EFX_WANT_NDO_POLL_CONTROLLER		kver	<	4.19
EFX_NEED_ROOT_DEVICE_REGISTER		nsymbol root_device_register	include/linux/device.h
EFX_HAVE_GRO				custom
EFX_NEED_GRO_RESULT_T			nsymbol	gro_result_t		include/linux/netdevice.h
EFX_HAVE_NAPI_GRO_RECEIVE_GR		symbol	napi_gro_receive_gr	include/linux/netdevice.h
EFX_HAVE_NAPI_GRO_BITMASK		member	struct_napi_struct	gro_bitmask	include/linux/netdevice.h
EFX_NEED_HEX_DUMP			nexport	print_hex_dump		include/linux/kernel.h include/linux/printk.h lib/hexdump.c
EFX_NEED_HEX_DUMP_CONST_FIX 		symtype	print_hex_dump		include/linux/kernel.h void(const char *, const char *, int, int, int, void *, size_t, bool)
EFX_NEED_VZALLOC			nsymbol	vzalloc			include/linux/vmalloc.h
EFX_NEED_MII_ADVERTISE_FLOWCTRL		nsymbol	mii_advertise_flowctrl	include/linux/mii.h
EFX_NEED_MII_RESOLVE_FLOWCTRL_FDX	nsymbol	mii_resolve_flowctrl_fdx include/linux/mii.h
EFX_HAVE_LINUX_MDIO_H			file				include/linux/mdio.h
EFX_NEED_MTD_DEVICE_REGISTER		nsymbol	mtd_device_register	include/linux/mtd/mtd.h
EFX_HAVE_MTD_DIRECT_ACCESS              custom
EFX_NEED_NETDEV_ALLOC_SKB		nsymbol	netdev_alloc_skb	include/linux/skbuff.h
EFX_NEED_SKB_COPY_FROM_LINEAR_DATA	nsymbol skb_copy_from_linear_data	include/linux/skbuff.h
EFX_NEED___SKB_QUEUE_HEAD_INIT		nsymbol __skb_queue_head_init	include/linux/skbuff.h
EFX_NEED_NETDEV_TX_T			nsymbol	netdev_tx_t		include/linux/netdevice.h
EFX_NEED_NETIF_NAPI_DEL			nsymbol	netif_napi_del		include/linux/netdevice.h
EFX_NEED_NETIF_TX_LOCK			nsymbol	netif_tx_lock		include/linux/netdevice.h
EFX_NEED_NETIF_ADDR_LOCK		nsymbol	netif_addr_lock		include/linux/netdevice.h
EFX_NEED_ALLOC_ETHERDEV_MQ		nsymbol	alloc_etherdev_mq	include/linux/etherdevice.h
EFX_NEED_NETIF_SET_REAL_NUM_TX_QUEUES	nsymbol	netif_set_real_num_tx_queues include/linux/netdevice.h
EFX_NEED_NETIF_SET_REAL_NUM_RX_QUEUES	nsymbol	netif_set_real_num_rx_queues include/linux/netdevice.h
EFX_NEED_PCI_CLEAR_MASTER		nsymbol	pci_clear_master	include/linux/pci.h
EFX_HAVE_PCI_RESET_FUNCTION		symbol	pci_reset_function	include/linux/pci.h
EFX_NEED_RESOURCE_SIZE_T		nsymbol resource_size_t		include/linux/types.h
EFX_NEED_RESOURCE_SIZE			nsymbol	resource_size		include/linux/ioport.h
EFX_NEED_RTNL_TRYLOCK			nsymbol	rtnl_trylock		include/linux/rtnetlink.h
EFX_HAVE_ROUND_JIFFIES_UP		symbol	round_jiffies_up	include/linux/timer.h
EFX_NEED_SKB_HEADER_MACROS		nsymbol	skb_mac_header		include/linux/skbuff.h
EFX_NEED_SKB_NETWORK_HEADER_LEN		nsymbol	skb_network_header_len	include/linux/skbuff.h
EFX_NEED_SKB_CHECKSUM_START_OFFSET	nsymbol	skb_checksum_start_offset	include/linux/skbuff.h
EFX_HAVE_CSUM_LEVEL			symbol	csum_level		include/linux/skbuff.h
EFX_HAVE_SKB_SET_TRANSPORT_HEADER	symbol	skb_set_transport_header	include/linux/skbuff.h
EFX_HAVE_OLD_SKB_HEADER_FIELDS		member	struct_sk_buff		h	include/linux/skbuff.h
EFX_HAVE_OLD_SKB_LINEARIZE		nsymtype skb_linearize		include/linux/skbuff.h int(struct sk_buff *)
EFX_HAVE_SKBTX_HW_TSTAMP		symbol	SKBTX_HW_TSTAMP		include/linux/skbuff.h
EFX_HAVE_SKB_SYSTSTAMP			member	struct_skb_shared_hwtstamps	syststamp	include/linux/skbuff.h
EFX_HAVE_SKB_TSTAMP_TX			symbol	skb_tstamp_tx		include/linux/skbuff.h
EFX_HAVE_SKB_TX_TIMESTAMP		symbol	skb_tx_timestamp	include/linux/skbuff.h
EFX_NEED_TCP_HDR			nsymbol	tcp_hdr			include/linux/tcp.h
EFX_NEED_UDP_HDR			nsymbol	udp_hdr			include/linux/udp.h
EFX_NEED_IP_HDR				nsymbol	ip_hdr			include/linux/ip.h
EFX_NEED_IPV6_HDR			nsymbol	ipv6_hdr		include/linux/ipv6.h
EFX_NEED_WORK_API_WRAPPERS		nmember	struct_delayed_work	timer	include/linux/workqueue.h
EFX_USE_CANCEL_DELAYED_WORK_SYNC	symbol	cancel_delayed_work_sync		include/linux/workqueue.h
EFX_USE_CANCEL_WORK_SYNC		symbol	cancel_work_sync	include/linux/workqueue.h
EFX_NEED_WQ_SYSFS			nsymbol	WQ_SYSFS		include/linux/workqueue.h
EFX_HAVE_ALLOC_WORKQUEUE		symbol	alloc_workqueue		include/linux/workqueue.h
EFX_HAVE_NEW_ALLOC_WORKQUEUE		custom
EFX_USE_ETHTOOL_ETH_TP_MDIX		symbol	eth_tp_mdix		include/linux/ethtool.h
EFX_USE_ETHTOOL_GET_PERM_ADDR		symbol	get_perm_addr		include/linux/ethtool.h
EFX_USE_ETHTOOL_FLAGS			symbol	get_flags		include/linux/ethtool.h
EFX_USE_ETHTOOL_LP_ADVERTISING		symbol	lp_advertising		include/linux/ethtool.h
EFX_USE_ETHTOOL_MDIO_SUPPORT		symbol	mdio_support		include/linux/ethtool.h
EFX_USE_LINUX_UACCESS_H			file				include/linux/uaccess.h
EFX_USE_MTD_WRITESIZE			symbol	writesize		include/linux/mtd/mtd.h
EFX_USE_NETDEV_DEV			member	struct_net_device	dev	include/linux/netdevice.h
EFX_USE_NETDEV_STATS			custom
EFX_USE_NETDEV_STATS64			member	struct_net_device_ops	ndo_get_stats64 include/linux/netdevice.h
EFX_HAVE_NETDEV_STATS64_VOID		memtype	struct_net_device_ops	ndo_get_stats64	include/linux/netdevice.h	void(*)(struct net_device *, struct rtnl_link_stats64 *)
EFX_USE_NETDEV_VLAN_FEATURES		symbol	vlan_features		include/linux/netdevice.h
EFX_HAVE_NET_DEVICE_UC			memtype	struct_net_device	uc	include/linux/netdevice.h	struct netdev_hw_addr_list
EFX_HAVE_NET_DEVICE_UC_LIST		symbol	uc_list			include/linux/netdevice.h
EFX_HAVE_NET_DEVICE_MC			memtype	struct_net_device	mc	include/linux/netdevice.h	struct netdev_hw_addr_list
EFX_HAVE_OLD_SKB_CHECKSUM_HELP		symtype	skb_checksum_help	include/linux/netdevice.h int(struct sk_buff *, int)
EFX_HAVE_HWMON_CLASS_DEVICE		symtype	hwmon_device_register	include/linux/hwmon.h struct class_device *(struct device *)
EFX_NEED_HWMON_T_ALARM			nsymbol	HWMON_T_ALARM		include/linux/hwmon.h
EFX_HAVE_HWMON_READ_STRING		member	struct_hwmon_ops	read_string	include/linux/hwmon.h
EFX_HAVE_HWMON_READ_STRING_CONST	memtype	struct_hwmon_ops	read_string	include/linux/hwmon.h	int(*)(struct device *, enum hwmon_sensor_types, u32, int, const char **)
EFX_HAVE_BIN_ATTRIBUTE_OP_FILE_PARAM	custom
EFX_USE_ETHTOOL_GET_SSET_COUNT		symbol	get_sset_count		include/linux/ethtool.h
# Do not use struct ethtool_ops_ext due to RH BZ 1008678 (SF bug 39031)
EFX_HAVE_ETHTOOL_RESET			member	struct_ethtool_ops reset include/linux/ethtool.h
EFX_HAVE_ETHTOOL_SET_PHYS_ID		symbol	set_phys_id		include/linux/ethtool.h
EFX_NEED_ETHTOOL_CMD_SPEED		nsymbol	ethtool_cmd_speed	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GMODULEEEPROM		symbol	get_module_eeprom	include/linux/ethtool.h
EFX_HAVE_OLD_DMA_MAPPING_ERROR		custom
EFX_NEED_DMA_SET_COHERENT_MASK		nsymbol	dma_set_coherent_mask	include/linux/dma-mapping.h
EFX_NEED_DMA_SET_MASK_AND_COHERENT		nsymbol	dma_set_mask_and_coherent	include/linux/dma-mapping.h
EFX_HAVE_LINUX_SEMAPHORE_H		file				include/linux/semaphore.h
EFX_HAVE_PRINTF_BITMAPS			symbol	cpumask_pr_args		include/linux/cpumask.h
EFX_HAVE_OLD_CPUMASK_SCNPRINTF		nsymtype cpumask_scnprintf	include/linux/cpumask.h int(char *, int, const struct cpumask *)
EFX_NEED_NEW_CPUMASK_API		nsymbol	cpumask_var_t		include/linux/cpumask.h
EFX_NEED_ZALLOC_CPUMASK_VAR		nsymbol zalloc_cpumask_var	include/linux/cpumask.h
EFX_USE_PM_EXT_OPS			symbol	pm_ext_ops		include/linux/pm.h
EFX_USE_DEV_PM_OPS			symbol	dev_pm_ops		include/linux/pm.h
EFX_NEED_PCI_WAKE_FROM_D3		nsymbol pci_wake_from_d3        include/linux/pci.h
EFX_HAVE_DEV_DISABLE_LRO		export	dev_disable_lro		include/linux/netdevice.h	net/core/dev.c
EFX_NEED_UNMASK_MSIX_VECTORS		nsymbol	masked			include/linux/msi.h
EFX_HAVE_PM_IDLE			export	pm_idle			include/linux/pm.h arch/$SRCARCH/kernel/process.c
EFX_NEED_SKB_RECORD_RX_QUEUE		nsymbol	skb_record_rx_queue	include/linux/skbuff.h
EFX_HAVE_XEN_XEN_H			file				include/xen/xen.h
EFX_HAVE_SYSDEV_H			file				include/linux/sysdev.h
EFX_HAVE_ASM_SYSTEM_H			file				asm/system.h
EFX_HAVE_XEN_START_INFO			custom
EFX_HAVE_CPUMASK_OF_NODE		symbol	cpumask_of_node		include/asm-generic/topology.h
EFX_HAVE_CPUMASK_OF_PCIBUS		symbol	cpumask_of_pcibus	include/asm-generic/topology.h
EFX_NEED_SET_CPUS_ALLOWED_PTR		nsymbol set_cpus_allowed_ptr	include/linux/sched.h
EFX_HAVE_EXPORTED_CPU_SIBLING_MAP	export	(per_cpu__)?cpu_sibling_map	include/asm/smp.h	arch/$SRCARCH/include/asm/smp.h	arch/$SRCARCH/kernel/smpboot.c	drivers/xen/core/smpboot.c
EFX_NEED_ROUNDDOWN_POW_OF_TWO		nsymbol	rounddown_pow_of_two	include/linux/log2.h include/linux/kernel.h
EFX_HAVE_SRIOV				export	pci_enable_sriov	include/linux/pci.h	drivers/pci/iov.c
EFX_HAVE_PCI_NUM_VF			export	pci_num_vf		include/linux/pci.h	drivers/pci/iov.c
EFX_HAVE_SRIOV_CONFIGURE                member  struct_pci_driver       sriov_configure        include/linux/pci.h
EFX_HAVE_PCI_DRIVER_RH                  member  struct_pci_driver_rh    sriov_configure        include/linux/pci.h
EFX_HAVE_PHYSFN                         member  struct_pci_dev          physfn                 include/linux/pci.h
EFX_HAVE_NET_DEVICE_OPS_EXTENDED	symbol	net_device_ops_extended	include/linux/netdevice.h
EFX_HAVE_NDO_SET_VF_MAC 		member	struct_net_device_ops	ndo_set_vf_mac		include/linux/netdevice.h
EFX_HAVE_NDO_SET_VF_VLAN_PROTO		memtype	struct_net_device_ops	ndo_set_vf_vlan		include/linux/netdevice.h	int (*)(struct net_device *, int, u16, u8, __be16)
EFX_HAVE_NDO_EXT_SET_VF_VLAN_PROTO		memtype struct_net_device_ops_extended	ndo_set_vf_vlan	include/linux/netdevice.h	int (*)(struct net_device *, int, u16, u8, __be16)
EFX_HAVE_NDO_SET_VF_SPOOFCHK		member	struct_net_device_ops	ndo_set_vf_spoofchk	include/linux/netdevice.h
EFX_HAVE_NDO_SET_FEATURES		member	struct_net_device_ops	ndo_set_features	include/linux/netdevice.h
EFX_HAVE_NDO_FEATURES_CHECK		member	struct_net_device_ops	ndo_features_check	include/linux/netdevice.h
EFX_HAVE_EXT_NDO_SET_FEATURES           member  struct_net_device_ops_ext ndo_set_features      include/linux/netdevice.h
EFX_HAVE_VF_LINK_STATE			member	struct_net_device_ops	ndo_set_vf_link_state	include/linux/netdevice.h
EFX_HAVE_NDO_SET_MULTICAST_LIST		member	struct_net_device_ops	ndo_set_multicast_list	include/linux/netdevice.h
EFX_HAVE_NDO_BUSY_POLL			member	struct_net_device_ops	ndo_busy_poll	        include/linux/netdevice.h
EFX_HAVE_NDO_GET_PHYS_PORT_ID		member	struct_net_device_ops	ndo_get_phys_port_id	include/linux/netdevice.h
EFX_HAVE_NDO_GET_PHYS_PORT_NAME		member	struct_net_device_ops	ndo_get_phys_port_name	include/linux/netdevice.h
EFX_HAVE_NDO_VLAN_RX_ADD_VID		member	struct_net_device_ops	ndo_vlan_rx_add_vid	include/linux/netdevice.h
EFX_HAVE_NDO_VLAN_RX_ADD_VID_PROTO	memtype	struct_net_device_ops	ndo_vlan_rx_add_vid	include/linux/netdevice.h	int (*)(struct net_device *, __be16, u16)
EFX_HAVE_NDO_VLAN_RX_ADD_VID_RC		memtype	struct_net_device_ops	ndo_vlan_rx_add_vid	include/linux/netdevice.h	int (*)(struct net_device *, u16)
EFX_NEED_ETHER_ADDR_COPY		nsymbol ether_addr_copy		include/linux/etherdevice.h
EFX_NEED_ETHER_ADDR_EQUAL		nsymbol	ether_addr_equal	include/linux/etherdevice.h
EFX_NEED_ETH_ZERO_ADDR			nsymbol eth_zero_addr		include/linux/etherdevice.h
EFX_NEED_ETH_BROADCAST_ADDR		nsymbol	eth_broadcast_addr	include/linux/etherdevice.h
EFX_NEED_ETH_RANDOM_ADDR		nsymbol	eth_random_addr		include/linux/etherdevice.h
EFX_NEED_MAC_PTON			nsymbol mac_pton		include/linux/kernel.h	include/linux/if_ether.h
EFX_HAVE_HEX_TO_BIN			symbol hex_to_bin		include/linux/kernel.h
EFX_NEED_IPV4_IS_MULTICAST		nsymbol	ipv4_is_multicast	include/linux/in.h
EFX_NEED_IPV4_IS_LBCAST			nsymbol	ipv4_is_lbcast		include/linux/in.h
EFX_HAVE_LIST_SPLICE_TAIL_INIT		symbol	list_splice_tail_init	include/linux/list.h
EFX_NEED_LIST_FIRST_ENTRY		nsymbol	list_first_entry	include/linux/list.h
EFX_NEED_TIMESPEC_ADD_NS		nsymbol	timespec_add_ns		include/linux/time.h	include/linux/time32.h
EFX_NEED_NS_TO_TIMESPEC			nexport ns_to_timespec		include/linux/time.h	kernel/time.c
EFX_HAVE_TIMESPEC64			symbol	timespec64		include/linux/time64.h	include/linux/time.h
EFX_NEED_KTIME_GET_REAL_TS64		nsymbol	ktime_get_real_ts64	include/linux/timekeeping.h	include/linux/ktime.h
EFX_HAVE_FDTABLE_FULL_ACCESSORS		symbol	__set_close_on_exec	include/linux/fdtable.h
EFX_HAVE_FDTABLE_PARTIAL_ACCESSORS	symbol	fd_is_open		include/linux/fdtable.h
EFX_HAVE_FDTABLE_H			file				include/linux/fdtable.h
EFX_NEED_SET_NORMALIZED_TIMESPEC	custom
EFX_HAVE_VLAN_RX_PATH			symbol	vlan_hwaccel_receive_skb include/linux/if_vlan.h
EFX_HAVE_OLD_ETHTOOL_GET_RXNFC		memtype	struct_ethtool_ops	get_rxnfc	include/linux/ethtool.h int (*)(struct net_device *, struct ethtool_rxnfc *, void *)
EFX_HAVE_CPU_RMAP			file				include/linux/cpu_rmap.h
EFX_NEED_KTIME_SUB_NS			nsymbol	ktime_sub_ns		include/linux/ktime.h
EFX_HAVE_NET_TSTAMP			file				include/linux/net_tstamp.h include/uapi/linux/net_tstamp.h
EFX_NEED_PTP_CLOCK_PPSUSR		custom
EFX_USE_64BIT_PHC			member	struct_ptp_clock_info gettime64	include/linux/ptp_clock_kernel.h
EFX_HAVE_PHC_SUPPORT			custom
EFX_NEED_PPS_SUB_TS			nsymbol pps_sub_ts		include/linux/pps_kernel.h
EFX_NEED_PPS_EVENT_TIME			nsymbol	pps_event_time		include/linux/pps_kernel.h
EFX_HAVE_PPS_EVENT_TIME_TIMESPEC	nmemtype	struct_pps_event_time	ts_real	include/linux/pps_kernel.h	struct timespec64
EFX_NEED_PPS_GET_TS			nsymbol	pps_get_ts		include/linux/pps_kernel.h
EFX_HAVE_PPS_KERNEL			file				include/linux/pps_kernel.h
EFX_HAVE_DIV_S64_REM			symbol	div_s64_rem		include/linux/math64.h
EFX_NEED_IP_IS_FRAGMENT			nsymbol	ip_is_fragment		include/net/ip.h
EFX_NEED_NETDEV_FEATURES_T		nsymbol	netdev_features_t	include/linux/netdevice.h
EFX_NEED_SKB_FILL_PAGE_DESC		nsymbol	skb_fill_page_desc	include/linux/skbuff.h
EFX_NEED_SKB_FRAG_DMA_MAP		nsymbol	skb_frag_dma_map	include/linux/skbuff.h
EFX_NEED_SKB_FRAG_ADDRESS		nsymbol skb_frag_address	include/linux/skbuff.h
EFX_NEED_SKB_FRAG_SIZE			nsymbol	skb_frag_size		include/linux/skbuff.h
EFX_NEED_SKB_FRAG_PAGE			nsymbol	skb_frag_page		include/linux/skbuff.h
EFX_HAVE_ETHTOOL_GET_RXFH_INDIR	symbol	get_rxfh_indir	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GET_RXFH_INDIR_SIZE	symbol	get_rxfh_indir_size	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GET_RXFH		symbol	get_rxfh	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GET_RXFH_KEY_SIZE		symbol	get_rxfh_key_size	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_SET_RXFH_NOCONST	custom
EFX_HAVE_OLD_ETHTOOL_RXFH_INDIR		custom
EFX_NEED_ETHTOOL_RXFH_INDIR_DEFAULT	nsymbol	ethtool_rxfh_indir_default	include/linux/ethtool.h
EFX_NEED_IS_COMPAT_TASK			custom
EFX_NEED_COMPAT_U64			nsymbol	compat_u64		include/asm/compat.h arch/$SRCARCH/include/asm/compat.h include/asm-$SRCARCH/compat.h
EFX_HAVE_IRQ_NOTIFIERS			symbol  irq_affinity_notify	include/linux/interrupt.h
EFX_HAVE_GSO_MAX_SEGS			member	struct_net_device	gso_max_segs		include/linux/netdevice.h
EFX_NEED_BYTE_QUEUE_LIMITS		nsymbol	netdev_tx_sent_queue	include/linux/netdevice.h
EFX_NEED_SKB_CHECKSUM_NONE_ASSERT	nsymbol	skb_checksum_none_assert	include/linux/skbuff.h
EFX_HAVE_NON_CONST_KERNEL_PARAM		symtype	param_set_uint		include/linux/moduleparam.h	int (const char *, struct kernel_param *)
EFX_HAVE_KERNEL_PARAM_OPS		symbol kernel_param_ops		include/linux/moduleparam.h
EFX_NEED___SET_BIT_LE			nsymtype __set_bit_le		include/asm-generic/bitops/le.h	void (int, void *)
EFX_NEED_KOBJECT_INIT_AND_ADD		nsymbol	kobject_init_and_add	include/linux/kobject.h
EFX_HAVE_NON_CONST_JHASH2		symtype	jhash2			include/linux/jhash.h		u32 (u32 *, u32, u32)
EFX_NEED_KOBJECT_SET_NAME_VARGS		nsymbol kobject_set_name_vargs	include/linux/kobject.h
EFX_USE_ETHTOOL_OPS_EXT			symbol	ethtool_ops_ext		include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GET_DUMP_FLAG		member	struct_ethtool_ops get_dump_flag	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GET_DUMP_DATA		member	struct_ethtool_ops get_dump_data	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_SET_DUMP		member	struct_ethtool_ops set_dump	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_GET_TS_INFO		member	struct_ethtool_ops get_ts_info	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_EXT_GET_TS_INFO	member	struct_ethtool_ops_ext get_ts_info	include/linux/ethtool.h
EFX_HAVE_OLD___VLAN_PUT_TAG		symtype	__vlan_put_tag		include/linux/if_vlan.h	struct sk_buff *(struct sk_buff *, u16)
EFX_HAVE_VLAN_INSERT_TAG_SET_PROTO	symbol vlan_insert_tag_set_proto	include/linux/if_vlan.h
EFX_HAVE_NETDEV_NOTIFIER_NETDEV_PTR	nsymbol	netdev_notifier_info	include/linux/netdevice.h
EFX_HAVE_NETDEV_REGISTER_RH		symbol	register_netdevice_notifier_rh	include/linux/netdevice.h
EFX_HAVE_NETDEV_RFS_INFO		symbol	netdev_rfs_info		include/linux/netdevice.h
EFX_HAVE_PCI_AER			file				include/linux/aer.h
EFX_HAVE_EEH_DEV_CHECK_FAILURE		symbol	eeh_dev_check_failure	arch/powerpc/include/asm/eeh.h
EFX_NEED_PCI_DEV_TO_EEH_DEV		nsymbol	pci_dev_to_eeh_dev	include/linux/pci.h
EFX_HAVE_IOREMAP_WC			symbol	ioremap_wc		arch/$SRCARCH/include/asm/io.h include/asm-$SRCARCH/io.h include/asm-generic/io.h
EFX_NEED_SKB_TRANSPORT_HEADER_WAS_SET	nsymbol	skb_transport_header_was_set include/linux/skbuff.h
EFX_HAVE_OLD_KMAP_ATOMIC		custom
EFX_HAVE_DEBUGFS_CREATE_SYMLINK		symbol	debugfs_create_symlink	include/linux/debugfs.h
EFX_HAVE_INODE_U_GENERIC_IP		symbol	generic_ip		include/linux/fs.h
EFX_HAVE_NAPI_STRUCT			symbol	napi_struct		include/linux/netdevice.h
EFX_HAVE_NAPI_STRUCT_NAPI_ID		member	struct_napi_struct	napi_id	include/linux/netdevice.h
EFX_HAVE_NAPI_HASH_ADD			symbol	napi_hash_add		include/linux/netdevice.h
EFX_HAVE_NAPI_HASH_DEL_RETURN		symtype	napi_hash_del		include/linux/netdevice.h	int (struct napi_struct *)
EFX_NEED_SKB_SET_HASH			nsymbol skb_set_hash		include/linux/skbuff.h
EFX_HAVE_SKB_L4HASH			member	struct_sk_buff l4_rxhash	include/linux/skbuff.h
EFX_HAVE_SKB_VLANTCI                     member    struct_sk_buff vlan_tci        include/linux/skbuff.h
EFX_HAVE_BUSY_POLL			file				include/net/busy_poll.h
EFX_NEED_USLEEP_RANGE			nsymbol	usleep_range		include/linux/delay.h
EFX_HAVE_SRIOV_GET_TOTALVFS		symbol	pci_sriov_get_totalvfs	include/linux/pci.h
EFX_NEED_SKB_VLAN_TAG_GET		nsymbol	skb_vlan_tag_get	include/linux/if_vlan.h
EFX_HAVE_OLD___VLAN_HWACCEL_PUT_TAG	symtype	__vlan_hwaccel_put_tag	include/linux/if_vlan.h	struct sk_buff *(struct sk_buff *, u16)
EFX_HAVE_ETHTOOL_CHANNELS		member	struct_ethtool_ops get_channels	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_EXT_CHANNELS		member	struct_ethtool_ops_ext get_channels	include/linux/ethtool.h
EFX_NEED_UINTPTR_T			nsymbol	uintptr_t		include/linux/types.h
EFX_NEED_IPV6_NFC			nsymbol	ethtool_tcpip6_spec	include/uapi/linux/ethtool.h
EFX_HAVE_SKB_HASH			member	struct_sk_buff hash	include/linux/skbuff.h
EFX_HAVE_SKB_INNER_NETWORK_HEADER	symbol	skb_inner_network_header	include/linux/skbuff.h
EFX_SKB_HAS_INNER_NETWORK_HEADER	member	struct_sk_buff	inner_network_header	include/linux/skbuff.h
EFX_HAVE_SKB_INNER_TRANSPORT_HEADER	symbol	skb_inner_transport_header	include/linux/skbuff.h
EFX_SKB_HAS_INNER_TRANSPORT_HEADER	member	struct_sk_buff	inner_transport_header	include/linux/skbuff.h
EFX_HAVE_SKB_FRAG_TRUESIZE		symtype	skb_add_rx_frag		include/linux/skbuff.h	void (struct sk_buff *, int, struct page *, int, int, unsigned int)
EFX_HAVE_INNER_IP_HDR			symbol	inner_ip_hdr		include/linux/ip.h
EFX_HAVE_INNER_TCP_HDR			symbol	inner_tcp_hdr		include/linux/tcp.h

# Stuff needed in code other than the linux net driver
EFX_NEED_SCSI_SGLIST			nsymbol scsi_sglist		include/scsi/scsi_cmnd.h
EFX_NEED_SG_NEXT			nsymbol sg_next			include/linux/scatterlist.h
EFX_HAVE_NEW_KFIFO			symbol kfifo_out		include/linux/kfifo.h
EFX_NEED_VMALLOC_NODE			nsymbol vmalloc_node		include/linux/vmalloc.h
EFX_NEED_VMALLOC_TO_PFN			nsymbol vmalloc_to_pfn		include/linux/mm.h
EFX_NEED_KVEC				nsymbol	kvec			include/linux/uio.h
EFX_NEED_KERNEL_SENDMSG			nsymbol kernel_sendmsg		include/linux/net.h
EFX_HAVE_NETFILTER_INDIRECT_SKB		memtype	struct_nf_hook_ops	hook	include/linux/netfilter.h	unsigned int(*)(unsigned int, struct sk_buff **, const struct net_device *, const struct net_device *, int (*)(struct sk_buff *))
EFX_HAVE_NFPROTO_CONSTANTS		symbol	NFPROTO_NUMPROTO	include/linux/netfilter.h
EFX_HAVE_FDTABLE			symbol	files_fdtable		include/linux/file.h include/linux/fdtable.h
EFX_HAVE_REMAP_PFN_RANGE		symbol	remap_pfn_range		include/linux/mm.h
EFX_HAVE___REGISTER_CHRDEV		symbol __register_chrdev	include/linux/fs.h

EFX_NEED_PCI_ENABLE_MSIX_RANGE          nsymbol pci_enable_msix_range include/linux/pci.h
EFX_HAVE_SKB_OOO_OKAY			member	struct_sk_buff ooo_okay	include/linux/skbuff.h
EFX_HAVE_SKB_TX_HASH			symbol	skb_tx_hash	include/linux/netdevice.h include/linux/skbuff.h
EFX_HAVE_SK_SET_TX_QUEUE		symbol	sk_tx_queue_set	include/net/sock.h
EFX_HAVE_SKB_GET_RX_QUEUE		symbol	skb_get_rx_queue	include/linux/skbuff.h
EFX_NEED_RCU_ACCESS_POINTER		nsymbol	rcu_access_pointer	include/linux/rcupdate.h
EFX_NEED_CPU_ONLINE_MASK		nsymbol	cpu_online_mask		include/linux/cpumask.h
EFX_HAVE_VF_INFO_MIN_TX_RATE		member	struct_ifla_vf_info min_tx_rate	include/linux/if_link.h
EFX_HAVE_NETDEV_HW_FEATURES		member	struct_net_device	hw_features	include/linux/netdevice.h
EFX_HAVE_NETDEV_EXTENDED_HW_FEATURES    member  struct_net_device_extended hw_features  include/linux/netdevice.h
EFX_HAVE_NETDEV_FEATURES_CHANGE	symbol	netdev_features_change	include/linux/netdevice.h
EFX_HAVE_PCI_DEV_FLAGS_ASSIGNED		symbol	PCI_DEV_FLAGS_ASSIGNED	include/linux/pci.h
EFX_HAVE_PCI_VFS_ASSIGNED		symbol	pci_vfs_assigned	include/linux/pci.h
EFX_HAVE_LINUX_EXPORT_H			file				include/linux/export.h
EFX_NEED_KMALLOC_ARRAY			nsymbol	kmalloc_array	include/linux/slab.h
EFX_HAVE_VOID_DYNAMIC_NETDEV_DBG	symtype	__dynamic_netdev_dbg	include/linux/dynamic_debug.h void (struct _ddebug *, const struct net_device *, const char *, ...)
EFX_HAVE_NDO_EXT_BUSY_POLL		member	struct_net_device_extended	ndo_busy_poll	        include/linux/netdevice.h
EFX_HAVE_NET_DEVICE_OPS_EXT	member struct_net_device_extended	netdev_ops_ext	include/linux/netdevice.h
EFX_HAVE_NET_DEVICE_OPS_EXT_GET_PHYS_PORT_ID	member struct_net_device_ops_ext	ndo_get_phys_port_id	include/linux/netdevice.h
EFX_HAVE_NET_DEVICE_OPS_EXT_SET_VF_SPOOFCHK	member struct_net_device_ops_ext	ndo_set_vf_spoofchk	include/linux/netdevice.h
EFX_HAVE_NET_DEVICE_OPS_EXT_SET_VF_LINK_STATE	member struct_net_device_ops_ext	ndo_set_vf_link_state	include/linux/netdevice.h
EFX_NEED_SKB_GSO_TCPV6			nsymbol	SKB_GSO_TCPV6		include/linux/skbuff.h
EFX_HAVE_GSO_PARTIAL			symbol	SKB_GSO_PARTIAL		include/linux/skbuff.h
EFX_HAVE_GSO_UDP_TUNNEL_CSUM		symbol	SKB_GSO_UDP_TUNNEL_CSUM	include/linux/skbuff.h
EFX_NEED_IS_ERR_OR_NULL		nsymbol IS_ERR_OR_NULL	include/linux/err.h
EFX_NEED_NETDEV_RSS_KEY_FILL	nsymbol	netdev_rss_key_fill	include/linux/netdevice.h
EFX_HAVE_NETIF_SET_XPS_QUEUE	symbol	netif_set_xps_queue	include/linux/netdevice.h
EFX_HAVE_NETIF_SET_XPS_QUEUE_NON_CONST	symtype	netif_set_xps_queue include/linux/netdevice.h	int (struct net_device *, struct cpumask *, u16)
EFX_HAVE_ALLOC_PAGES_NODE	symbol	alloc_pages_node	include/linux/gfp.h
EFX_HAVE_NETIF_XMIT_STOPPED	symbol	netif_xmit_stopped	include/linux/netdevice.h
EFX_NEED_CPUMASK_LOCAL_SPREAD	nsymbol	cpumask_local_spread	include/linux/cpumask.h
EFX_HAVE_CONST_PCI_ERR_HANDLER	memtype	struct_pci_driver err_handler	include/linux/pci.h	const struct pci_error_handlers *
EFX_HAVE_ETHTOOL_PRIV_FLAGS	member	struct_ethtool_ops	get_priv_flags	include/linux/ethtool.h
EFX_HAVE_HW_ENC_FEATURES	member	struct_net_device	hw_enc_features	include/linux/netdevice.h
EFX_NEED_SKB_INNER_TRANSPORT_OFFSET	nsymbol	skb_inner_transport_offset	include/linux/skbuff.h
EFX_HAVE_SKB_XMIT_MORE	bitfield	struct_sk_buff	xmit_more	include/linux/skbuff.h
EFX_HAVE_NDO_ADD_VXLAN_PORT	member	struct_net_device_ops	ndo_add_vxlan_port	include/linux/netdevice.h
EFX_NEED_PAGE_REF_ADD		nfile				include/linux/page_ref.h
EFX_NEED_D_HASH_AND_LOOKUP	nexport	d_hash_and_lookup	include/linux/dcache.h fs/dcache.c
EFX_HAVE_KTIME_UNION		custom
EFX_NEED_HWMON_DEVICE_REGISTER_WITH_INFO	nsymbol	hwmon_device_register_with_info	include/linux/hwmon.h
EFX_HAVE_NDO_UDP_TUNNEL_ADD	member	struct_net_device_ops	ndo_udp_tunnel_add	include/linux/netdevice.h
EFX_HAVE_NEW_FLOW_KEYS		member	struct_flow_keys	basic		include/net/flow_dissector.h
EFX_HAVE_SKB_ENCAPSULATION	bitfield	struct_sk_buff	encapsulation	include/linux/skbuff.h
EFX_HAVE_NDO_ADD_GENEVE_PORT	member	struct_net_device_ops	ndo_add_geneve_port	include/linux/netdevice.h
EFX_HAVE_NETDEV_MTU_LIMITS	member	struct_net_device	max_mtu	include/linux/netdevice.h
EFX_NEED_BOOL_NAPI_COMPLETE_DONE	nsymtype	napi_complete_done	include/linux/netdevice.h	bool (struct napi_struct *, int)
EFX_HAVE_XDP	symbol	netdev_bpf	include/linux/netdevice.h
EFX_HAVE_XDP_OLD	symbol	netdev_xdp	include/linux/netdevice.h
EFX_HAVE_XDP_TRACE	file	include/trace/events/xdp.h
EFX_HAVE_XDP_HEAD	member	struct_xdp_buff	data_hard_start	include/linux/filter.h
EFX_HAVE_XDP_TX		symbol	XDP_TX		include/uapi/linux/bpf.h
EFX_HAVE_XDP_TX_FLAGS	memtype	struct_net_device_ops	ndo_xdp_xmit	include/linux/netdevice.h	int (*)(struct net_device *, int, struct xdp_frame **, u32)
EFX_HAVE_XDP_REDIR	symbol	XDP_REDIRECT	include/uapi/linux/bpf.h
EFX_HAVE_XDP_RXQ_INFO	symbol	xdp_rxq_info	include/net/xdp.h
EFX_HAVE_XDP_EXT	member	struct_net_device_ops_extended	ndo_xdp	include/linux/netdevice.h
EFX_NEED_XDP_FLUSH	member	struct_net_device_ops	ndo_xdp_flush	include/linux/netdevice.h
EFX_HAVE_XDP_PROG_ATTACHED	member	struct_netdev_bpf	prog_attached	include/linux/netdevice.h
EFX_HAVE_XDP_PROG_ID	member	struct_netdev_bpf	prog_id	include/linux/netdevice.h
EFX_NEED_PAGE_FRAG_FREE	nsymbol	page_frag_free	include/linux/gfp.h
EFX_HAVE_FREE_PAGE_FRAG	symbol	__free_page_frag	include/linux/gfp.h
EFX_NEED_VOID_SKB_PUT	nsymtype	skb_pub	include/linux/skbuff.h	void *skb_put(struct sk_buff *, unsigned int)
EFX_HAVE_ETHTOOL_FCS	symbol	NETIF_F_RXALL	include/linux/netdev_features.h
EFX_HAVE_ETHTOOL_LINKSETTINGS	symbol	ethtool_link_ksettings	include/linux/ethtool.h
EFX_HAVE_LINK_MODE_25_50_100	symbol	ETHTOOL_LINK_MODE_25000baseCR_Full_BIT	include/uapi/linux/ethtool.h
EFX_HAVE_LINK_MODE_FEC_BITS	symbol	ETHTOOL_LINK_MODE_FEC_BASER_BIT	include/uapi/linux/ethtool.h
EFX_HAVE_NETDEV_EXT_MTU_LIMITS	member	struct_net_device_extended	max_mtu	include/linux/netdevice.h
EFX_HAVE_NDO_EXT_CHANGE_MTU	memtype	struct_net_device_ops_extended	ndo_change_mtu	include/linux/netdevice.h	int (*)(struct net_device *, int)
EFX_HAVE_ETHTOOL_FECPARAM	member	struct_ethtool_ops	get_fecparam	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_RXFH_CONTEXT	member	struct_ethtool_ops	get_rxfh_context	include/linux/ethtool.h
EFX_HAVE_ETHTOOL_RXNFC_CONTEXT	member	struct_ethtool_rxnfc	rss_context	include/linux/ethtool.h
EFX_NEED_HASH_64		nsymbol	hash_64	include/linux/hash.h
EFX_HAVE_XDP_FRAME_API		symbol	xdp_frame	include/net/xdp.h
EFX_HAVE_XDP_DATA_META		member	struct_xdp_buff	data_meta	include/linux/filter.h
" | egrep -v -e '^#' -e '^$' | sed 's/[ \t][ \t]*/:/g'
}

######################################################################
# Generic methods for standard symbol types

# Look for up to 3 numeric components separated by dots and stop when
# we find anything that doesn't match this.  Convert to a number like
# the LINUX_VERSION_CODE macro does.
function string_to_version_code
{
    local ver="$1"
    local code=0
    local place=65536
    local num

    while [ -n "$ver" ]; do
	# Look for numeric component; if none found then we're done;
	# otherwise add to the code
	num=${ver%%[^0-9]*}
	test -n "$num" || break
	code=$((code + $num * $place))

	# If this was the last component (place value = 1) then we're done;
	# otherwise update place value
	test $place -gt 1 || break
	place=$((place / 256))

	# Move past numeric component and following dot (if present)
	ver=${ver#$num}
	ver=${ver#.}
    done

    echo $code
}

# Test cases for string_to_version_code:
# test $(string_to_version_code 1.2.3) = $((1 * 65536 + 2 * 256 + 3))
# test $(string_to_version_code 12.34.56) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56foo) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56.78) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56.foo) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56-foo) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34.0) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34foo) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34-56) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34.foo) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34-foo) = $((12 * 65536 + 34 * 256))

function do_kver()
{
    shift 2;
    local op="$1"
    local right_ver="$2"

    local left=$(string_to_version_code "$KVER")
    local right=$(string_to_version_code "$right_ver")

    local result=$((1 - ($left $op $right)))
    local msg="$KVER $op $right_ver == $left $op $right == "
    if [ $result = 0 ]; then
	msg="$msg true"
    else
	msg="$msg false"
    fi
    vmsg "$msg"
    return $result
}

function do_symbol()  { shift 2; test_symbol "$@"; }
function do_nsymbol() { shift 2; ! test_symbol "$@"; }
function do_symtype() { shift 2; defer_test_symtype pos "$@"; }
function do_nsymtype() { shift 2; defer_test_symtype neg "$@"; }
function do_member() { shift 2; defer_test_memtype pos "$@" void; }
function do_nmember() { shift 2; defer_test_memtype neg "$@" void; }
function do_memtype() { shift 2; defer_test_memtype pos "$@"; }
function do_nmemtype() { shift 2; defer_test_memtype neg "$@"; }
function do_bitfield() { shift 2; defer_test_bitfield pos "$@"; }
function do_nbitfield() { shift 2; defer_test_bitfield neg "$@"; }
function do_export()
{
    local sym=$3
    shift 3

    # Only scan header files for the symbol
    test_symbol $sym $(echo "$@" | sed -r 's/ [^ ]+\.c/ /g') || return
    test_export $sym "$@"
}
function do_nexport() { ! do_export "$@"; }
function do_file()
{
    for file in "$@"; do
        if [ -f $KBUILD_SRC/$file ]; then
            return 0
        fi
    done
    return 1
}
function do_nfile()   { ! do_file "$@"; }

function do_custom()  { do_$1; }

######################################################################
# Implementation of kernel feature checking

# Special return value for deferred test
DEFERRED=42

function atexit_cleanup()
{
  rc=$?
  [ -n "$rmfiles" ] && rm -rf $rmfiles
  return $rc
}

function strip_comments()
{
    local file=$1

    cat $1 | sed -e '
/\/\*/!b
:a
/\*\//!{
N
ba
}
s:/\*.*\*/::'
}

function test_symbol()
{
    local symbol=$1
    shift
    local file
    local prefix
    local prefix_list

    for file in "$@"; do
        # For speed, lets just grep through the file. The symbol may
        # be of any of these forms:
        #     #define SYMBOL
        #     typedef void (SYMBOL)(void)
        #     extern void SYMBOL(void)
        #     void (*SYMBOL)(void)
        #     enum { SYMBOL, } void
        #
	# Since 3.7 headers can be in both $KBUILD_SRC/include
	#     or $KBUILD_SRC/include/uapi so check both
	# If the file contains "include/linux" then build set of
        # prefixes 

        prefix=$(dirname $file)
	file=$(basename $file)
        if [ "$prefix" == "include/linux" ]; then
            prefix_list="include/linux/ include/uapi/linux/"
	else
            prefix_list="$prefix/"
        fi

	for prefix in $prefix_list; do
            if [ $verbose = true ]; then
                echo >&2 "Looking for '$symbol' in '$KBUILD_SRC/$prefix$file'"
            fi
            [ -f "$KBUILD_SRC/$prefix$file" ] &&  \
                strip_comments $KBUILD_SRC/$prefix$file | \
                egrep -w "$symbol" >/dev/null && \
                return 0
        done
    done
    return 1
}

function defer_test_symtype()
{
    local sense=$1
    local symbol=$2
    local file=$3
    shift 3
    local type="$*"

    if [ ${file:0:8} != "include/" ]; then
	fail "defer_test_symtype() can work in include/ - request was '$file'"
    fi

    defer_test_compile $sense "
#include <linux/types.h>
#include <${file:8}>

#include \"_autocompat.h\"

__typeof($type) *kernel_compat_dummy = &$symbol;
"
}

function defer_test_memtype()
{
    local sense=$1
    local aggtype="${2/_/ }"
    local memname=$3
    local file=$4
    shift 4
    local memtype="$*"

    if [ ${file:0:8} != "include/" ]; then
	fail "defer_test_symtype() can work in include/ - request was '$file'"
    fi

    defer_test_compile $sense "
#include <${file:8}>
$aggtype kernel_compat_dummy_1;
__typeof($memtype) *kernel_compat_dummy_2 = &kernel_compat_dummy_1.$memname;
"
}

function defer_test_bitfield()
{
    local sense=$1
    local aggtype="${2/_/ }"
    local memname=$3
    local file=$4
    shift 4

    if [ ${file:0:8} != "include/" ]; then
	fail "defer_test_bitfield() only works in include/ - request was '$file'"
    fi

    defer_test_compile $sense "
#include <${file:8}>
$aggtype kernel_compat_dummy_1;
unsigned long test(void) {
	return kernel_compat_dummy_1.$memname;
}
"
}

function test_inline_symbol()
{
    local symbol=$1
    local file=$2
    local t=$(mktemp)
    rmfiles="$rmfiles $t"

    [ -f "$KBUILD_SRC/$file" ] || return

    # TODO: This isn't very satisfactory. Alternative options are:
    #   1. Come up with a clever sed version
    #   2. Do a test compile, and look for an undefined symbol (extern)

    # look for the inline..symbol. This is complicated since the inline
    # and the symbol may be on different lines.
    strip_comments $KBUILD_SRC/$file | \
	egrep -m 1 -B 1 '(^|[,\* \(])'"$symbol"'($|[,; \(\)])' > $t
    [ $? = 0 ] || return $?
        
    # there is either an inline on the final line, or an inline and
    # no semicolon on the previous line
    head -1 $t | egrep -q 'inline[^;]*$' && return
    tail -1 $t | egrep -q 'inline' && return

    return 1
}

function test_export()
{
    local symbol=$1
    shift
    local files="$@"
    local file match

    # Looks for the given export symbol $symbol, defined in $file
    # Since this symbol is exported, we can look for it in:
    #     1. $KPATH/Module.symvers
    #     2. If the full source is installed, look in there.
    #        May give a false positive if the export is conditional.
    #     3. The MAP file if present. May give a false positive
    #        because it lists all extern (not only exported) symbols.
    if [ -f $KPATH/Module.symvers ]; then
        if [ $verbose = true ]; then
            echo >&2 "Looking for export of $symbol in $KPATH/Module.symvers"
	fi
	[ -n "$(awk '/0x[0-9a-f]+[\t ]+'$symbol'[\t ]+/' $KPATH/Module.symvers)" ]
    else
	for file in $files; do
            if [ $verbose = true ]; then
		echo >&2 "Looking for export of $symbol in $KBUILD_SRC/$file"
            fi
            if [ -f $KBUILD_SRC/$file ]; then
		egrep -q 'EXPORT_(PER_CPU)?SYMBOL(_GPL)?\('"$symbol"'\)' $KBUILD_SRC/$file && return
            fi
	done
	if [ -n "$MAP" ]; then
            if [ $verbose = true ]; then
		echo >&2 "Looking for export of $symbol in $MAP"
            fi
	    egrep -q "[A-Z] $symbol\$" $MAP && return
	fi
	return 1
    fi
}

function test_compile()
{
    local source="$1"
    local rc
    local dir=$(mktemp -d)
    echo "$source" > $dir/test.c
    cat > $dir/Makefile <<EOF
$makefile_prefix
obj-m := test.o
EOF
    make -C $KPATH M=$dir >$dir/log 2>&1
    rc=$?

    if [ $verbose = true ]; then
	echo >&2 "tried to compile:"
	sed >&2 's/^/    /' $dir/test.c
	echo >&2 "compiler output:"
	sed >&2 's/^/    /' $dir/log
    fi

    rm -rf $dir
    return $rc
}

function defer_test_compile()
{
    local sense=$1
    local source="$2"
    echo "$source" > "$compile_dir/test_$key.c"
    echo "obj-m += test_$key.o" >> "$compile_dir/Makefile"
    eval deferred_$sense=\"\$deferred_$sense $key\"
    return $DEFERRED
}

function read_make_variables()
{
    local regexp=''
    local split='('
    local variable
    local variables="$@"
    local dir=$(mktemp -d)

    for variable in $variables; do
	echo "\$(warning $variable=\$($variable))" >> $dir/Makefile
	regexp=$regexp$split$variable
	split='|'
    done
    make -C $KPATH $EXTRA_MAKEFLAGS M=$dir 2>&1 >/dev/null | sed -r "s#$dir/Makefile:.*: ($regexp)=.*$)#\1#; t; d"
    rc=$?

    rm -rf $dir
    return $rc
}

function read_define()
{
    local variable="$1"
    local file="$2"
    cat $KPATH/$2 | sed -r 's/#define '"$variable"' (.*)/\1/; t; d'
}

######################################################################
# Implementation for more tricky types

function do_EFX_HAVE_MTD_DIRECT_ACCESS()
{
    # RHEL 4 is missing <mtd/mtd-abi.h>; assume old operation names
    # in this case
    # kernels post 3.5 changed to use _<operator> for function pointers
    # kernels post 3.7 changed the location of mtd-abi.h to uapi/..
    (! test -f $KBUILD_SRC/include/mtd/mtd-abi.h && \
    ! test -f $KBUILD_SRC/include/uapi/mtd/mtd-abi.h ) || \
	 defer_test_memtype pos struct_mtd_info erase include/linux/mtd/mtd.h void
}

function do_EFX_USE_NETDEV_STATS()
{
    local source="
#include <linux/netdevice.h>
struct net_device_stats *stats;
void test(struct net_device *net_dev) { stats = &net_dev->stats; }"
    defer_test_compile pos "$source"
}

function do_EFX_HAVE_BIN_ATTRIBUTE_OP_FILE_PARAM()
{
    defer_test_compile pos "
#include <linux/list.h>
#include <linux/sysfs.h>
ssize_t f(struct file *, struct kobject *, struct bin_attribute *,
          char *, loff_t, size_t);
struct bin_attribute attr = { .read = f };
"
}

function do_EFX_HAVE_OLD_DMA_MAPPING_ERROR()
{
    # We should be able to use symtype for this, but dma_mapping_error
    # used to be defined as a macro on some architectures.
    defer_test_compile pos "
#include <linux/dma-mapping.h>
int f(void) { return dma_mapping_error(0); }
"
}

function do_EFX_HAVE_XEN_START_INFO()
{
    case $SRCARCH in
	i386 | x86)
	    test_export xen_start_info arch/$SRCARCH/xen/enlighten.c || return
	    ;;
	ia64)
	    test_export xen_start_info arch/ia64/xen/hypervisor.c || return
	    ;;
	*)
	    return 1
	    ;;
    esac

    test_symbol xen_start_info \
	include/asm/xen/hypervisor.h \
	arch/$SRCARCH/include/asm/xen/hypervisor.h
}

function do_EFX_HAVE_EXPORTED_CPU_DATA()
{
    # cpu_data gets exported in lots of places in various kernels
    test_export cpu_data \
        arch/x86_64/kernel/x8664_ksyms.c \
        arch/i386/kernel/i386_ksyms.c \
        arch/$SRCARCH/kernel/smpboot.c \
        drivers/xen/core/smpboot.c && \
	defer_test_symtype pos cpu_data include/asm/processor.h 'struct cpuinfo_x86[]'
}

function do_EFX_HAVE_GRO()
{
    # We check symbol types here because in Linux 2.6.29 and 2.6.30
    # napi_gro_frags() took an extra parameter.  We don't bother to
    # support GRO on those versions; no major distribution used them.
    if test_symbol napi_gro_receive_gr include/linux/netdevice.h; then
	true
    elif test_symbol gro_result_t include/linux/netdevice.h; then
	defer_test_symtype pos napi_gro_frags include/linux/netdevice.h "gro_result_t(struct napi_struct *)"
    else
	defer_test_symtype pos napi_gro_frags include/linux/netdevice.h "int(struct napi_struct *)"
    fi
}

function do_EFX_NEED_SET_NORMALIZED_TIMESPEC
{
    ! test_inline_symbol set_normalized_timespec include/linux/time.h && \
	! test_export set_normalized_timespec include/linux/time.h kernel/time.c
}

function do_EFX_HAVE_OLD_ETHTOOL_RXFH_INDIR
{
    test_symbol ETHTOOL_GRXFHINDIR include/linux/ethtool.h && \
	! test_symbol get_rxfh_indir_size include/linux/ethtool.h
}

function do_EFX_HAVE_ETHTOOL_SET_RXFH_NOCONST
{
	defer_test_compile pos "
#include <linux/ethtool.h>
static int test_func(struct net_device *a, u32  *b, u8 *c)
{
	return 0;
}
struct ethtool_ops_ext test = {
	.set_rxfh = test_func
};
"
}

function do_EFX_NEED_IS_COMPAT_TASK
{
    defer_test_compile neg "
#include <linux/compat.h>
int test(void) { return is_compat_task(); }
"
}

function do_EFX_NEED_PTP_CLOCK_PPSUSR
{
    # If the enum is not complete
    test_symbol PTP_CLOCK_PPS include/linux/ptp_clock_kernel.h && \
      ! test_symbol PTP_CLOCK_PPSUSR include/linux/ptp_clock_kernel.h
}

function do_EFX_HAVE_PHC_SUPPORT
{
    if [ "${CONFIG_PTP_1588_CLOCK:-}" = "y" ] || [ "${CONFIG_PTP_1588_CLOCK:-}" = "m" ]; then
        # Ideally this would use this (but it is a deferred test)
        #   test_member struct ptp_clock_event ptp_evt pps_times
        # NB pps_times is needed for the PTP_CLOCK_PPSUSR event
        test_export ptp_clock_register && \
          test_symbol pps_times include/linux/ptp_clock_kernel.h
    else
        return 1
    fi
}

function do_EFX_HAVE_PHYS_ADDR_T
{
    local source="
#include <linux/types.h>
#include <asm/page.h>
phys_addr_t paddr;"
    test_compile "$source"
}

function do_EFX_HAVE_OLD_KMAP_ATOMIC
{
    # This is a negative test because the new implementation of
    # kmap_atomic() was a macro that accepts and ignores extra
    # arguments.
    defer_test_compile neg "
#include <linux/highmem.h>

void *f(struct page *p)
{
	return kmap_atomic(p);
}
"
}

function do_EFX_HAVE_KTIME_UNION
{
	defer_test_compile pos "
#include <linux/ktime.h>

void f(void)
{
	ktime_t t;
	t.tv64 = 0;
}
"
}

function do_EFX_HAVE_NEW_ALLOC_WORKQUEUE
{
    # The old macro only accepts 3 arguments.
    defer_test_compile pos '
#include <linux/workqueue.h>

void f(void)
{
	alloc_workqueue("%s", 0, 0, "test");
}
'
}

quiet=false
verbose=false

KVER=
KPATH=
FILTER=
unset ARCH  # avoid exporting ARCH during initial checks
ARCH=
MAP=
EXTRA_MAKEFLAGS=
kompat_symbols=

# These variables from an outer build will interfere with our test builds
unset KBUILD_EXTMOD
unset KBUILD_SRC
unset M
unset TOPDIR

# Filter out make options except for job-server (parallel make)
old_MAKEFLAGS="${MAKEFLAGS:-}"
MAKEFLAGS=
next=
for word in $old_MAKEFLAGS; do
    case "$word" in
	'-j' | '-l')
	    export MAKEFLAGS="$MAKEFLAGS $word"
	    next=1
	    ;;
	'-j'* | '-l'*)
	    export MAKEFLAGS="$MAKEFLAGS $word"
	    ;;
	'--jobserver-fds'* | '--jobs='* | '--jobs' | '--load-average'*)
	    export MAKEFLAGS="$MAKEFLAGS $word"
	    ;;
	*)
	    test -n "$next" && export MAKEFLAGS="$MAKEFLAGS $word"
	    next=
	    ;;
    esac
done

# Clean-up temporary files when we exit.
rmfiles=
trap atexit_cleanup EXIT

while [ $# -gt 0 ]; do
    case "$1" in
	-r) KVER=$2; shift;;
	-k) KPATH=$2; shift;;
	-q) quiet=true;;
	-m) MAP=$2; shift;;
	-v) verbose=true;;
	-s) kompat_symbols="$2"; shift;;
	-*) usage; exit -1;;
	*)  [ -z $FILTER ] && FILTER=$1 || FILTER="$FILTER|$1";;
	*)  break;
    esac
    shift
done

vmsg "MAKEFLAGS  := $MAKEFLAGS"

# resolve KVER and KPATH
[ -z "$KVER" ] && [ -z "$KPATH" ] && KVER=`uname -r`
[ -z "$KPATH" ] && KPATH=/lib/modules/$KVER/build

# Need to set CC explicitly on the kernel make line
# Needs to override top-level kernel Makefile setting
# Somehow this script does the wrong thing when ccache is used, so disable
# that.
if [ -n "${CC:-}" ]; then
    EXTRA_MAKEFLAGS=CC=\"${CC/ccache /}\"
fi

# Select the right warnings - complicated by working out which options work
makefile_prefix='
ifndef try-run
try-run = $(shell set -e;		\
	TMP="$(obj)/.$$$$.tmp";		\
	TMPO="$(obj)/.$$$$.o";		\
	if ($(1)) >/dev/null 2>&1;	\
	then echo "$(2)";		\
	else echo "$(3)";		\
	fi;				\
	rm -f "$$TMP" "$$TMPO")
endif
ifndef cc-disable-warning
cc-disable-warning = $(call try-run,\
	$(CC) $(KBUILD_CPPFLAGS) $(KBUILD_CFLAGS) -W$(strip $(1)) -c -xc /dev/null -o "$$TMP",-Wno-$(strip $(1)))
endif
EXTRA_CFLAGS = -Werror $(call cc-disable-warning, unused-but-set-variable)
'

# Ensure it looks like a build tree and we can build a module
[ -d "$KPATH" ] || fail "$KPATH is not a directory"
[ -f "$KPATH/Makefile" ] || fail "$KPATH/Makefile is not present"
test_compile "#include <linux/module.h>" || \
    fail "Kernel build tree is unable to build modules"

# strip the KVER out of UTS_RELEASE, and compare to the specified KVER
_KVER=
for F in include/generated/utsrelease.h include/linux/utsrelease.h include/linux/version.h; do
    [ -f $KPATH/$F ] && _KVER="$(eval echo $(read_define UTS_RELEASE $F))" && break
done
[ -n "$_KVER" ] || fail "Unable to identify kernel version from $KPATH"
if [ -n "$KVER" ]; then
    [ "$KVER" = "$_KVER" ] || fail "$KPATH kernel version $_KVER does not match $KVER"
fi
KVER=$_KVER
unset _KVER

vmsg "KVER       := $KVER"
vmsg "KPATH      := $KPATH"

# Read the following variables from the Makefile:
#  KBUILD_SRC:            Root of source tree (not the same as KPATH under SUSE)
#  ARCH:                  Target architecture name
#  SRCARCH:               Target architecture directory name (2.6.24 onward)
#  CONFIG_X86_{32,64}:    Work around ARCH = x86 madness
#  CONFIG_PTP_1588_CLOCK: PTP clock support
[ -n "$ARCH" ] && export ARCH
eval $(read_make_variables KBUILD_SRC ARCH SRCARCH CONFIG_X86_32 CONFIG_X86_64 CONFIG_PTP_1588_CLOCK)

# Define:
#     KBUILD_SRC:         If not already set, same as KPATH
#     SRCARCH:            If not already set, same as ARCH
#     WORDSUFFIX:         Suffix added to some filenames by the i386/amd64 merge
[ -n "${KBUILD_SRC:-}" ] || KBUILD_SRC=$KPATH
[ -n "${SRCARCH:-}" ] || SRCARCH=$ARCH
if [ "$ARCH" = "i386" ] || [ "${CONFIG_X86_32:-}" = "y" ]; then
    WORDSUFFIX=_32
elif [ "$ARCH" = "x86_64" ] || [ "${CONFIG_X86_64:-}" = "y" ]; then
    WORDSUFFIX=_64
else
    WORDSUFFIX=
fi
[ -f "$KBUILD_SRC/arch/$SRCARCH/Makefile" ] || fail "$KBUILD_SRC doesn't directly build $SRCARCH"

vmsg "KBUILD_SRC := $KBUILD_SRC"
vmsg "SRCARCH    := $SRCARCH"
vmsg "WORDSUFFIX := $WORDSUFFIX"

# try and find the System map [used by test_export]
if [ -z "$MAP" ]; then
    if [ -f /boot/System.map-$KVER ]; then
	MAP=/boot/System.map-$KVER
    elif [ $KVER = "`uname -r`" ] && [ -f /proc/kallsyms ]; then
	MAP=/proc/kallsyms
    elif [ -f $KPATH/Module.symvers ]; then
	# can use this to find external symbols only
	true
    else
	vmsg "!!Unable to find a valid System map. Export symbol checks may not work"
    fi
fi

if [ "$kompat_symbols" == "" ]; then
    kompat_symbols="$(generate_kompat_symbols)"
fi

# filter the available symbols
if [ -n "$FILTER" ]; then
    kompat_symbols="$(echo "$kompat_symbols" | egrep "^($FILTER):")"
fi

compile_dir="$(mktemp -d)"
rmfiles="$rmfiles $compile_dir"
echo >"$compile_dir/Makefile" "$makefile_prefix"
echo >"$compile_dir/_autocompat.h"
deferred_pos=
deferred_neg=

# Note that for deferred tests this runs after the Makefile has run all tests
function do_one_symbol() {
    local key=$1
    shift
    # NB work is in the following if clause "do_${method}"
    if "$@"; then
	echo "#define $key yes"
	# So that future compile tests can consume this
	echo "#define $key yes" >> "${compile_dir}/_autocompat.h"
    elif [ $? -ne $DEFERRED ]; then
	echo "// #define $key"
    fi
}

# process each symbol
for symbol in $kompat_symbols; do
    # split symbol at colons; disable globbing (pathname expansion)
    set -o noglob
    IFS=:
    set -- $symbol
    unset IFS
    set +o noglob

    key="$1"
    method="$2"
    do_one_symbol $key do_${method} "$@"
done

# Run the deferred compile tests
eval make -C $KPATH -k $EXTRA_MAKEFLAGS M="$compile_dir" \
    >"$compile_dir/log" 2>&1 \
    || true
if [ $verbose = true ]; then
    echo >&2 "compiler output:"
    sed >&2 's/^/    /' "$compile_dir/log"
fi
for key in $deferred_pos; do
    # Use existence of object file as evidence of compile without warning/errors
    do_one_symbol $key test -f "$compile_dir/test_$key.o"
done
for key in $deferred_neg; do
    do_one_symbol $key test ! -f "$compile_dir/test_$key.o"
done
