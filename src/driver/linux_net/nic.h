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
 * Copyright 2006-2015 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_NIC_H
#define EFX_NIC_H

#ifndef EFX_USE_KCOMPAT
#include <linux/net_tstamp.h>
#endif
#include <linux/i2c-algo-bit.h>
#include <linux/timer.h>

#include "net_driver.h"
#include "efx.h"
#include "mcdi.h"

enum {
	EFX_REV_FALCON_A0 = 0,
	EFX_REV_FALCON_A1 = 1,
	EFX_REV_FALCON_B0 = 2,
	EFX_REV_SIENA_A0 = 3,
	EFX_REV_HUNT_A0 = 4,
};

static inline int efx_nic_rev(struct efx_nic *efx)
{
	return efx->type->revision;
}

u32 efx_farch_fpga_ver(struct efx_nic *efx);

#ifdef CONFIG_SFC_FALCON
/* NIC has two interlinked PCI functions for the same port. */
static inline bool efx_nic_is_dual_func(struct efx_nic *efx)
{
	return efx_nic_rev(efx) < EFX_REV_FALCON_B0;
}
#endif

/* Read the current event from the event queue */
static inline efx_qword_t *efx_event(struct efx_channel *channel,
				     unsigned int index)
{
	return ((efx_qword_t *) (channel->eventq.buf.addr)) +
		(index & channel->eventq_mask);
}

/* See if an event is present
 *
 * We check both the high and low dword of the event for all ones.  We
 * wrote all ones when we cleared the event, and no valid event can
 * have all ones in either its high or low dwords.  This approach is
 * robust against reordering.
 *
 * Note that using a single 64-bit comparison is incorrect; even
 * though the CPU read will be atomic, the DMA write may not be.
 */
static inline int efx_event_present(efx_qword_t *event)
{
	return !(EFX_DWORD_IS_ALL_ONES(event->dword[0]) |
		  EFX_DWORD_IS_ALL_ONES(event->dword[1]));
}

/* Returns a pointer to the specified transmit descriptor in the TX
 * descriptor queue belonging to the specified channel.
 */
static inline efx_qword_t *
efx_tx_desc(struct efx_tx_queue *tx_queue, unsigned int index)
{
	return ((efx_qword_t *) (tx_queue->txd.buf.addr)) + index;
}

/* Report whether the NIC considers this TX queue empty, given the
 * write_count used for the last doorbell push.  May return false
 * negative.
 */
static inline bool __efx_nic_tx_is_empty(struct efx_tx_queue *tx_queue,
					 unsigned int write_count)
{
	unsigned int empty_read_count = ACCESS_ONCE(tx_queue->empty_read_count);

	if (empty_read_count == 0)
		return false;

	return ((empty_read_count ^ write_count) & ~EFX_EMPTY_COUNT_VALID) == 0;
}

/* Returns a pointer to the specified descriptor in the RX descriptor queue */
static inline efx_qword_t *
efx_rx_desc(struct efx_rx_queue *rx_queue, unsigned int index)
{
	return ((efx_qword_t *) (rx_queue->rxd.buf.addr)) + index;
}

enum {
	PHY_TYPE_NONE = 0,
	PHY_TYPE_TXC43128 = 1,
	PHY_TYPE_88E1111 = 2,
	PHY_TYPE_SFX7101 = 3,
	PHY_TYPE_QT2022C2 = 4,
	PHY_TYPE_PM8358 = 6,
	PHY_TYPE_SFT9001A = 8,
	PHY_TYPE_QT2025C = 9,
	PHY_TYPE_SFT9001B = 10,
};

#define FALCON_XMAC_LOOPBACKS			\
	((1 << LOOPBACK_XGMII) |		\
	 (1 << LOOPBACK_XGXS) |			\
	 (1 << LOOPBACK_XAUI))

/* Alignment of PCIe DMA boundaries (4KB) */
#define EFX_PAGE_SIZE	4096
/* Size and alignment of buffer table entries (same) */
#define EFX_BUF_SIZE	EFX_PAGE_SIZE

/* NIC-generic software stats */
enum {
	GENERIC_STAT_rx_noskb_drops,
	GENERIC_STAT_rx_nodesc_trunc,
	GENERIC_STAT_COUNT
};

#ifdef CONFIG_SFC_FALCON
/**
 * struct falcon_board_type - board operations and type information
 * @id: Board type id, as found in NVRAM
 * @init: Allocate resources and initialise peripheral hardware
 * @init_phy: Do board-specific PHY initialisation
 * @fini: Shut down hardware and free resources
 * @set_id_led: Set state of identifying LED or revert to automatic function
 * @monitor: Board-specific health check function
 */
struct falcon_board_type {
	u8 id;
	int (*init) (struct efx_nic *nic);
	void (*init_phy) (struct efx_nic *efx);
	void (*fini) (struct efx_nic *nic);
	void (*set_id_led) (struct efx_nic *efx, enum efx_led_mode mode);
	int (*monitor) (struct efx_nic *nic);
};

/**
 * struct falcon_board - board information
 * @type: Type of board
 * @major: Major rev. ('A', 'B' ...)
 * @minor: Minor rev. (0, 1, ...)
 * @i2c_adap: I2C adapter for on-board peripherals
 * @i2c_data: Data for bit-banging algorithm
 * @hwmon_client: I2C client for hardware monitor
 * @ioexp_client: I2C client for power/port control
 */
struct falcon_board {
	const struct falcon_board_type *type;
	int major;
	int minor;
#ifdef CONFIG_SFC_I2C
	struct i2c_adapter i2c_adap;
	struct i2c_algo_bit_data i2c_data;
	struct i2c_client *hwmon_client, *ioexp_client;
#endif
};

/**
 * struct falcon_spi_device - a Falcon SPI (Serial Peripheral Interface) device
 * @device_id:		Controller's id for the device
 * @size:		Size (in bytes)
 * @addr_len:		Number of address bytes in read/write commands
 * @munge_address:	Flag whether addresses should be munged.
 *	Some devices with 9-bit addresses (e.g. AT25040A EEPROM)
 *	use bit 3 of the command byte as address bit A8, rather
 *	than having a two-byte address.  If this flag is set, then
 *	commands should be munged in this way.
 * @erase_command:	Erase command (or 0 if sector erase not needed).
 * @erase_size:		Erase sector size (in bytes)
 *	Erase commands affect sectors with this size and alignment.
 *	This must be a power of two.
 * @block_size:		Write block size (in bytes).
 *	Write commands are limited to blocks with this size and alignment.
 */
struct falcon_spi_device {
	int device_id;
	unsigned int size;
	unsigned int addr_len;
	unsigned int munge_address:1;
	u8 erase_command;
	unsigned int erase_size;
	unsigned int block_size;
};

static inline bool falcon_spi_present(const struct falcon_spi_device *spi)
{
	return spi->size != 0;
}

enum {
	FALCON_STAT_tx_bytes = GENERIC_STAT_COUNT,
	FALCON_STAT_tx_packets,
	FALCON_STAT_tx_pause,
	FALCON_STAT_tx_control,
	FALCON_STAT_tx_unicast,
	FALCON_STAT_tx_multicast,
	FALCON_STAT_tx_broadcast,
	FALCON_STAT_tx_lt64,
	FALCON_STAT_tx_64,
	FALCON_STAT_tx_65_to_127,
	FALCON_STAT_tx_128_to_255,
	FALCON_STAT_tx_256_to_511,
	FALCON_STAT_tx_512_to_1023,
	FALCON_STAT_tx_1024_to_15xx,
	FALCON_STAT_tx_15xx_to_jumbo,
	FALCON_STAT_tx_gtjumbo,
	FALCON_STAT_tx_non_tcpudp,
	FALCON_STAT_tx_mac_src_error,
	FALCON_STAT_tx_ip_src_error,
	FALCON_STAT_rx_bytes,
	FALCON_STAT_rx_good_bytes,
	FALCON_STAT_rx_bad_bytes,
	FALCON_STAT_rx_packets,
	FALCON_STAT_rx_good,
	FALCON_STAT_rx_bad,
	FALCON_STAT_rx_pause,
	FALCON_STAT_rx_control,
	FALCON_STAT_rx_unicast,
	FALCON_STAT_rx_multicast,
	FALCON_STAT_rx_broadcast,
	FALCON_STAT_rx_lt64,
	FALCON_STAT_rx_64,
	FALCON_STAT_rx_65_to_127,
	FALCON_STAT_rx_128_to_255,
	FALCON_STAT_rx_256_to_511,
	FALCON_STAT_rx_512_to_1023,
	FALCON_STAT_rx_1024_to_15xx,
	FALCON_STAT_rx_15xx_to_jumbo,
	FALCON_STAT_rx_gtjumbo,
	FALCON_STAT_rx_bad_lt64,
	FALCON_STAT_rx_bad_gtjumbo,
	FALCON_STAT_rx_overflow,
	FALCON_STAT_rx_symbol_error,
	FALCON_STAT_rx_align_error,
	FALCON_STAT_rx_length_error,
	FALCON_STAT_rx_internal_error,
	FALCON_STAT_rx_nodesc_drop_cnt,
	FALCON_STAT_COUNT
};

/**
 * struct falcon_nic_data - Falcon NIC state
 * @sram_config: NIC SRAM configuration code
 * @pci_dev2: Secondary function of Falcon A
 * @board: Board state and functions
 * @stats: Hardware statistics
 * @stats_disable_count: Nest count for disabling statistics fetches
 * @stats_pending: Is there a pending DMA of MAC statistics.
 * @stats_timer: A timer for regularly fetching MAC statistics.
 * @spi_flash: SPI flash device
 * @spi_eeprom: SPI EEPROM device
 * @spi_lock: SPI bus lock
 * @mdio_lock: MDIO bus lock
 * @xmac_poll_required: XMAC link state needs polling
 */
struct falcon_nic_data {
	int sram_config;
	struct pci_dev *pci_dev2;
	struct falcon_board board;
	u64 stats[FALCON_STAT_COUNT];
	unsigned int stats_disable_count;
	bool stats_pending;
	struct timer_list stats_timer;
	struct falcon_spi_device spi_flash;
	struct falcon_spi_device spi_eeprom;
	struct mutex spi_lock;
	struct mutex mdio_lock;
	bool xmac_poll_required;
};

static inline struct falcon_board *falcon_board(struct efx_nic *efx)
{
	struct falcon_nic_data *nic_data;
	EFX_BUG_ON_PARANOID(efx_nic_rev(efx) > EFX_REV_FALCON_B0);
	nic_data = efx->nic_data;
	return &nic_data->board;
}
#endif /* CONFIG_SFC_FALCON */

enum {
	SIENA_STAT_tx_bytes = GENERIC_STAT_COUNT,
	SIENA_STAT_tx_good_bytes,
	SIENA_STAT_tx_bad_bytes,
	SIENA_STAT_tx_packets,
	SIENA_STAT_tx_bad,
	SIENA_STAT_tx_pause,
	SIENA_STAT_tx_control,
	SIENA_STAT_tx_unicast,
	SIENA_STAT_tx_multicast,
	SIENA_STAT_tx_broadcast,
	SIENA_STAT_tx_lt64,
	SIENA_STAT_tx_64,
	SIENA_STAT_tx_65_to_127,
	SIENA_STAT_tx_128_to_255,
	SIENA_STAT_tx_256_to_511,
	SIENA_STAT_tx_512_to_1023,
	SIENA_STAT_tx_1024_to_15xx,
	SIENA_STAT_tx_15xx_to_jumbo,
	SIENA_STAT_tx_gtjumbo,
	SIENA_STAT_tx_collision,
	SIENA_STAT_tx_single_collision,
	SIENA_STAT_tx_multiple_collision,
	SIENA_STAT_tx_excessive_collision,
	SIENA_STAT_tx_deferred,
	SIENA_STAT_tx_late_collision,
	SIENA_STAT_tx_excessive_deferred,
	SIENA_STAT_tx_non_tcpudp,
	SIENA_STAT_tx_mac_src_error,
	SIENA_STAT_tx_ip_src_error,
	SIENA_STAT_rx_bytes,
	SIENA_STAT_rx_good_bytes,
	SIENA_STAT_rx_bad_bytes,
	SIENA_STAT_rx_packets,
	SIENA_STAT_rx_good,
	SIENA_STAT_rx_bad,
	SIENA_STAT_rx_pause,
	SIENA_STAT_rx_control,
	SIENA_STAT_rx_unicast,
	SIENA_STAT_rx_multicast,
	SIENA_STAT_rx_broadcast,
	SIENA_STAT_rx_lt64,
	SIENA_STAT_rx_64,
	SIENA_STAT_rx_65_to_127,
	SIENA_STAT_rx_128_to_255,
	SIENA_STAT_rx_256_to_511,
	SIENA_STAT_rx_512_to_1023,
	SIENA_STAT_rx_1024_to_15xx,
	SIENA_STAT_rx_15xx_to_jumbo,
	SIENA_STAT_rx_gtjumbo,
	SIENA_STAT_rx_bad_gtjumbo,
	SIENA_STAT_rx_overflow,
	SIENA_STAT_rx_false_carrier,
	SIENA_STAT_rx_symbol_error,
	SIENA_STAT_rx_align_error,
	SIENA_STAT_rx_length_error,
	SIENA_STAT_rx_internal_error,
	SIENA_STAT_rx_nodesc_drop_cnt,
	SIENA_STAT_rx_char_error_lane0,
	SIENA_STAT_rx_char_error_lane1,
	SIENA_STAT_rx_char_error_lane2,
	SIENA_STAT_rx_char_error_lane3,
	SIENA_STAT_rx_disp_error_lane0,
	SIENA_STAT_rx_disp_error_lane1,
	SIENA_STAT_rx_disp_error_lane2,
	SIENA_STAT_rx_disp_error_lane3,
	SIENA_STAT_rx_match_fault,
	SIENA_STAT_COUNT
};

/**
 * struct siena_nic_data - Siena NIC state
 * @efx: Pointer back to main interface structure
 * @wol_filter_id: Wake-on-LAN packet filter id
 * @stats: Hardware statistics
 * @vf: Array of &struct siena_vf objects
 * @vf_rtnl_count: Number of VFs exposed to rtnetlink.
 * @vf_buftbl_base: The zeroth buffer table index used to back VF queues.
 * @vfdi_status: Common VFDI status page to be dmad to VF address space.
 * @local_addr_list: List of local addresses. Protected by %local_lock.
 * @local_page_list: List of DMA addressable pages used to broadcast
 *	%local_addr_list. Protected by %local_lock.
 * @local_lock: Mutex protecting %local_addr_list and %local_page_list.
 * @peer_work: Work item to broadcast peer addresses to VMs.
 */
struct siena_nic_data {
	struct efx_nic *efx;
	int wol_filter_id;
	u32 caps;
	u64 stats[SIENA_STAT_COUNT];
#ifdef CONFIG_SFC_SRIOV
	struct siena_vf *vf;
	struct efx_channel *vfdi_channel;
	unsigned int vf_rtnl_count;
	struct efx_buffer vfdi_status;
	struct list_head local_addr_list;
	struct list_head local_page_list;
	struct mutex local_lock;
	struct work_struct peer_work;
	struct efx_dl_siena_sriov sriov_resources;
#endif
};

enum {
	EF10_STAT_port_tx_bytes = GENERIC_STAT_COUNT,
	EF10_STAT_port_tx_packets,
	EF10_STAT_port_tx_pause,
	EF10_STAT_port_tx_control,
	EF10_STAT_port_tx_unicast,
	EF10_STAT_port_tx_multicast,
	EF10_STAT_port_tx_broadcast,
	EF10_STAT_port_tx_lt64,
	EF10_STAT_port_tx_64,
	EF10_STAT_port_tx_65_to_127,
	EF10_STAT_port_tx_128_to_255,
	EF10_STAT_port_tx_256_to_511,
	EF10_STAT_port_tx_512_to_1023,
	EF10_STAT_port_tx_1024_to_15xx,
	EF10_STAT_port_tx_15xx_to_jumbo,
	EF10_STAT_port_rx_bytes,
	EF10_STAT_port_rx_bytes_minus_good_bytes,
	EF10_STAT_port_rx_good_bytes,
	EF10_STAT_port_rx_bad_bytes,
	EF10_STAT_port_rx_packets,
	EF10_STAT_port_rx_good,
	EF10_STAT_port_rx_bad,
	EF10_STAT_port_rx_pause,
	EF10_STAT_port_rx_control,
	EF10_STAT_port_rx_unicast,
	EF10_STAT_port_rx_multicast,
	EF10_STAT_port_rx_broadcast,
	EF10_STAT_port_rx_lt64,
	EF10_STAT_port_rx_64,
	EF10_STAT_port_rx_65_to_127,
	EF10_STAT_port_rx_128_to_255,
	EF10_STAT_port_rx_256_to_511,
	EF10_STAT_port_rx_512_to_1023,
	EF10_STAT_port_rx_1024_to_15xx,
	EF10_STAT_port_rx_15xx_to_jumbo,
	EF10_STAT_port_rx_gtjumbo,
	EF10_STAT_port_rx_bad_gtjumbo,
	EF10_STAT_port_rx_overflow,
	EF10_STAT_port_rx_align_error,
	EF10_STAT_port_rx_length_error,
	EF10_STAT_port_rx_nodesc_drops,
	EF10_STAT_port_rx_pm_trunc_bb_overflow,
	EF10_STAT_port_rx_pm_discard_bb_overflow,
	EF10_STAT_port_rx_pm_trunc_vfifo_full,
	EF10_STAT_port_rx_pm_discard_vfifo_full,
	EF10_STAT_port_rx_pm_trunc_qbb,
	EF10_STAT_port_rx_pm_discard_qbb,
	EF10_STAT_port_rx_pm_discard_mapping,
	EF10_STAT_port_rx_dp_q_disabled_packets,
	EF10_STAT_port_rx_dp_di_dropped_packets,
	EF10_STAT_port_rx_dp_streaming_packets,
	EF10_STAT_port_rx_dp_hlb_fetch,
	EF10_STAT_port_rx_dp_hlb_wait,
	EF10_STAT_rx_unicast,
	EF10_STAT_rx_unicast_bytes,
	EF10_STAT_rx_multicast,
	EF10_STAT_rx_multicast_bytes,
	EF10_STAT_rx_broadcast,
	EF10_STAT_rx_broadcast_bytes,
	EF10_STAT_rx_bad,
	EF10_STAT_rx_bad_bytes,
	EF10_STAT_rx_overflow,
	EF10_STAT_tx_unicast,
	EF10_STAT_tx_unicast_bytes,
	EF10_STAT_tx_multicast,
	EF10_STAT_tx_multicast_bytes,
	EF10_STAT_tx_broadcast,
	EF10_STAT_tx_broadcast_bytes,
	EF10_STAT_tx_bad,
	EF10_STAT_tx_bad_bytes,
	EF10_STAT_tx_overflow,
	EF10_STAT_COUNT
};

/* Maximum number of TX PIO buffers we may allocate to a function.
 * This matches the total number of buffers on each SFC9100-family
 * controller.
 */
#define EF10_TX_PIOBUF_COUNT 16

/**
 * struct efx_ef10_nic_data - EF10 architecture NIC state
 * @efx: Pointer back to main interface structure
 * @mcdi_buf: DMA buffer for MCDI
 * @warm_boot_count: Last seen MC warm boot count
 * @vi_base: Absolute index of first VI in this function
 * @n_allocated_vis: Number of VIs allocated to this function
 * @must_realloc_vis: Flag: VIs have yet to be reallocated after MC reboot
 * @must_restore_filters: Flag: filters have yet to be restored after MC reboot
 * @n_piobufs: Number of PIO buffers allocated to this function
 * @wc_membase: Base address of write-combining mapping of the memory BAR
 * @pio_write_base: Base address for writing PIO buffers
 * @pio_write_vi_base: Relative VI number for @pio_write_base
 * @piobuf_handle: Handle of each PIO buffer allocated
 * @piobuf_size: size of a single PIO buffer
 * @must_restore_piobufs: Flag: PIO buffers have yet to be restored after MC
 *	reboot
 * @rx_rss_context: Firmware handle for our RSS context
 * @rx_rss_context_exclusive: Whether our RSS context is exclusive or shared
 * @stats: Hardware statistics
 * @vf_stats_work: Work item to poll hardware statistics (VF driver only)
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
 * @vf_stats_enabled: Marker to avoid stats work rearming if
 *	cancel_delayed_work_sync() is not availble. Serialized by stats_lock.
#endif
 * @workaround_35388: Flag: firmware supports workaround for bug 35388
 * @workaround_26807: Flag: firmware supports workaround for bug 26807
 * @workaround_61265: Flag: firmware supports workaround for bug 61265
 * @must_check_datapath_caps: Flag: @datapath_caps needs to be revalidated
 *	after MC reboot
 * @datapath_caps: Capabilities of datapath firmware (FLAGS1 field of
 *	%MC_CMD_GET_CAPABILITIES response)
 * @datapath_caps2: Further capabilities of datapath firmware (FLAGS2 field of
 *	%MC_CMD_GET_CAPABILITIES_V2 response)
 * @vport_id: The function's vport ID, only relevant for PFs
 * @must_probe_vswitching: Flag: vswitching has yet to be setup after MC reboot
 * @pf_index: The number for this PF, or the parent PF if this is a VF
#ifdef CONFIG_SFC_SRIOV
 * @vf: Pointer to VF data structure
#endif
 * @vport_mac: The MAC address on the vport, only for PFs; VFs will be zero
 * @vlan_list: List of VLANs added over the interface. Serialised by vlan_lock.
 * @vlan_lock: Lock to serialize access to vlan_list.
 * @udp_tunnels: UDP tunnel port numbers and types.
 * @udp_tunnels_dirty: flag indicating a reboot occurred while pushing
 *	@udp_tunnels to hardware and thus the push must be re-done.
 * @udp_tunnels_lock: Serialises writes to @udp_tunnels and @udp_tunnels_dirty.
 */
struct efx_ef10_nic_data {
	struct efx_nic *efx;
	struct efx_buffer mcdi_buf;
	u16 warm_boot_count;
	unsigned int vi_base;
	unsigned int n_allocated_vis;
	bool must_realloc_vis;
	bool must_restore_filters;
	unsigned int n_piobufs;
	void __iomem *wc_membase, *pio_write_base;
	unsigned int pio_write_vi_base;
	unsigned int piobuf_handle[EF10_TX_PIOBUF_COUNT];
	u16 piobuf_size;
	bool must_restore_piobufs;
	u32 rx_rss_context;
	bool rx_rss_context_exclusive;
	u64 stats[EF10_STAT_COUNT];
	struct delayed_work vf_stats_work;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
	bool vf_stats_enabled;
#endif
	bool workaround_35388;
	bool workaround_26807;
	bool workaround_61265;
	bool must_check_datapath_caps;
	u32 datapath_caps;
	u32 datapath_caps2;
	unsigned int vport_id;
	bool must_probe_vswitching;
	unsigned int pf_index;
	unsigned int vf_index;
	u8 port_id[ETH_ALEN];
#ifdef CONFIG_SFC_SRIOV
	struct ef10_vf *vf;
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_AOE)
	uint32_t caps;
#endif
	u8 vport_mac[ETH_ALEN];
	struct list_head vlan_list;
	struct mutex vlan_lock;
	struct efx_udp_tunnel udp_tunnels[16];
	bool udp_tunnels_dirty;
	struct mutex udp_tunnels_lock;
	u64 licensed_features;
};

int efx_init_sriov(void);
void efx_fini_sriov(void);

unsigned int efx_nic_calc_mac_mtu(struct efx_nic *efx);

struct ethtool_ts_info;
#ifdef CONFIG_SFC_PTP
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
struct hwtstamp_config;
struct efx_ts_read;
int efx_ptp_ts_init(struct efx_nic *efx, struct hwtstamp_config *init);
int efx_ptp_ts_read(struct efx_nic *efx, struct efx_ts_read *read);
#endif
#if defined(EFX_NOT_UPSTREAM)
struct efx_ts_settime;
struct efx_ts_adjtime;
struct efx_ts_sync;
struct efx_ts_set_sync_status;
struct efx_ts_set_vlan_filter;
struct efx_ts_set_uuid_filter;
struct efx_ts_set_domain_filter;
int efx_ptp_ts_settime(struct efx_nic *efx, struct efx_ts_settime *settime);
int efx_ptp_ts_adjtime(struct efx_nic *efx, struct efx_ts_adjtime *adjtime);
int efx_ptp_ts_sync(struct efx_nic *efx, struct efx_ts_sync *sync);
int efx_ptp_ts_set_sync_status(struct efx_nic *efx, struct efx_ts_set_sync_status *status);
int efx_ptp_ts_set_vlan_filter(struct efx_nic *efx, struct efx_ts_set_vlan_filter *vlan_filter);
int efx_ptp_ts_set_uuid_filter(struct efx_nic *efx, struct efx_ts_set_uuid_filter *uuid_filter);
int efx_ptp_ts_set_domain_filter(struct efx_nic *efx, struct efx_ts_set_domain_filter *domain_filter);
#endif
int efx_ptp_probe(struct efx_nic *efx, struct efx_channel *channel);
void efx_ptp_defer_probe_with_channel(struct efx_nic *efx);
struct efx_channel *efx_ptp_channel(struct efx_nic *efx);
void efx_ptp_remove(struct efx_nic *efx);
int efx_ptp_set_ts_config(struct efx_nic *efx, struct ifreq *ifr);
int efx_ptp_get_ts_config(struct efx_nic *efx, struct ifreq *ifr);
void efx_ptp_get_ts_info(struct efx_nic *efx, struct ethtool_ts_info *ts_info);
bool efx_ptp_is_ptp_tx(struct efx_nic *efx, struct sk_buff *skb);
int efx_ptp_get_mode(struct efx_nic *efx);
int efx_ptp_change_mode(struct efx_nic *efx, bool enable_wanted,
			unsigned int new_mode);
int efx_ptp_tx(struct efx_nic *efx, struct sk_buff *skb);
void efx_ptp_event(struct efx_nic *efx, efx_qword_t *ev);
size_t efx_ptp_describe_stats(struct efx_nic *efx, u8 *strings);
size_t efx_ptp_update_stats(struct efx_nic *efx, u64 *stats);
void efx_time_sync_event(struct efx_channel *channel, efx_qword_t *ev);
void __efx_rx_skb_attach_timestamp(struct efx_channel *channel,
				   struct sk_buff *skb);
static inline void efx_rx_skb_attach_timestamp(struct efx_channel *channel,
					       struct sk_buff *skb)
{
	__efx_rx_skb_attach_timestamp(channel, skb);
}
void efx_ptp_start_datapath(struct efx_nic *efx);
void efx_ptp_stop_datapath(struct efx_nic *efx);
bool efx_ptp_use_mac_tx_timestamps(struct efx_nic *efx);
ktime_t efx_ptp_nic_to_kernel_time(struct efx_tx_queue *tx_queue);
#else
static inline int efx_ptp_probe(struct efx_nic *efx, struct efx_channel *channel)
{ return -ENODEV; }
static inline void efx_ptp_defer_probe_with_channel(struct efx_nic *efx) {}
static inline struct efx_channel *efx_ptp_channel(struct efx_nic *efx)
{
	return NULL;
}
static inline void efx_ptp_remove(struct efx_nic *efx) {}
static inline int efx_ptp_set_ts_config(struct efx_nic *efx, struct ifreq *ifr) {return -EOPNOTSUPP; }
static inline int efx_ptp_get_ts_config(struct efx_nic *efx, struct ifreq *ifr) {return -EOPNOTSUPP; }
static inline int efx_ptp_get_ts_info(struct efx_nic *efx,
				      struct ethtool_ts_info *ts_info)
{ return -EOPNOTSUPP; }
static inline bool efx_ptp_is_ptp_tx(struct efx_nic *efx, struct sk_buff *skb) { return false; }
static inline int efx_ptp_tx(struct efx_nic *efx, struct sk_buff *skb) { return NETDEV_TX_OK; }
static inline void efx_ptp_event(struct efx_nic *efx, efx_qword_t *ev) {}
static inline size_t efx_ptp_describe_stats(struct efx_nic *efx, u8 *strings)
{ return 0; }
static inline size_t efx_ptp_update_stats(struct efx_nic *efx, u64 *stats)
{ return 0; }
static inline void efx_rx_skb_attach_timestamp(struct efx_channel *channel,
					       struct sk_buff *skb) {}
static inline void efx_time_sync_event(struct efx_channel *channel,
				       efx_qword_t *ev) {}
static inline void efx_ptp_start_datapath(struct efx_nic *efx) {}
static inline void efx_ptp_stop_datapath(struct efx_nic *efx) {}
static inline bool efx_ptp_use_mac_tx_timestamps(struct efx_nic *efx)
{
	return false;
}
static inline ktime_t efx_ptp_nic_to_kernel_time(struct efx_tx_queue *tx_queue)
{
	return (ktime_t) { 0 };
}
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
struct efx_ts_get_pps;
struct efx_ts_hw_pps;
int efx_ptp_pps_get_event(struct efx_nic *efx, struct efx_ts_get_pps *data);
int efx_ptp_hw_pps_enable(struct efx_nic *efx, struct efx_ts_hw_pps *data);
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_AOE)
int efx_aoe_attach(struct efx_nic *efx);
void efx_aoe_detach(struct efx_nic *efx);
#endif

#ifdef EFX_NOT_UPSTREAM
struct efx_update_license2;
int efx_ef10_update_keys(struct efx_nic *efx,
			 struct efx_update_license2 *key_stats);
struct efx_licensed_app_state;
int efx_ef10_licensed_app_state(struct efx_nic *efx,
				struct efx_licensed_app_state *app_state);
#endif

#ifdef CONFIG_SFC_FALCON
extern const struct efx_nic_type falcon_a1_nic_type;
extern const struct efx_nic_type falcon_b0_nic_type;
#endif
extern const struct efx_nic_type siena_a0_nic_type;
extern const struct efx_nic_type efx_hunt_a0_nic_type;
extern const struct efx_nic_type efx_hunt_a0_vf_nic_type;

/**************************************************************************
 *
 * Externs
 *
 **************************************************************************
 */

#ifdef CONFIG_SFC_FALCON
int falcon_probe_board(struct efx_nic *efx, u16 revision_info);
#endif

/* TX data path */
static inline int efx_nic_probe_tx(struct efx_tx_queue *tx_queue)
{
	return tx_queue->efx->type->tx_probe(tx_queue);
}
static inline int efx_nic_init_tx(struct efx_tx_queue *tx_queue)
{
	return tx_queue->efx->type->tx_init(tx_queue);
}
static inline void efx_nic_remove_tx(struct efx_tx_queue *tx_queue)
{
	tx_queue->efx->type->tx_remove(tx_queue);
}
static inline void efx_nic_push_buffers(struct efx_tx_queue *tx_queue)
{
	tx_queue->efx->type->tx_write(tx_queue);
}
static inline void efx_nic_notify_tx_desc(struct efx_tx_queue *tx_queue)
{
	tx_queue->efx->type->tx_notify(tx_queue);
}

/* RX data path */
static inline int efx_nic_probe_rx(struct efx_rx_queue *rx_queue)
{
	return rx_queue->efx->type->rx_probe(rx_queue);
}
static inline int efx_nic_init_rx(struct efx_rx_queue *rx_queue)
{
	return rx_queue->efx->type->rx_init(rx_queue);
}
static inline void efx_nic_remove_rx(struct efx_rx_queue *rx_queue)
{
	rx_queue->efx->type->rx_remove(rx_queue);
}
static inline void efx_nic_notify_rx_desc(struct efx_rx_queue *rx_queue)
{
	rx_queue->efx->type->rx_write(rx_queue);
}
static inline int efx_nic_generate_fill_event(struct efx_rx_queue *rx_queue)
{
	return rx_queue->efx->type->rx_defer_refill(rx_queue);
}

/* Event data path */
static inline int efx_nic_probe_eventq(struct efx_channel *channel)
{
	return channel->efx->type->ev_probe(channel);
}
static inline int efx_nic_init_eventq(struct efx_channel *channel)
{
	return channel->efx->type->ev_init(channel);
}
static inline void efx_nic_fini_eventq(struct efx_channel *channel)
{
	channel->efx->type->ev_fini(channel);
}
static inline void efx_nic_remove_eventq(struct efx_channel *channel)
{
	channel->efx->type->ev_remove(channel);
}
static inline int
efx_nic_process_eventq(struct efx_channel *channel, int quota)
{
	return channel->efx->type->ev_process(channel, quota);
}
static inline void efx_nic_eventq_read_ack(struct efx_channel *channel)
{
	channel->efx->type->ev_read_ack(channel);
}
static inline bool efx_nic_hw_unavailable(struct efx_nic *efx)
{
	if (efx->type->hw_unavailable)
		return efx->type->hw_unavailable(efx);
	return false;
}
void efx_nic_event_test_start(struct efx_channel *channel);

/* Falcon/Siena queue operations */
int efx_farch_tx_probe(struct efx_tx_queue *tx_queue);
int efx_farch_tx_init(struct efx_tx_queue *tx_queue);
void efx_farch_tx_fini(struct efx_tx_queue *tx_queue);
void efx_farch_tx_remove(struct efx_tx_queue *tx_queue);
void efx_farch_tx_write(struct efx_tx_queue *tx_queue);
void efx_farch_notify_tx_desc(struct efx_tx_queue *tx_queue);
unsigned int efx_farch_tx_limit_len(struct efx_tx_queue *tx_queue,
				    dma_addr_t dma_addr, unsigned int len);
int efx_farch_rx_probe(struct efx_rx_queue *rx_queue);
int efx_farch_rx_init(struct efx_rx_queue *rx_queue);
void efx_farch_rx_fini(struct efx_rx_queue *rx_queue);
void efx_farch_rx_remove(struct efx_rx_queue *rx_queue);
void efx_farch_rx_write(struct efx_rx_queue *rx_queue);
int efx_farch_rx_defer_refill(struct efx_rx_queue *rx_queue);
int efx_farch_ev_probe(struct efx_channel *channel);
int efx_farch_ev_init(struct efx_channel *channel);
void efx_farch_ev_fini(struct efx_channel *channel);
void efx_farch_ev_remove(struct efx_channel *channel);
int efx_farch_ev_process(struct efx_channel *channel, int quota);
void efx_farch_ev_read_ack(struct efx_channel *channel);
void efx_farch_ev_test_generate(struct efx_channel *channel);

/* Falcon/Siena filter operations */
int efx_farch_filter_table_probe(struct efx_nic *efx);
void efx_farch_filter_table_restore(struct efx_nic *efx);
void efx_farch_filter_table_remove(struct efx_nic *efx);
bool efx_farch_filter_match_supported(struct efx_nic *efx, bool encap,
				      unsigned int match_flags);
void efx_farch_filter_update_rx_scatter(struct efx_nic *efx);
s32 efx_farch_filter_insert(struct efx_nic *efx,
			    const struct efx_filter_spec *spec, bool replace);
int efx_farch_filter_remove_safe(struct efx_nic *efx,
				 enum efx_filter_priority priority,
				 u32 filter_id);
int efx_farch_filter_get_safe(struct efx_nic *efx,
			      enum efx_filter_priority priority, u32 filter_id,
			      struct efx_filter_spec *);
int efx_farch_filter_clear_rx(struct efx_nic *efx,
			      enum efx_filter_priority priority);
int efx_farch_filter_redirect(struct efx_nic *efx, u32 filter_id,
			      int rxq_i, int stack_id);
u32 efx_farch_filter_count_rx_used(struct efx_nic *efx,
				   enum efx_filter_priority priority);
u32 efx_farch_filter_get_rx_id_limit(struct efx_nic *efx);
s32 efx_farch_filter_get_rx_ids(struct efx_nic *efx,
				enum efx_filter_priority priority, u32 *buf,
				u32 size);
#if (defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SARFS)) || defined(CONFIG_RFS_ACCEL)
s32 efx_farch_filter_async_insert(struct efx_nic *efx,
				  const struct efx_filter_spec *spec);
#endif
#ifdef CONFIG_RFS_ACCEL
bool efx_farch_filter_rfs_expire_one(struct efx_nic *efx, u32 flow_id,
				     unsigned int index);
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SARFS)
int efx_farch_filter_async_remove(struct efx_nic *efx, unsigned int index);
#endif
#ifdef EFX_NOT_UPSTREAM
int efx_farch_filter_block_kernel(struct efx_nic *efx, enum
				  efx_dl_filter_block_kernel_type type);
void efx_farch_filter_unblock_kernel(struct efx_nic *efx, enum
				     efx_dl_filter_block_kernel_type type);
int efx_farch_vport_filter_insert(struct efx_nic *efx, unsigned int vport_id,
				  const struct efx_filter_spec *spec,
				  u64 *filter_id_out, bool *is_exclusive_out);
int efx_farch_vport_filter_remove(struct efx_nic *efx, unsigned int vport_id,
				  u64 filter_id, bool is_exclusive);
#endif
void efx_farch_filter_sync_rx_mode(struct efx_nic *efx);

bool efx_nic_event_present(struct efx_channel *channel);

/* Some statistics are computed as A - B where A and B each increase
 * linearly with some hardware counter(s) and the counters are read
 * asynchronously.  If the counters contributing to B are always read
 * after those contributing to A, the computed value may be lower than
 * the true value by some variable amount, and may decrease between
 * subsequent computations.
 *
 * We should never allow statistics to decrease or to exceed the true
 * value.  Since the computed value will never be greater than the
 * true value, except when the MAC stats are zeroed as a result of a NIC reset
 * we can achieve this by only storing the computed value
 * when it increases, or when it is zeroed.
 */
static inline void efx_update_diff_stat(u64 *stat, u64 diff)
{
	if (!diff || (s64)(diff - *stat) > 0)
		*stat = diff;
}

/* Interrupts */
int efx_nic_init_interrupt(struct efx_nic *efx);
int efx_nic_irq_test_start(struct efx_nic *efx);
void efx_nic_fini_interrupt(struct efx_nic *efx);

/* Falcon/Siena interrupts */
void efx_farch_irq_enable_master(struct efx_nic *efx);
int efx_farch_irq_test_generate(struct efx_nic *efx);
void efx_farch_irq_disable_master(struct efx_nic *efx);
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_HAVE_IRQ_HANDLER_REGS)
irqreturn_t efx_farch_msi_interrupt(int irq, void *dev_id);
irqreturn_t efx_farch_legacy_interrupt(int irq, void *dev_id);
#else
irqreturn_t efx_farch_msi_interrupt(int irq, void *dev_id, struct pt_regs *);
irqreturn_t efx_farch_legacy_interrupt(int irq, void *dev_id, struct pt_regs *);
#endif
irqreturn_t efx_farch_fatal_interrupt(struct efx_nic *efx);

static inline int efx_nic_event_test_irq_cpu(struct efx_channel *channel)
{
	return ACCESS_ONCE(channel->event_test_cpu);
}
static inline int efx_nic_irq_test_irq_cpu(struct efx_nic *efx)
{
	return ACCESS_ONCE(efx->last_irq_cpu);
}

/* Global Resources */
int efx_nic_flush_queues(struct efx_nic *efx);
void siena_prepare_flush(struct efx_nic *efx);
int efx_farch_fini_dmaq(struct efx_nic *efx);
void efx_farch_finish_flr(struct efx_nic *efx);
void siena_finish_flush(struct efx_nic *efx);
#if !defined(EFX_NOT_UPSTREAM) && !defined(__VMKLNX__)
void falcon_start_nic_stats(struct efx_nic *efx);
void falcon_stop_nic_stats(struct efx_nic *efx);
int falcon_reset_xaui(struct efx_nic *efx);
#endif
int efx_farch_dimension_resources(struct efx_nic *efx,
				  unsigned int sram_lim_qw);
void efx_farch_init_common(struct efx_nic *efx);
void efx_ef10_handle_drain_event(struct efx_nic *efx);
void efx_farch_rx_push_indir_table(struct efx_nic *efx);
void efx_farch_rx_pull_indir_table(struct efx_nic *efx);
void efx_nic_check_pcie_link(struct efx_nic *efx,
			     unsigned int desired_bandwidth,
			     unsigned int *actual_width,
			     unsigned int *actual_speed);

int efx_nic_alloc_buffer(struct efx_nic *efx, struct efx_buffer *buffer,
			 unsigned int len, gfp_t gfp_flags);
void efx_nic_free_buffer(struct efx_nic *efx, struct efx_buffer *buffer);

/* Tests */
struct efx_farch_register_test {
	unsigned int address;
	efx_oword_t mask;
};
struct efx_farch_table_test {
	unsigned int address;
	unsigned int step;
	unsigned int rows;
	efx_oword_t mask;
};
int efx_farch_test_registers(struct efx_nic *efx,
			     const struct efx_farch_register_test *regs,
			     size_t n_regs);
int efx_farch_test_table(struct efx_nic *efx,
			 const struct efx_farch_table_test *table,
			 void (*pattern)(unsigned int, efx_qword_t *, int, int),
			 int a, int b);

size_t efx_nic_get_regs_len(struct efx_nic *efx);
void efx_nic_get_regs(struct efx_nic *efx, void *buf);

size_t efx_nic_describe_stats(const struct efx_hw_stat_desc *desc, size_t count,
			      const unsigned long *mask, u8 *names);
void efx_nic_update_stats(const struct efx_hw_stat_desc *desc, size_t count,
			  const unsigned long *mask, u64 *stats,
			  const void *dma_buf, bool accumulate);
void efx_nic_fix_nodesc_drop_stat(struct efx_nic *efx, u64 *stat);

#define EFX_MAX_FLUSH_TIME 5000

void efx_farch_generate_event(struct efx_nic *efx, unsigned int evq,
			      efx_qword_t *event);
struct efx_tx_queue *efx_farch_select_tx_queue(struct efx_channel *channel,
					       struct sk_buff *skb);

#endif /* EFX_NIC_H */
