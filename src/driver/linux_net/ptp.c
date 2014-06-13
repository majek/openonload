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
 * Copyright 2011 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

/* Theory of operation:
 *
 * PTP support is assisted by firmware running on the MC, which provides
 * the hardware timestamping capabilities.  Both transmitted and received
 * PTP event packets are queued onto internal queues for subsequent processing;
 * this is because the MC operations are relatively long and would block
 * block NAPI/interrupt operation.
 *
 * Receive event processing:
 *	The event contains the packet's UUID and sequence number, together
 *	with the hardware timestamp.  The PTP receive packet queue is searched
 *	for this UUID/sequence number and, if found, put on a pending queue.
 *	Packets not matching are delivered without timestamps (MCDI events will
 *	always arrive after the actual packet).
 *	It is important for the operation of the PTP protocol that the ordering
 *	of packets between the event and general port is maintained.
 *
 * Work queue processing:
 *	If work waiting, synchronise host/hardware time
 *
 *	Transmit: send packet through MC, which returns the transmission time
 *	that is converted to an appropriate timestamp.
 *
 *	Receive: the packet's reception time is converted to an appropriate
 *	timestamp.
 */
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/time.h>
#include <linux/module.h>
#ifndef EFX_USE_KCOMPAT
#include <linux/ktime.h>
#include <linux/net_tstamp.h>
#endif
#include "net_driver.h"
#include "efx.h"
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "io.h"
#include "regs.h"
#include "nic.h"
#include "debugfs.h"
#include "efx_ioctl.h"
#include "kernel_compat.h"

/* Maximum number of events expected to make up a PTP event */
#define	MAX_EVENT_FRAGS			3

/* Maximum delay, ms, to begin synchronisation */
#define	MAX_SYNCHRONISE_WAIT_MS		2

/* How long, at most, to spend synchronising */
#define	SYNCHRONISE_PERIOD_NS		250000

/* How often to update the shared memory time */
#define	SYNCHRONISATION_GRANULARITY_NS	200

/* Minimum permitted length of a (corrected) synchronisation time */
#define	MIN_SYNCHRONISATION_NS		120

/* Maximum permitted length of a (corrected) synchronisation time */
#define	MAX_SYNCHRONISATION_NS		1000

/* How many (MC) receive events that can be queued */
#define	MAX_RECEIVE_EVENTS		8

/* Length of (modified) moving average. */
#define	AVERAGE_LENGTH			16

/* How long an unmatched event or packet can be held */
#define PKT_EVENT_LIFETIME_MS		10

/* Offsets into PTP packet for identification.  These offsets are from the
 * start of the IP header, not the MAC header.  Note that neither PTP V1 nor
 * PTP V2 permit the use of IPV4 options.
 */
#define PTP_DPORT_OFFSET	22

#define PTP_V1_VERSION_LENGTH	2
#define PTP_V1_VERSION_OFFSET	28

#define PTP_V1_UUID_LENGTH	6
#define PTP_V1_UUID_OFFSET	50

#define PTP_V1_SEQUENCE_LENGTH	2
#define PTP_V1_SEQUENCE_OFFSET	58

/* The minimum length of a PTP V1 packet for offsets, etc. to be valid:
 * includes IP header.
 */
#define	PTP_V1_MIN_LENGTH	64

#define PTP_V2_VERSION_LENGTH	1
#define PTP_V2_VERSION_OFFSET	29

#define PTP_V2_DOMAIN_LENGTH    1
#define PTP_V2_DOMAIN_OFFSET    32

#define PTP_V2_UUID_LENGTH	8
#define PTP_V2_UUID_OFFSET	48

/* Although PTP V2 UUIDs are comprised a ClockIdentity (8) and PortNumber (2),
 * the MC only captures the last six bytes of the clock identity. These values
 * reflect those, not the ones used in the standard.  The standard permits
 * mapping of V1 UUIDs to V2 UUIDs with these same values.
 */
#define PTP_V2_MC_UUID_LENGTH	6
#define PTP_V2_MC_UUID_OFFSET	50

#define PTP_V2_SEQUENCE_LENGTH	2
#define PTP_V2_SEQUENCE_OFFSET	58

/* The minimum length of a PTP V2 packet for offsets, etc. to be valid:
 * includes IP header.
 */
#define	PTP_V2_MIN_LENGTH	63

#define	PTP_MIN_LENGTH		63

#define PTP_PRIMARY_ADDRESS	0xe0000181	/* 224.0.1.129 */
#define PTP_PEER_DELAY_ADDRESS	0xe000016B	/* 224.0.1.107 */
#define PTP_EVENT_PORT		319
#define PTP_GENERAL_PORT	320

/* Annoyingly the format of the version numbers are different between
 * versions 1 and 2 so it isn't possible to simply look for 1 or 2.
 */
#define	PTP_VERSION_V1		1

#define	PTP_VERSION_V2		2
#define	PTP_VERSION_V2_MASK	0x0f

enum ptp_packet_state {
	PTP_PACKET_STATE_UNMATCHED = 0,
	PTP_PACKET_STATE_MATCHED,
	PTP_PACKET_STATE_TIMED_OUT,
	PTP_PACKET_STATE_MATCH_UNWANTED
};

/* NIC synchronised with single word of time only comprising
 * partial seconds and full nanoseconds: 10^9 ~ 2^30 so 2 bits for seconds.
 */
#define	MC_NANOSECOND_BITS	30
#define	MC_NANOSECOND_MASK	((1 << MC_NANOSECOND_BITS) - 1)
#define	MC_SECOND_MASK		((1 << (32 - MC_NANOSECOND_BITS)) - 1)

/* Maximum parts-per-billion adjustment that is acceptable */
#define MAX_PPB			1000000

/* Number of bits required to hold the above */
#define	MAX_PPB_BITS		20

/* Number of extra bits allowed when calculating fractional ns.
 * EXTRA_BITS + MC_CMD_PTP_IN_ADJUST_BITS + MAX_PPB_BITS should
 * be less than 63.
 */
#define	PPB_EXTRA_BITS		2

/* Precalculate scale word to avoid long long division at runtime */
#define	PPB_SCALE_WORD	((1LL << (PPB_EXTRA_BITS + MC_CMD_PTP_IN_ADJUST_BITS +\
			MAX_PPB_BITS)) / 1000000000LL)

#define PTP_SYNC_ATTEMPTS	4

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
/* Number of received packets to hold in timestamp queue */
#define	MAX_RX_TS_ENTRIES	16

/**
 * struct efx_ptp_rx_timestamp - Compatibility layer
 */
struct efx_ptp_rx_timestamp {
	struct skb_shared_hwtstamps ts;
	u8 uuid[PTP_V1_UUID_LENGTH];
	u8 seqid[PTP_V1_SEQUENCE_LENGTH];
};
#endif

/**
 * struct efx_ptp_match - Matching structure, stored in sk_buff's cb area.
 * @words: UUID and (partial) sequence number
 * @expiry: Time after which the packet should be delivered irrespective of
 *            event arrival.
 * @state: The state of the packet - whether it is ready for processing or
 *         whether that is of no interest.
 */
struct efx_ptp_match {
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
	struct skb_shared_hwtstamps timestamps;	/* Must be first member */
#endif
	u32 words[DIV_ROUND_UP(PTP_V1_UUID_LENGTH, 4)];
	unsigned long expiry;
	enum ptp_packet_state state;
	u16 vlan_tci;
	u16 flags;
};

/**
 * struct efx_ptp_event_ts - timestamp of event
 * @seq0: First part of UUID
 * @seq1: Second part of UUID and sequence number
 * @hwtimestamp: Event timestamp
 */
struct efx_ptp_event_ts {
	u32 seq0;
	u32 seq1;
	ktime_t hwtimestamp;
};

/**
 * struct efx_ptp_event_rx - A PTP receive event (from MC)
 * @ts: timestamp data
 * @hwtimestamp: Event timestamp
 */
struct efx_ptp_event_rx {
	struct list_head link;
	struct efx_ptp_event_ts ts;
	unsigned long expiry;
};

/**
 * struct efx_ptp_timeset - Synchronisation between host and MC
 * @host_start: Host time immediately before hardware timestamp taken
 * @seconds: Hardware timestamp, seconds
 * @nanoseconds: Hardware timestamp, nanoseconds
 * @host_end: Host time immediately after hardware timestamp taken
 * @waitns: Number of nanoseconds between hardware timestamp being read and
 *          host end time being seen
 * @window: Difference of host_end and host_start
 * @valid: Whether this timeset is valid
 */
struct efx_ptp_timeset {
	u32 host_start;
	u32 seconds;
	u32 nanoseconds;
	u32 host_end;
	u32 waitns;
	u32 window;	/* Derived: end - start, allowing for wrap */
};

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
/* Fordward declaration */
struct efx_ptp_data;

/**
 * struct efx_pps_data - PPS device node informatino
 * @ptp: Pointer to parent ptp structure
 * @kobj: kobject for stats handling
 * @read_data: Queue for handling API reads
 * @s_assert: sys assert time of hw_pps event
 * @n_assert: nic assert time of hw_pps event
 * @s_delta: computed delta between nic and sys clocks
 * @hw_pps_work: work struct for handling hw_pps events
 * @hw_pps_workwq: work queue for handling hw_pps events
 * @nic_hw_pps_enabled: Are hw_pps events enabled
 * @fd_count: Number of open fds
 * @major: device major number
 * @last_ev: Last event sequence number
 * @last_ev_taken: Last event sequence number read by API
 */
struct efx_pps_data {
	struct efx_ptp_data *ptp;
	struct kobject kobj;
	wait_queue_head_t read_data;
	struct pps_event_time s_assert;
	struct efx_ptp_event_ts n_assert;
	struct timespec s_delta;
	struct work_struct hw_pps_work;
	struct workqueue_struct *hw_pps_workwq;
	bool nic_hw_pps_enabled;
	int fd_count;
	int major;
	int last_ev;
	int last_ev_taken;
};

/**
 * struct efx_pps_dev_attr - PPS device attr structure
 * @attr: attribute object
 * @pos: offset of the stat desired
 * @show: function pointer to obtain and print the stats
 */

struct efx_pps_dev_attr {
	struct attribute attr;
	u8 pos;
	ssize_t (*show)(struct efx_pps_data *, u8 pos, char *);
};
#endif

/**
 * struct efx_ptp_data - Precision Time Protocol (PTP) state
 * @channel: The PTP channel
 * @rxq: Receive queue (awaiting timestamps)
 * @txq: Transmit queue
 * @evt_list: List of MC receive events awaiting packets
 * @evt_free_list: List of free events
 * @evt_lock: Lock for manipulating evt_list and evt_free_list
 * @rx_evts: Instantiated events (on evt_list and evt_free_list)
 * @workwq: Work queue for processing pending PTP operations
 * @work: Work task
 * @reset_required: A serious error has occurred and the PTP task needs to be
 *                  reset (disable, enable).
 * @rxfilter.multicast_installed: Indicates if multicast filters are installed
 * @rxfilter.unicast_installed: Indicates if unicast filters are installed
 * @rxfilter.primary_event: Receive filter for primary multicast address
 * @rxfilter.primary_general: Receive filter for primary multicast address
 * @rxfilter.peer_delay_event: Receive filter for peer delay multicast address
 * @rxfilter.peer_delay_general: Receive filter for peer delay multicast address
 * @rxfilter.unicast_address: Unicast address to filter on
 * @rxfilter.unicast_event: Receive filter for unicast address
 * @rxfilter.unicast_general: Receive filter for unicast address
 * @uuid_filter: Filtering of received packets against PTP UUID
 * @domain_filter: Filtering of received packets against PTP domain number
 * @vlan_filter: Filtering of received packets against VLAN tags
 * @config: Current timestamp configuration
 * @enabled: PTP operation enabled
 * @mode: Mode in which PTP operating (PTP version)
 * @evt_frags: Partly assembled PTP events
 * @evt_frag_idx: Current PTP fragment number
 * @evt_code: Last event code
 * @start: Address at which MC indicates ready for synchronisation
 * @host_time_pps: Host time at last PPS
 * @last_sync_ns: Last number of nanoseconds between readings when synchronising
 * @base_sync_ns: Number of nanoseconds for last synchronisation.
 * @base_sync_valid: Whether base_sync_time is valid.
 * @current_adjfreq: Current ppb adjustment.
 * @phc_clock: Pointer to registered phc device
 * @phc_clock_info: Registration structure for phc device
 * @pps_work: pps work task for handling pps events
 * @pps_workwq: pps work queue
 * @pps_data: Data associated with optional HW PPS events
 * @nic_ts_enabled: Flag indicating if NIC generated TS events are handled
 * @txbuf: Buffer for use when transmitting (PTP) packets to MC (avoids
 *         allocations in main data path).
 * @debug_ptp_dir: PTP debugfs directory
 * @missed_rx_sync: Number of packets received without syncrhonisation.
 * @good_syncs: Number of successful synchronisations.
 * @no_time_syncs: Number of synchronisations with no good times.
 * @bad_sync_durations: Number of synchronisations with bad durations.
 * @bad_syncs: Number of failed synchronisations.
 * @last_sync_time: Number of nanoseconds for last synchronisation.
 * @sync_timeouts: Number of synchronisation timeouts
 * @fast_syncs: Number of synchronisations requiring short delay
 * @min_sync_delta: Minimum time between event and synchronisation
 * @max_sync_delta: Maximum time between event and synchronisation
 * @average_sync_delta: Average time between event and synchronisation.
 *                      Modified moving average.
 * @last_sync_delta: Last time between event and synchronisation
 * @mc_stats: Context value for MC statistics
 * @timeset: Last set of synchronisation statistics.
 */
struct efx_ptp_data {
	struct efx_channel *channel;
	struct sk_buff_head rxq;
	struct sk_buff_head txq;
	struct list_head evt_list;
	struct list_head evt_free_list;
	spinlock_t evt_lock;
	struct efx_ptp_event_rx rx_evts[MAX_RECEIVE_EVENTS];
	struct workqueue_struct *workwq;
	struct work_struct work;
	bool reset_required;
	struct {
		bool multicast_installed;
		bool unicast_installed;
		u32 primary_event;
		u32 primary_general;
		u32 peer_delay_event;
		u32 peer_delay_general;
		u32 unicast_address;
		u32 unicast_event;
		u32 unicast_general;
	} rxfilter;
#if defined(EFX_NOT_UPSTREAM)
	struct efx_ts_set_uuid_filter uuid_filter;
	struct efx_ts_set_domain_filter domain_filter;
	struct efx_ts_set_vlan_filter vlan_filter;
#endif
	struct hwtstamp_config config;
	bool enabled;
	unsigned int mode;
	efx_qword_t evt_frags[MAX_EVENT_FRAGS];
	int evt_frag_idx;
	int evt_code;
	struct efx_buffer start;
	struct pps_event_time host_time_pps;
	unsigned last_sync_ns;
	unsigned base_sync_ns;
	bool base_sync_valid;
	s64 current_adjfreq;
#if defined(EFX_USE_KCOMPAT)
	struct timespec last_delta;
#endif
	struct ptp_clock *phc_clock;
	struct ptp_clock_info phc_clock_info;
#if defined(EFX_HAVE_PHC_SUPPORT)
	struct work_struct pps_work;
	struct workqueue_struct *pps_workwq;
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
	struct efx_pps_data *pps_data;
#endif
	bool nic_ts_enabled;

	u8 txbuf[ALIGN(MC_CMD_PTP_IN_TRANSMIT_LEN(
			       MC_CMD_PTP_IN_TRANSMIT_PACKET_MAXNUM), 4)];
#ifdef CONFIG_SFC_DEBUGFS
	unsigned int missed_rx_sync;
	unsigned int good_syncs;
	unsigned int no_time_syncs;
	unsigned int bad_sync_durations;
	unsigned int bad_syncs;
	unsigned int last_sync_time;
	unsigned int sync_timeouts;
	unsigned int fast_syncs;
	unsigned int min_sync_delta;
	unsigned int max_sync_delta;
	unsigned int average_sync_delta;
	unsigned int last_sync_delta;
	u8 mc_stats[MC_CMD_PTP_OUT_STATUS_LEN / sizeof(u32)];
#endif
	struct efx_ptp_timeset
	timeset[MC_CMD_PTP_OUT_SYNCHRONIZE_TIMESET_MAXNUM];
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
	bool tx_ts_valid;
	struct skb_shared_hwtstamps tx_ts;
	unsigned int rx_ts_head;
	unsigned int rx_ts_tail;
	struct efx_ptp_rx_timestamp rx_ts[MAX_RX_TS_ENTRIES];
#endif
	u16 vlan_tci;	
};

static int efx_phc_adjfreq(struct ptp_clock_info *ptp, s32 delta);
static int efx_phc_adjtime(struct ptp_clock_info *ptp, s64 delta);
static int efx_phc_gettime(struct ptp_clock_info *ptp, struct timespec *ts);
#if defined(EFX_HAVE_PHC_SUPPORT)
static int efx_phc_settime(struct ptp_clock_info *ptp,
			   const struct timespec *e_ts);
static int efx_phc_enable(struct ptp_clock_info *ptp,
			  struct ptp_clock_request *request, int on);
#endif

static int efx_ptp_insert_unicast_filters(struct efx_nic *efx,
					  u32 unicast_address);

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)

static void efx_ptp_save_rx_ts(struct efx_nic *efx, struct sk_buff *skb,
			       struct skb_shared_hwtstamps *timestamps)
{
	unsigned int new_tail;
	struct efx_ptp_data *ptp = efx->ptp_data;

	local_bh_disable();
	new_tail = ptp->rx_ts_tail + 1;
	if (new_tail >= MAX_RX_TS_ENTRIES)
		new_tail = 0;

	if (new_tail != ptp->rx_ts_head) {
		struct efx_ptp_rx_timestamp *ts;

		ts = &ptp->rx_ts[ptp->rx_ts_tail];
		ptp->rx_ts_tail = new_tail;
		ts->ts = *timestamps;
		
		if (ptp->mode == MC_CMD_PTP_MODE_V1) {
			memcpy(ts->uuid, &skb->data[PTP_V1_UUID_OFFSET],
			       PTP_V1_UUID_LENGTH);
		} else if (ptp->mode == MC_CMD_PTP_MODE_V2) {
			/* In the normal V2 mode, we pass bytes 2-7 of the V2
			 * UUID to the application */
			memcpy(ts->uuid, &skb->data[PTP_V2_MC_UUID_OFFSET],
			       PTP_V2_MC_UUID_LENGTH);
		} else {
			/* bug 33070 In the enhanced V2 mode, we pass bytes 0-2
			 * and 5-7 of the V2 UUID to the application */
			ts->uuid[0] = skb->data[PTP_V2_UUID_OFFSET];
			ts->uuid[1] = skb->data[PTP_V2_UUID_OFFSET + 1];
			ts->uuid[2] = skb->data[PTP_V2_UUID_OFFSET + 2];
			ts->uuid[3] = skb->data[PTP_V2_UUID_OFFSET + 5];
			ts->uuid[4] = skb->data[PTP_V2_UUID_OFFSET + 6];
			ts->uuid[5] = skb->data[PTP_V2_UUID_OFFSET + 7];
			BUG_ON(ptp->mode != MC_CMD_PTP_MODE_V2_ENHANCED);
		}

		memcpy(ts->seqid, &skb->data[PTP_V1_SEQUENCE_OFFSET],
		       PTP_V1_SEQUENCE_LENGTH);
	}
	local_bh_enable();
}
#endif

#if (defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)) || defined(CONFIG_SFC_DEBUGFS)
/* Read one MC PTP related statistic.  This actually gathers
 * all PTP statistics, throwing away the others.
 */
static int ptp_read_stat(struct efx_ptp_data *ptp,
			 u8 pos, efx_dword_t *value)
{
	u8 inbuf[MC_CMD_PTP_IN_STATUS_LEN];
	u8 outbuf[MC_CMD_PTP_OUT_STATUS_LEN];
	int rc;

	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_STATUS);
	rc = efx_mcdi_rpc(ptp->channel->efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), NULL);
	if (rc) {
		*value->u32 = 0;
		return rc;
	}

	*value = *((efx_dword_t *)(outbuf + pos));

	return 0;
}
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
static ssize_t efx_pps_stats_int(struct efx_pps_data *pps, u8 pos, char *data)
{
	efx_dword_t value;

	ptp_read_stat(pps->ptp, pos, &value);

	return sprintf(data, "%d\n", EFX_DWORD_FIELD(value, EFX_DWORD_0));
}

static ssize_t efx_pps_stats_show(struct kobject *kobj,
				  struct attribute *attr,
				  char *buff)
{
	struct efx_pps_data *pps = container_of(kobj,
						struct efx_pps_data,
						kobj);

	struct efx_pps_dev_attr *efx_attr = container_of(attr,
							 struct efx_pps_dev_attr,
							 attr);
	return efx_attr->show(pps, efx_attr->pos, buff);
}

#define EFX_PPS_DEVICE_ATTR(_name, _mode, _pos) \
	static struct efx_pps_dev_attr efx_pps_attr_##_name = { \
		.attr = {.name = __stringify(_name), .mode = _mode }, \
		.pos = MC_CMD_PTP_OUT_STATUS_STATS_##_pos##_OFST, \
		.show = efx_pps_stats_int, \
	}

#define EFX_PPS_ATTR_PTR(_name) \
	&efx_pps_attr_##_name.attr

EFX_PPS_DEVICE_ATTR(pps_oflow, S_IRUGO, PPS_OFLOW);
EFX_PPS_DEVICE_ATTR(pps_bad, S_IRUGO, PPS_BAD);
EFX_PPS_DEVICE_ATTR(pps_per_min, S_IRUGO, PPS_PER_MIN);
EFX_PPS_DEVICE_ATTR(pps_per_max, S_IRUGO, PPS_PER_MAX);
EFX_PPS_DEVICE_ATTR(pps_per_last, S_IRUGO, PPS_PER_LAST);
EFX_PPS_DEVICE_ATTR(pps_per_mean, S_IRUGO, PPS_PER_MEAN);
EFX_PPS_DEVICE_ATTR(pps_off_min, S_IRUGO, PPS_OFF_MIN);
EFX_PPS_DEVICE_ATTR(pps_off_max, S_IRUGO, PPS_OFF_MAX);
EFX_PPS_DEVICE_ATTR(pps_off_last, S_IRUGO, PPS_OFF_LAST);
EFX_PPS_DEVICE_ATTR(pps_off_mean, S_IRUGO, PPS_OFF_MEAN);

static struct attribute *efx_pps_device_attrs[] = {
	EFX_PPS_ATTR_PTR(pps_oflow),
	EFX_PPS_ATTR_PTR(pps_bad),
	EFX_PPS_ATTR_PTR(pps_per_min),
	EFX_PPS_ATTR_PTR(pps_per_max),
	EFX_PPS_ATTR_PTR(pps_per_last),
	EFX_PPS_ATTR_PTR(pps_per_mean),
	EFX_PPS_ATTR_PTR(pps_off_min),
	EFX_PPS_ATTR_PTR(pps_off_max),
	EFX_PPS_ATTR_PTR(pps_off_last),
	EFX_PPS_ATTR_PTR(pps_off_mean),
	NULL,
};

static void aoe_boardattr_release(struct kobject *kobj) { }

static const struct sysfs_ops efx_sysfs_ops = {
	.show = efx_pps_stats_show,
	.store = NULL,
};

static struct kobj_type efx_sysfs_ktype = {
	.release = aoe_boardattr_release,
	/* May need to cast away const */
	.sysfs_ops = (struct sysfs_ops *)&efx_sysfs_ops,
	.default_attrs = efx_pps_device_attrs,
};

#endif


#ifdef CONFIG_SFC_DEBUGFS

#define STAT_OFF(_item) (MC_CMD_PTP_OUT_STATUS_STATS_ ## _item ## _OFST / \
			 sizeof(u32))


static int ptp_read_mc_int(struct seq_file *file, void *data)
{
	int rc;
	efx_dword_t value;
	u8 pos = *((u8 *)data);
	struct efx_ptp_data *ptp =
		container_of(data, struct efx_ptp_data, mc_stats[pos]);

	rc = ptp_read_stat(ptp, pos, &value);

	if (rc)
		return rc;

	return seq_printf(file, "%d\n", EFX_DWORD_FIELD(value, EFX_DWORD_0));
}

#define EFX_PTP_INT_PARAMETER(container_type, parameter)		\
	EFX_NAMED_PARAMETER(ptp_ ## parameter, container_type, parameter, \
			    unsigned int, efx_debugfs_read_int)

#define EFX_PTP_MC_INT_PARAMETER(container_type, parameter, offset)	\
	EFX_NAMED_PARAMETER(ptp_mc_ ## parameter, container_type,	\
			    mc_stats[STAT_OFF(offset)],			\
			    u8, ptp_read_mc_int)

/* PTP parameters */
static struct efx_debugfs_parameter efx_debugfs_ptp_parameters[] = {
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, last_sync_ns),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, missed_rx_sync),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, good_syncs),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, no_time_syncs),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, bad_sync_durations),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, bad_syncs),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, last_sync_time),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, sync_timeouts),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, fast_syncs),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, min_sync_delta),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, max_sync_delta),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, average_sync_delta),
	EFX_PTP_INT_PARAMETER(struct efx_ptp_data, last_sync_delta),
	EFX_PTP_MC_INT_PARAMETER(struct efx_ptp_data, tx, TX),
	EFX_PTP_MC_INT_PARAMETER(struct efx_ptp_data, rx, RX),
	EFX_PTP_MC_INT_PARAMETER(struct efx_ptp_data, ts, TS),
	EFX_PTP_MC_INT_PARAMETER(struct efx_ptp_data, fm, FM),
	EFX_PTP_MC_INT_PARAMETER(struct efx_ptp_data, nfm, NFM),
	{NULL},
};

static ssize_t set_ptp_stats(struct device *dev,
			     struct device_attribute *attr, const char *buf, size_t count)
{
	bool clear = count > 0 && *buf != '0';

	if (clear) {
		struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
		u8 in_rst_stats[MC_CMD_PTP_IN_RESET_STATS_LEN];
		int rc;

		MCDI_SET_DWORD(in_rst_stats, PTP_IN_OP, MC_CMD_PTP_OP_RESET_STATS);

		rc = efx_mcdi_rpc(efx, MC_CMD_PTP, in_rst_stats, sizeof(in_rst_stats),
				  NULL, 0, NULL);
		if (rc < 0)
			count = (size_t) rc;
	}

	return count;
}

static DEVICE_ATTR(ptp_stats, S_IWUSR, NULL, set_ptp_stats);

#define EFX_PTP_INC_DEBUG_VAR(var)		do { (var)++; } while (0)
#define EFX_PTP_SET_DEBUG_VAR(var, value)	do { (var) = (value); } while (0)
#else
#define EFX_PTP_INC_DEBUG_VAR(var)		do {} while (0)
#define EFX_PTP_SET_DEBUG_VAR(var, value)	do {} while (0)
#endif

/* Enable MCDI PTP support. */
static int efx_ptp_enable(struct efx_nic *efx)
{
	u8 inbuf[MC_CMD_PTP_IN_ENABLE_LEN];

	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_ENABLE);
	MCDI_SET_DWORD(inbuf, PTP_IN_ENABLE_QUEUE,
		       efx->ptp_data->channel->channel);
	MCDI_SET_DWORD(inbuf, PTP_IN_ENABLE_MODE, efx->ptp_data->mode);

	return efx_mcdi_rpc(efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

/* Disable MCDI PTP support.
 *
 * Note that this function should never rely on the presence of ptp_data -
 * may be called before that exists.
 */
static int efx_ptp_disable(struct efx_nic *efx)
{
	u8 inbuf[MC_CMD_PTP_IN_DISABLE_LEN];

	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_DISABLE);
	return efx_mcdi_rpc(efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

static void efx_ptp_deliver_rx_queue(struct sk_buff_head *q)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(q))) {
		local_bh_disable();
		netif_receive_skb(skb);
		local_bh_enable();
	}
}

static void efx_ptp_handle_no_channel(struct efx_nic *efx)
{
	netif_err(efx, drv, efx->net_dev,
		  "ERROR: PTP requires MSI-X and 1 additional interrupt"
		  "vector. PTP disabled\n");
}

/* Repeatedly send the host time to the MC which will capture the hardware
 * time.
 */
static void efx_ptp_send_times(struct efx_nic *efx,
			       struct pps_event_time *last_time)
{
	struct pps_event_time now;
	struct timespec limit;
	struct efx_ptp_data *ptp = efx->ptp_data;
	struct timespec start;
	int *mc_running = ptp->start.addr;

	pps_get_ts(&now);
	start = now.ts_real;
	limit = now.ts_real;
	timespec_add_ns(&limit, SYNCHRONISE_PERIOD_NS);

	/* Write host time for specified period or until MC is done */
	while ((timespec_compare(&now.ts_real, &limit) < 0) &&
	       ACCESS_ONCE(*mc_running)) {
		struct timespec update_time;
		unsigned int host_time;

		/* Don't update continuously to avoid saturating the PCIe bus */
		update_time = now.ts_real;
		timespec_add_ns(&update_time, SYNCHRONISATION_GRANULARITY_NS);
		do {
			pps_get_ts(&now);
		} while ((timespec_compare(&now.ts_real, &update_time) < 0) &&
			 ACCESS_ONCE(*mc_running));

		/* Synchronise NIC with single word of time only */
		host_time = (now.ts_real.tv_sec << MC_NANOSECOND_BITS |
			     now.ts_real.tv_nsec);
		/* Update host time in NIC memory */
		_efx_writed(efx, __cpu_to_le32(host_time),
			    FR_CZ_MC_TREG_SMEM + MC_SMEM_P0_PTP_TIME_OFST);
	}
	*last_time = now;
	EFX_PTP_SET_DEBUG_VAR(ptp->last_sync_time,
			      (unsigned int) now.ts_real.tv_nsec);
}

/* Read a timeset from the MC's results and partial process. */
static void efx_ptp_read_timeset(u8 *data, struct efx_ptp_timeset *timeset)
{
	unsigned start_ns, end_ns;

	timeset->host_start = MCDI_DWORD(data, PTP_OUT_SYNCHRONIZE_HOSTSTART);
	timeset->seconds = MCDI_DWORD(data, PTP_OUT_SYNCHRONIZE_SECONDS);
	timeset->nanoseconds = MCDI_DWORD(data,
					  PTP_OUT_SYNCHRONIZE_NANOSECONDS);
	timeset->host_end = MCDI_DWORD(data, PTP_OUT_SYNCHRONIZE_HOSTEND),
	timeset->waitns = MCDI_DWORD(data, PTP_OUT_SYNCHRONIZE_WAITNS);

	/* Ignore seconds */
	start_ns = timeset->host_start & MC_NANOSECOND_MASK;
	end_ns = timeset->host_end & MC_NANOSECOND_MASK;
	/* Allow for rollover */
	if (end_ns < start_ns)
		end_ns += NSEC_PER_SEC;
	/* Determine duration of operation */
	timeset->window = end_ns - start_ns;
}

/* Process times received from MC.
 *
 * Extract times from returned results, and establish the minimum value
 * seen.  The minimum value represents the "best" possible time and events
 * too much greater than this are rejected - the machine is, perhaps, too
 * busy. A number of readings are taken so that, hopefully, at least one good
 * synchronisation will be seen in the results.
 */
static int efx_ptp_process_times(struct efx_nic *efx, u8 *synch_buf,
				 size_t response_length,
				 struct pps_event_time *last_time)
{
	unsigned number_readings = (response_length /
			       MC_CMD_PTP_OUT_SYNCHRONIZE_TIMESET_LEN);
	unsigned i;
	unsigned min;
	unsigned min_set = 0;
	unsigned total;
	unsigned ngood = 0;
	unsigned last_good = 0;
	struct efx_ptp_data *ptp = efx->ptp_data;
	bool min_valid = false;
	u32 last_sec;
	u32 start_sec;
	struct timespec delta;
	ktime_t mc_time;
	ktime_t host_time;

	if (number_readings == 0)
		return -EAGAIN;

	/* Find minimum value in this set of results, discarding clearly
	 * erroneous results.
	 */
	for (i = 0; i < number_readings; i++) {
		efx_ptp_read_timeset(synch_buf, &ptp->timeset[i]);
		synch_buf += MC_CMD_PTP_OUT_SYNCHRONIZE_TIMESET_LEN;
		if (ptp->timeset[i].window > SYNCHRONISATION_GRANULARITY_NS) {
			if (min_valid) {
				if (ptp->timeset[i].window < min_set)
					min_set = ptp->timeset[i].window;
			} else {
				min_valid = true;
				min_set = ptp->timeset[i].window;
			}
		}
#ifdef CONFIG_SFC_DEBUGFS
		else {
			/* The apparent time for the operation is below
			 * the expected bound.  This is most likely to be
			 * as a consequence of the host's time being adjusted.
			 * Ignore this reading.
			 */
			EFX_PTP_INC_DEBUG_VAR(ptp->bad_sync_durations);
		}
#endif
	}

	if (min_valid) {
		if (ptp->base_sync_valid && (min_set > ptp->base_sync_ns))
			min = ptp->base_sync_ns;
		else
			min = min_set;
	} else {
		min = SYNCHRONISATION_GRANULARITY_NS;
	}

	/* Discard excessively long synchronise durations.  The MC times
	 * when it finishes reading the host time so the corrected window
	 * time should be fairly constant for a given platform.
	 */
	total = 0;
	for (i = 0; i < number_readings; i++)
		if (ptp->timeset[i].window > ptp->timeset[i].waitns) {
			unsigned win;

			win = ptp->timeset[i].window - ptp->timeset[i].waitns;
			if (win >= MIN_SYNCHRONISATION_NS &&
			    win < MAX_SYNCHRONISATION_NS) {
				total += ptp->timeset[i].window;
				ngood++;
				last_good = i;
			}
		}

	if (ngood == 0) {
		netif_warn(efx, drv, efx->net_dev,
			   "PTP no suitable synchronisations %dns %dns\n",
			   ptp->base_sync_ns, min_set);
		return -EAGAIN;
	}

	/* Average minimum this synchronisation */
	ptp->last_sync_ns = DIV_ROUND_UP(total, ngood);
	if (!ptp->base_sync_valid || (ptp->last_sync_ns < ptp->base_sync_ns)) {
		ptp->base_sync_valid = true;
		ptp->base_sync_ns = ptp->last_sync_ns;
	}

	/* Calculate delay from actual PPS to last_time */
	last_time->ts_real.tv_nsec =
		ptp->timeset[last_good].host_start & MC_NANOSECOND_MASK;

	/* It is possible that the seconds rolled over between taking
	 * the start reading and the last value written by the host.  The
	 * timescales are such that a gap of more than one second is never
	 * expected.
	 */
	start_sec = ptp->timeset[last_good].host_start >> MC_NANOSECOND_BITS;
	last_sec = last_time->ts_real.tv_sec & MC_SECOND_MASK;
	if (start_sec != last_sec) {
		if (((start_sec + 1) & MC_SECOND_MASK) != last_sec) {
			netif_warn(efx, hw, efx->net_dev,
				   "PTP bad synchronisation seconds\n");
			return -EAGAIN;
		} else {
			last_time->ts_real.tv_sec--;
		}
	}

	ptp->host_time_pps = *last_time;
	delta.tv_sec = 0;
	delta.tv_nsec = ptp->timeset[last_good].nanoseconds;
	pps_sub_ts(&ptp->host_time_pps, delta);
#if defined(EFX_NOT_UPSTREAM)

	mc_time = ktime_set(ptp->timeset[last_good].seconds,
			    ptp->timeset[last_good].nanoseconds);

	host_time = ktime_set(last_time->ts_real.tv_sec,
			      last_time->ts_real.tv_nsec);

	ptp->last_delta = ktime_to_timespec(ktime_sub(mc_time, host_time));
#endif
	return 0;
}

/* Synchronize times between the host and the MC */
static int efx_ptp_synchronize(struct efx_nic *efx, unsigned int num_readings)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	u8 synch_buf[MC_CMD_PTP_OUT_SYNCHRONIZE_LENMAX];
	size_t response_length;
	int rc;
	unsigned long timeout;
	struct pps_event_time last_time = {};
	unsigned int loops = 0;
	int *start = ptp->start.addr;

	MCDI_SET_DWORD(synch_buf, PTP_IN_OP, MC_CMD_PTP_OP_SYNCHRONIZE);
	MCDI_SET_DWORD(synch_buf, PTP_IN_SYNCHRONIZE_NUMTIMESETS,
		       num_readings);
	MCDI_SET_DWORD(synch_buf, PTP_IN_SYNCHRONIZE_START_ADDR_LO,
		       (u32)ptp->start.dma_addr);
	MCDI_SET_DWORD(synch_buf, PTP_IN_SYNCHRONIZE_START_ADDR_HI,
		       (u32)((u64)ptp->start.dma_addr >> 32));

	/* Clear flag that signals MC ready */
	ACCESS_ONCE(*start) = 0;
	efx_mcdi_rpc_start(efx, MC_CMD_PTP, synch_buf,
			   MC_CMD_PTP_IN_SYNCHRONIZE_LEN);

	/* Wait for start from MCDI (or timeout) */
	timeout = jiffies + msecs_to_jiffies(MAX_SYNCHRONISE_WAIT_MS);
	while (!ACCESS_ONCE(*start) && (time_before(jiffies, timeout))) {
		udelay(20);	/* Usually start MCDI execution quickly */
		loops++;
	}

	if (loops <= 1)
		EFX_PTP_INC_DEBUG_VAR(ptp->fast_syncs);
	if (!time_before(jiffies, timeout))
		EFX_PTP_INC_DEBUG_VAR(ptp->sync_timeouts);

	if (ACCESS_ONCE(*start))
		efx_ptp_send_times(efx, &last_time);

	/* Collect results */
	rc = efx_mcdi_rpc_finish(efx, MC_CMD_PTP,
				 MC_CMD_PTP_IN_SYNCHRONIZE_LEN,
				 synch_buf, sizeof(synch_buf),
				 &response_length);
	if (rc == 0) {
		rc = efx_ptp_process_times(efx, synch_buf, response_length,
					   &last_time);
#ifdef CONFIG_SFC_DEBUGFS
		if (rc == 0)
			EFX_PTP_INC_DEBUG_VAR(ptp->good_syncs);
		else
			EFX_PTP_INC_DEBUG_VAR(ptp->no_time_syncs);
	} else {
		EFX_PTP_INC_DEBUG_VAR(ptp->bad_syncs);
#endif
	}

	return rc;
}

#if defined(EFX_NOT_UPSTREAM) && !defined(EFX_HAVE_PHC_SUPPORT)
/* Get the host time from a given hardware time */
static bool efx_ptp_get_host_time(struct efx_nic *efx,
				  struct skb_shared_hwtstamps *timestamps)
{
	if (efx->ptp_data->base_sync_valid) {
		ktime_t diff = timespec_to_ktime(efx->ptp_data->last_delta);
		timestamps->syststamp = ktime_add(timestamps->hwtstamp, diff);
	}

	return efx->ptp_data->base_sync_valid;
}
#endif

/* Transmit a PTP packet, via the MCDI interface, to the wire. */
static int efx_ptp_xmit_skb(struct efx_nic *efx, struct sk_buff *skb)
{
	u8 *txbuf = efx->ptp_data->txbuf;
	struct skb_shared_hwtstamps timestamps;
	int rc = -EIO;
	/* MCDI driver requires word aligned lengths */
	size_t aligned_len;
	u8 txtime[MC_CMD_PTP_OUT_TRANSMIT_LEN];

	/* Get the UDP source IP address and use it to set up a unicast receive
	 * filter for received PTP packets. This enables PTP hybrid mode to
	 * work. */
	efx_ptp_insert_unicast_filters(efx, ip_hdr(skb)->saddr);

	if (skb_shinfo(skb)->nr_frags != 0) {
		rc = skb_linearize(skb);
		if (rc != 0)
			goto fail;
	}

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		rc = skb_checksum_help(skb);
		if (rc != 0)
			goto fail;
	}
	
#if defined(EFX_USE_FAKE_VLAN_TX_ACCEL)
	if (vlan_tx_tag_present(skb)) {
		skb = __vlan_put_tag(skb, vlan_tx_tag_get(skb));
		if (unlikely(!skb))
			return NETDEV_TX_OK;
	}
#endif
	
	aligned_len = ALIGN(MC_CMD_PTP_IN_TRANSMIT_LEN(skb->len), 4);
	skb_copy_from_linear_data(skb,
				  &txbuf[MC_CMD_PTP_IN_TRANSMIT_PACKET_OFST],
				  aligned_len);

	MCDI_SET_DWORD(txbuf, PTP_IN_OP, MC_CMD_PTP_OP_TRANSMIT);
	MCDI_SET_DWORD(txbuf, PTP_IN_TRANSMIT_LENGTH, skb->len);
	rc = efx_mcdi_rpc(efx, MC_CMD_PTP, txbuf, aligned_len, txtime,
			  sizeof(txtime), &aligned_len);
	if (rc != 0) {
		goto fail;
	}

	memset(&timestamps, 0, sizeof(timestamps));
	timestamps.hwtstamp = ktime_set(
		MCDI_DWORD(txtime, PTP_OUT_TRANSMIT_SECONDS),
		MCDI_DWORD(txtime, PTP_OUT_TRANSMIT_NANOSECONDS));
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
	efx->ptp_data->tx_ts_valid = 1;
	efx->ptp_data->tx_ts = timestamps;
#else
	skb_tstamp_tx(skb, &timestamps);
#endif
	/* Success even if hardware timestamping failed */
	rc = 0;

fail:
	dev_kfree_skb(skb);

	return rc;
}

static void efx_ptp_drop_time_expired_events(struct efx_nic *efx)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	struct list_head *cursor;
	struct list_head *next;

	/* Drop time-expired events */
	spin_lock_bh(&ptp->evt_lock);
	if (!list_empty(&ptp->evt_list)) {
		list_for_each_safe(cursor, next, &ptp->evt_list) {
			struct efx_ptp_event_rx *evt;

			evt = list_entry(cursor, struct efx_ptp_event_rx,
					 link);
			if (time_after(jiffies, evt->expiry)) {
				list_move(&evt->link, &ptp->evt_free_list);
				netif_warn(efx, hw, efx->net_dev,
					   "PTP rx event dropped\n");
			}
		}
	}
	spin_unlock_bh(&ptp->evt_lock);
}

static enum ptp_packet_state efx_ptp_match_rx(struct efx_nic *efx,
					      struct sk_buff *skb)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	bool evts_waiting;
	struct list_head *cursor;
	struct list_head *next;
	struct efx_ptp_match *match;
	enum ptp_packet_state rc = PTP_PACKET_STATE_UNMATCHED;

	spin_lock_bh(&ptp->evt_lock);
	evts_waiting = !list_empty(&ptp->evt_list);
	spin_unlock_bh(&ptp->evt_lock);

	if (!evts_waiting)
		return PTP_PACKET_STATE_UNMATCHED;

	match = (struct efx_ptp_match *)skb->cb;
	/* Look for a matching timestamp in the event queue */
	spin_lock_bh(&ptp->evt_lock);
	list_for_each_safe(cursor, next, &ptp->evt_list) {
		struct efx_ptp_event_rx *evt;

		evt = list_entry(cursor, struct efx_ptp_event_rx, link);
		if ((evt->ts.seq0 == match->words[0]) &&
		    (evt->ts.seq1 == match->words[1])) {
			struct skb_shared_hwtstamps *timestamps;

			/* Match - add in hardware timestamp */
			timestamps = skb_hwtstamps(skb);
			timestamps->hwtstamp = evt->ts.hwtimestamp;

			match->state = PTP_PACKET_STATE_MATCHED;
			rc = PTP_PACKET_STATE_MATCHED;
			list_move(&evt->link, &ptp->evt_free_list);
			break;
		}
	}
	spin_unlock_bh(&ptp->evt_lock);

	return rc;
}

/* Process any queued receive events and corresponding packets
 *
 * q is returned with all the packets that are ready for delivery.
 * true is returned if at least one of those packets requires
 * synchronisation.
 */
static bool efx_ptp_process_events(struct efx_nic *efx, struct sk_buff_head *q)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	bool rc = false;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&ptp->rxq))) {
		struct efx_ptp_match *match;

		match = (struct efx_ptp_match *)skb->cb;
		if (match->state == PTP_PACKET_STATE_MATCH_UNWANTED) {
			__skb_queue_tail(q, skb);
		} else if (efx_ptp_match_rx(efx, skb) ==
			   PTP_PACKET_STATE_MATCHED) {
			rc = true;
			__skb_queue_tail(q, skb);
		} else if (time_after(jiffies, match->expiry)) {
			match->state = PTP_PACKET_STATE_TIMED_OUT;
			EFX_PTP_INC_DEBUG_VAR(ptp->missed_rx_sync);
			__skb_queue_tail(q, skb);
		} else {
			/* Replace unprocessed entry and stop */
			skb_queue_head(&ptp->rxq, skb);
			break;
		}
	}

	return rc;
}

/* Calculate synchronisation delta statistics */
#ifdef CONFIG_SFC_DEBUGFS
static void efx_ptp_update_delta_stats(struct efx_nic *efx,
				       struct skb_shared_hwtstamps *timestamps)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	ktime_t diff;
	ktime_t delta = timespec_to_ktime(ptp->last_delta);

	diff = ktime_sub(timestamps->hwtstamp, delta);
	ptp->last_sync_delta = ktime_to_ns(diff);
	if (ptp->last_sync_delta < ptp->min_sync_delta)
		ptp->min_sync_delta = ptp->last_sync_delta;

	if (ptp->last_sync_delta > ptp->max_sync_delta)
		ptp->max_sync_delta = ptp->last_sync_delta;

	/* This will underestimate the average because of the
	 * truncating integer calculations.  Attempt to correct by
	 * pseudo rounding up.
	 */
	ptp->average_sync_delta = DIV_ROUND_UP(
		(AVERAGE_LENGTH - 1) * ptp->average_sync_delta +
		ptp->last_sync_delta, AVERAGE_LENGTH);
}
#endif

/* Complete processing of a received packet */
static void efx_ptp_process_rx(struct efx_nic *efx, struct sk_buff *skb)
{
	struct efx_ptp_match *match = (struct efx_ptp_match *)skb->cb;

	/* Translate timestamps, as required */
	if (match->state == PTP_PACKET_STATE_MATCHED) {
		struct skb_shared_hwtstamps *timestamps;

		timestamps = skb_hwtstamps(skb);
#if defined(EFX_NOT_UPSTREAM) && !defined(EFX_HAVE_PHC_SUPPORT)
		efx_ptp_get_host_time(efx, timestamps);
#endif
#ifdef CONFIG_SFC_DEBUGFS
		efx_ptp_update_delta_stats(efx, timestamps);
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
		efx_ptp_save_rx_ts(efx, skb, timestamps);
#endif
	}

	local_bh_disable();
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	if (match->flags & EFX_RX_BUF_VLAN_XTAG)
		vlan_hwaccel_receive_skb(skb, efx->vlan_group,
				match->vlan_tci);
	else
#endif
		netif_receive_skb(skb);
	local_bh_enable();
}

static void efx_ptp_remove_unicast_filters(struct efx_nic *efx)
{
	struct efx_ptp_data *ptp = efx->ptp_data;

	if (ptp->rxfilter.unicast_installed) {
		efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
					  ptp->rxfilter.unicast_event);
		efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
					  ptp->rxfilter.unicast_general);
		ptp->rxfilter.unicast_installed = false;
	}
}

static int efx_ptp_insert_unicast_filters(struct efx_nic *efx,
					  u32 unicast_address)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	struct efx_filter_spec rxfilter;
	int rc;

	if (ptp->rxfilter.unicast_installed &&
	    (ptp->rxfilter.unicast_address == unicast_address)) {
		return 0;
	}

	/* Remove the existing unicast filter. This has no effect if
	 * the filters are not installed */
	efx_ptp_remove_unicast_filters(efx);

	/* Filtering of event and general port on unicast address */
	efx_filter_init_rx(&rxfilter, EFX_FILTER_PRI_REQUIRED, 0,
			   efx_rx_queue_index(
				efx_channel_get_rx_queue(ptp->channel)));
	rc = efx_filter_set_ipv4_local(&rxfilter, IPPROTO_UDP,
				       unicast_address,
				       htons(PTP_EVENT_PORT));
	if (rc != 0)
		return rc;

	rc = efx_filter_insert_filter(efx, &rxfilter, true);
	if (rc < 0)
		return rc;
	ptp->rxfilter.unicast_event = rc;

	efx_filter_init_rx(&rxfilter, EFX_FILTER_PRI_REQUIRED, 0,
			   efx_rx_queue_index(
				efx_channel_get_rx_queue(ptp->channel)));
	rc = efx_filter_set_ipv4_local(&rxfilter, IPPROTO_UDP,
				       unicast_address,
				       htons(PTP_GENERAL_PORT));
	if (rc != 0)
		goto fail;

	rc = efx_filter_insert_filter(efx, &rxfilter, true);
	if (rc < 0)
		goto fail;

	ptp->rxfilter.unicast_general = rc;
	ptp->rxfilter.unicast_address = unicast_address;
	ptp->rxfilter.unicast_installed = true;

	netif_warn(efx, hw, efx->net_dev,
		   "PTP set up unicast filter on 0x%x\n", unicast_address);
	
	return 0;

fail:
	efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
				  ptp->rxfilter.unicast_event);
	return rc;
}

static int efx_ptp_start(struct efx_nic *efx)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	struct efx_filter_spec rxfilter;
	int rc;

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
	ptp->rx_ts_tail = 0;
	ptp->rx_ts_head = 0;
	ptp->tx_ts_valid = 0;
#endif
	ptp->reset_required = false;

	/* Must filter on both event and general ports to ensure
	 * that there is no packet re-ordering.
	 */
	efx_filter_init_rx(&rxfilter, EFX_FILTER_PRI_REQUIRED, 0,
			   efx_rx_queue_index(
				   efx_channel_get_rx_queue(ptp->channel)));
	rc = efx_filter_set_ipv4_local(&rxfilter, IPPROTO_UDP,
				       htonl(PTP_PRIMARY_ADDRESS),
				       htons(PTP_EVENT_PORT));
	if (rc != 0)
		return rc;

	rc = efx_filter_insert_filter(efx, &rxfilter, true);
	if (rc < 0)
		return rc;
	ptp->rxfilter.primary_event = rc;

	efx_filter_init_rx(&rxfilter, EFX_FILTER_PRI_REQUIRED, 0,
			   efx_rx_queue_index(
				   efx_channel_get_rx_queue(ptp->channel)));
	rc = efx_filter_set_ipv4_local(&rxfilter, IPPROTO_UDP,
				       htonl(PTP_PRIMARY_ADDRESS),
				       htons(PTP_GENERAL_PORT));
	if (rc != 0)
		goto fail;

	rc = efx_filter_insert_filter(efx, &rxfilter, true);
	if (rc < 0)
		goto fail;
	ptp->rxfilter.primary_general = rc;

	/* Filtering of event and general port on peer delay address */
	efx_filter_init_rx(&rxfilter, EFX_FILTER_PRI_REQUIRED, 0,
			   efx_rx_queue_index(
				   efx_channel_get_rx_queue(ptp->channel)));
	rc = efx_filter_set_ipv4_local(&rxfilter, IPPROTO_UDP,
				       htonl(PTP_PEER_DELAY_ADDRESS),
				       htons(PTP_EVENT_PORT));
	if (rc != 0)
		goto fail2;

	rc = efx_filter_insert_filter(efx, &rxfilter, true);
	if (rc < 0)
		goto fail2;
	ptp->rxfilter.peer_delay_event = rc;

	efx_filter_init_rx(&rxfilter, EFX_FILTER_PRI_REQUIRED, 0,
			   efx_rx_queue_index(
				   efx_channel_get_rx_queue(ptp->channel)));
	rc = efx_filter_set_ipv4_local(&rxfilter, IPPROTO_UDP,
				       htonl(PTP_PEER_DELAY_ADDRESS),
				       htons(PTP_GENERAL_PORT));
	if (rc != 0)
		goto fail3;

	rc = efx_filter_insert_filter(efx, &rxfilter, true);
	if (rc < 0)
		goto fail3;
	ptp->rxfilter.peer_delay_general = rc;

	rc = efx_ptp_enable(efx);
	if (rc != 0)
		goto fail4;

	ptp->evt_frag_idx = 0;
	ptp->current_adjfreq = 0;
	ptp->rxfilter.multicast_installed = true;

	return 0;

fail4:
	efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
				  ptp->rxfilter.peer_delay_general);
fail3:
	efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
				  ptp->rxfilter.peer_delay_event);
fail2:
	efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
				  ptp->rxfilter.primary_general);
fail:
	efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
				  ptp->rxfilter.primary_event);

	return rc;
}

static int efx_ptp_stop(struct efx_nic *efx)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	int rc = efx_ptp_disable(efx);
	struct list_head *cursor;
	struct list_head *next;

	if (ptp->rxfilter.multicast_installed) {
		efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
					  ptp->rxfilter.primary_general);
		efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
					  ptp->rxfilter.primary_event);
		efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
					  ptp->rxfilter.peer_delay_general);
		efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
					  ptp->rxfilter.peer_delay_event);
		ptp->rxfilter.multicast_installed = false;
	}

	efx_ptp_remove_unicast_filters(efx);

	/* Make sure RX packets are really delivered */
	efx_ptp_deliver_rx_queue(&efx->ptp_data->rxq);
	skb_queue_purge(&efx->ptp_data->txq);

	/* Drop any pending receive events */
	spin_lock_bh(&efx->ptp_data->evt_lock);
	list_for_each_safe(cursor, next, &efx->ptp_data->evt_list) {
		list_move(cursor, &efx->ptp_data->evt_free_list);
	}
	spin_unlock_bh(&efx->ptp_data->evt_lock);

	return rc;
}

#if defined(EFX_HAVE_PHC_SUPPORT)
static void efx_ptp_pps_worker(struct work_struct *work)
{
	struct efx_ptp_data *ptp =
		container_of(work, struct efx_ptp_data, pps_work);
	struct efx_nic *efx = ptp->channel->efx;
	struct ptp_clock_event ptp_evt;

	if (efx_ptp_synchronize(efx, PTP_SYNC_ATTEMPTS))
		return;

	ptp_evt.type = PTP_CLOCK_PPSUSR;
	ptp_evt.pps_times = ptp->host_time_pps;
	ptp_clock_event(ptp->phc_clock, &ptp_evt);
}
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
int efx_ptp_pps_get_event(struct efx_nic *efx, struct efx_ts_get_pps *event)
{
	struct timespec nic_time;
	struct efx_pps_data *pps_data = efx->ptp_data->pps_data;
	unsigned int ev;
	unsigned int err;
	unsigned int timeout = msecs_to_jiffies(event->timeout);

	ev = pps_data->last_ev_taken;

	if (ev == pps_data->last_ev) {
		err = wait_event_interruptible_timeout(pps_data->read_data,
						       ev != pps_data->last_ev,
						       timeout);
		if (err == 0)
			return -ETIMEDOUT;

		/* Check for pending signals */
		if (err == -ERESTARTSYS)
			return -EINTR;
	}

	/* Return the fetched timestamp */
	nic_time = ktime_to_timespec(pps_data->n_assert.hwtimestamp);
	event->nic_assert.tv_sec = nic_time.tv_sec;
	event->nic_assert.tv_nsec = nic_time.tv_nsec;

	event->sys_assert.tv_sec = pps_data->s_assert.ts_real.tv_sec;
	event->sys_assert.tv_nsec = pps_data->s_assert.ts_real.tv_nsec;

	event->delta.tv_sec = pps_data->s_delta.tv_sec;
	event->delta.tv_nsec = pps_data->s_delta.tv_nsec;
	event->sequence = pps_data->last_ev;

	pps_data->last_ev_taken = pps_data->last_ev;

	return 0;	
}

static void efx_ptp_hw_pps_worker(struct work_struct *work)
{
	struct efx_pps_data *pps =
		container_of(work, struct efx_pps_data, hw_pps_work);
	struct efx_nic *efx = pps->ptp->channel->efx;

	if (efx_ptp_synchronize(efx, PTP_SYNC_ATTEMPTS))
		return;

	/* Get the sequence number from the packet
	 * check against the last one, if new then add
	 * to queue */

	pps->s_assert = pps->ptp->host_time_pps;
	pps->s_delta = pps->ptp->last_delta;
	pps->last_ev++;

	if (waitqueue_active(&pps->read_data))
		wake_up(&pps->read_data);
}

int efx_ptp_hw_pps_enable(struct efx_nic *efx, struct efx_ts_hw_pps *data)
{
	struct efx_ptp_data *ptp_data = efx->ptp_data;
	struct efx_pps_data *pps_data = ptp_data->pps_data;
	u8 inbuf[MC_CMD_PTP_IN_PPS_ENABLE_LEN];
	int rc;

	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_PPS_ENABLE);
	MCDI_SET_DWORD(inbuf, PTP_IN_PPS_ENABLE_OP,
		       data->enable ? MC_CMD_PTP_ENABLE_PPS :
				      MC_CMD_PTP_DISABLE_PPS);
	MCDI_SET_DWORD(inbuf, PTP_IN_PPS_ENABLE_QUEUE_ID,
		       efx->ptp_data->channel->channel);

	rc  = efx_mcdi_rpc(efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
			NULL, 0, NULL);

	if (rc)
		return rc;

	if (data->enable) {
		pps_data->last_ev = 0;
		pps_data->last_ev_taken = 0;
		memset(&pps_data->s_delta, 0x0, sizeof(pps_data->s_delta));
		memset(&pps_data->s_assert, 0x0, sizeof(pps_data->s_assert));
		memset(&pps_data->n_assert, 0x0, sizeof(pps_data->n_assert));
	}

	pps_data->nic_hw_pps_enabled = data->enable;

	return 0;
}
#endif

/* Process any pending transmissions and timestamp any received packets.
 */
static void efx_ptp_worker(struct work_struct *work)
{
	struct efx_ptp_data *ptp_data =
		container_of(work, struct efx_ptp_data, work);
	struct efx_nic *efx = ptp_data->channel->efx;
	struct sk_buff *skb;
	struct sk_buff_head tempq;

	if (ptp_data->reset_required) {
		efx_ptp_stop(efx);
		efx_ptp_start(efx);
		return;
	}

	efx_ptp_drop_time_expired_events(efx);

	__skb_queue_head_init(&tempq);
	if (efx_ptp_process_events(efx, &tempq) ||
	    !skb_queue_empty(&ptp_data->txq)) {
#if defined(EFX_NOT_UPSTREAM) && !defined(EFX_HAVE_PHC_SUPPORT)
		if (0 != efx_ptp_synchronize(efx, PTP_SYNC_ATTEMPTS))
			netif_warn(efx, drv, efx->net_dev,
				   "PTP couldn't get synchronisation\n");
#endif

		while ((skb = skb_dequeue(&ptp_data->txq)))
			efx_ptp_xmit_skb(efx, skb);
	}

	while ((skb = __skb_dequeue(&tempq)))
		efx_ptp_process_rx(efx, skb);
}

static ssize_t siena_show_ptp(struct device *dev,
			      struct device_attribute *attr,
			      char *buff)
{
	return sprintf(buff, "HW clock\nPTP TS\n");
}

static DEVICE_ATTR(ptp_caps, S_IRUGO, siena_show_ptp, NULL);

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
static int efx_ptp_create_pps(struct efx_ptp_data *ptp)
{
	struct efx_pps_data *pps;

	pps = kzalloc(sizeof(*pps), GFP_ATOMIC);
	if (!pps)
		return -ENOMEM;

	INIT_WORK(&pps->hw_pps_work, efx_ptp_hw_pps_worker);
	pps->hw_pps_workwq = create_singlethread_workqueue("sfc_hw_pps");
	if (!pps->hw_pps_workwq)
		goto fail1;

	init_waitqueue_head(&pps->read_data);
	pps->nic_hw_pps_enabled = false;

	if (kobject_init_and_add(&pps->kobj,
				 &efx_sysfs_ktype,
				 &ptp->channel->efx->pci_dev->dev.kobj,
				 "pps_stats"))
		goto fail2;

	pps->ptp = ptp;
	ptp->pps_data = pps;

	return 0;
fail2:
	destroy_workqueue(pps->hw_pps_workwq);
fail1:
	kfree(pps);
	ptp->pps_data = NULL;

	return -ENOMEM;
}

static void efx_ptp_destroy_pps(struct efx_ptp_data *ptp)
{
	if (!ptp->pps_data)
		return;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_WORK_SYNC)
	cancel_work_sync(&ptp->pps_data->hw_pps_work);
	flush_workqueue(ptp->pps_data->hw_pps_workwq);
#endif

	destroy_workqueue(ptp->pps_data->hw_pps_workwq);

	kobject_del(&ptp->pps_data->kobj);

	kfree(ptp->pps_data);
	ptp->pps_data = NULL;
}
#endif

/* Initialise PTP channel and state.
 *
 * Setting core_index to zero causes the queue to be initialised and doesn't
 * overlap with 'rxq0' because ptp.c doesn't use skb_record_rx_queue.
 */
static int efx_ptp_probe_channel(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;
	struct efx_ptp_data *ptp;
	int rc = 0;
	unsigned int pos;

	channel->irq_moderation = 0;
	channel->rx_queue.core_index = 0;

	ptp = kzalloc(sizeof(struct efx_ptp_data), GFP_KERNEL);
	efx->ptp_data = ptp;
	if (!efx->ptp_data)
		return -ENOMEM;

#ifdef CONFIG_SFC_DEBUGFS
	for (pos = 0; pos < (MC_CMD_PTP_OUT_STATUS_LEN / sizeof(u32)); pos++)
		efx->ptp_data->mc_stats[pos] = pos;

	rc = efx_extend_debugfs_port(efx, efx->ptp_data, 0,
				     efx_debugfs_ptp_parameters);
	if (rc < 0)
		goto fail;
#endif

	rc = efx_nic_alloc_buffer(efx, &ptp->start, sizeof(int));
	if (rc != 0)
		goto fail1;

	ptp->channel = channel;
	skb_queue_head_init(&ptp->rxq);
	skb_queue_head_init(&ptp->txq);
	ptp->workwq = create_singlethread_workqueue("sfc_ptp");
	if (!ptp->workwq) {
		rc = -ENOMEM;
		goto fail2;
	}

	INIT_WORK(&ptp->work, efx_ptp_worker);
	ptp->config.flags = 0;
	ptp->config.tx_type = HWTSTAMP_TX_OFF;
	ptp->config.rx_filter = HWTSTAMP_FILTER_NONE;
	INIT_LIST_HEAD(&ptp->evt_list);
	INIT_LIST_HEAD(&ptp->evt_free_list);
	spin_lock_init(&ptp->evt_lock);
	for (pos = 0; pos < MAX_RECEIVE_EVENTS; pos++)
		list_add(&ptp->rx_evts[pos].link, &ptp->evt_free_list);

	ptp->phc_clock_info.owner = THIS_MODULE;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
	snprintf(ptp->phc_clock_info.name,
		 sizeof(ptp->phc_clock_info.name),
		 "%pm", efx->net_dev->perm_addr);
#endif
	ptp->phc_clock_info.max_adj = MAX_PPB;
	ptp->phc_clock_info.n_alarm = 0;
	ptp->phc_clock_info.n_ext_ts = 0;
	ptp->phc_clock_info.n_per_out = 0;
	ptp->phc_clock_info.pps = 1;
	ptp->phc_clock_info.adjfreq = efx_phc_adjfreq;
	ptp->phc_clock_info.adjtime = efx_phc_adjtime;
	ptp->phc_clock_info.gettime = efx_phc_gettime;
#if defined(EFX_HAVE_PHC_SUPPORT)
	ptp->phc_clock_info.settime = efx_phc_settime;
	ptp->phc_clock_info.enable = efx_phc_enable;

	ptp->phc_clock = ptp_clock_register(&ptp->phc_clock_info,
					    &efx->pci_dev->dev);
	if (!ptp->phc_clock)
		goto fail3;

	INIT_WORK(&ptp->pps_work, efx_ptp_pps_worker);
	ptp->pps_workwq = create_singlethread_workqueue("sfc_pps");
	if (!ptp->pps_workwq) {
		rc = -ENOMEM;
		goto fail4;
	}
#endif

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
	rc = efx_ptp_create_pps(ptp);

	if (rc < 0)
		goto fail5;	
#endif
	ptp->nic_ts_enabled = false;

#ifdef CONFIG_SFC_DEBUGFS
	ptp->min_sync_delta = UINT_MAX;

	rc = device_create_file(&efx->pci_dev->dev,
				&dev_attr_ptp_stats);
	if (rc < 0)
		goto fail6;
#endif

	rc = device_create_file(&efx->pci_dev->dev,
				&dev_attr_ptp_caps);
	if (rc < 0)
		goto fail7;

	return 0;

fail7:
#ifdef CONFIG_SFC_DEBUGFS
	device_remove_file(&efx->pci_dev->dev, &dev_attr_ptp_stats);
#endif
fail6:
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
	efx_ptp_destroy_pps(efx->ptp_data);
#endif
fail5:
#if defined(EFX_HAVE_PHC_SUPPORT)
	destroy_workqueue(efx->ptp_data->pps_workwq);
fail4:
	ptp_clock_unregister(efx->ptp_data->phc_clock);
#endif

fail3:
	destroy_workqueue(efx->ptp_data->workwq);

fail2:
	efx_nic_free_buffer(efx, &ptp->start);

fail1:
#ifdef CONFIG_SFC_DEBUGFS
	efx_trim_debugfs_port(efx, efx_debugfs_ptp_parameters);

fail:
#endif
	kfree(efx->ptp_data);
	efx->ptp_data = NULL;

	return rc;
}

static void efx_ptp_remove_channel(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;

	if (!efx->ptp_data)
		return;

	(void)efx_ptp_disable(channel->efx);

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
	efx_ptp_destroy_pps(efx->ptp_data);
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_WORK_SYNC)
	cancel_work_sync(&efx->ptp_data->work);
#if defined(EFX_HAVE_PHC_SUPPORT)
	cancel_work_sync(&efx->ptp_data->pps_work);
#endif
#endif
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_CANCEL_WORK_SYNC)
	flush_workqueue(efx->ptp_data->workwq);
#if defined(EFX_HAVE_PHC_SUPPORT)
	flush_workqueue(efx->ptp_data->pps_workwq);
#endif
#endif
	skb_queue_purge(&efx->ptp_data->rxq);
	skb_queue_purge(&efx->ptp_data->txq);

	device_remove_file(&efx->pci_dev->dev, &dev_attr_ptp_caps);
#ifdef CONFIG_SFC_DEBUGFS
	device_remove_file(&efx->pci_dev->dev, &dev_attr_ptp_stats);
#endif
#if defined(EFX_HAVE_PHC_SUPPORT)
	ptp_clock_unregister(efx->ptp_data->phc_clock);
#endif

	destroy_workqueue(efx->ptp_data->workwq);
#if defined(EFX_HAVE_PHC_SUPPORT)
	destroy_workqueue(efx->ptp_data->pps_workwq);
#endif

	efx_nic_free_buffer(efx, &efx->ptp_data->start);
#ifdef CONFIG_SFC_DEBUGFS
	efx_trim_debugfs_port(efx, efx_debugfs_ptp_parameters);
#endif
	kfree(efx->ptp_data);
}

static void efx_ptp_get_channel_name(struct efx_channel *channel,
				     char *buf, size_t len)
{
	snprintf(buf, len, "%s-ptp", channel->efx->name);
}

/* Determine whether this packet should be processed by the PTP module
 * or transmitted conventionally.
 */
bool efx_ptp_is_ptp_tx(struct efx_nic *efx, struct sk_buff *skb)
{
	return efx->ptp_data &&
		efx->ptp_data->enabled &&
		skb->len >= PTP_MIN_LENGTH &&
		skb->len <= MC_CMD_PTP_IN_TRANSMIT_PACKET_MAXNUM &&
		likely(skb->protocol == htons(ETH_P_IP)) &&
		ip_hdr(skb)->protocol == IPPROTO_UDP &&
		udp_hdr(skb)->dest == htons(PTP_EVENT_PORT);
}

/* Receive a PTP packet.  Packets are queued until the arrival of
 * the receive timestamp from the MC - this will probably occur after the
 * packet arrival because of the processing in the MC.
 */
static bool efx_ptp_rx(struct efx_channel *channel, struct sk_buff *skb)
{
	struct efx_nic *efx = channel->efx;
	struct efx_ptp_data *ptp = efx->ptp_data;
	struct efx_ptp_match *match = (struct efx_ptp_match *)skb->cb;
	u8 *match_data_012, *match_data_345;
	unsigned int version;
#if defined(EFX_NOT_UPSTREAM)
	unsigned int uuid_len;
	u8 domain, *uuid;
#if defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	struct efx_rx_buffer *rx_buff = channel->rx_pkt;
#endif
#endif

	match->expiry = jiffies + msecs_to_jiffies(PKT_EVENT_LIFETIME_MS);

	/* Correct version? */
	if (ptp->mode == MC_CMD_PTP_MODE_V1) {
		if (skb->len < PTP_V1_MIN_LENGTH) {
			return false;
		}
		version = ntohs(*(__be16 *)&skb->data[PTP_V1_VERSION_OFFSET]);
		if (version != PTP_VERSION_V1) {
			return false;
		}
		
		/* PTP V1 uses all six bytes of the UUID to match the packet
		 * to the timestamp */
		match_data_012 = skb->data + PTP_V1_UUID_OFFSET;
		match_data_345 = skb->data + PTP_V1_UUID_OFFSET + 3;
	} else {
		if (skb->len < PTP_V2_MIN_LENGTH) {
			return false;
		}
		version = skb->data[PTP_V2_VERSION_OFFSET];
		if ((version & PTP_VERSION_V2_MASK) != PTP_VERSION_V2) {
			return false;
		}

		/* bug 33070 The original implementation uses bytes 2-7 of
		 * the UUID to match the packet to the timestamp. This discards
		 * two of the bytes of the MAC address used to create the UUID.
		 * The PTP V2 enhanced mode fixes this issue and uses bytes 0-2
		 * and byte 5-7 of the UUID. */
		match_data_345 = skb->data + PTP_V2_UUID_OFFSET + 5;
		if (ptp->mode == MC_CMD_PTP_MODE_V2) {
			match_data_012 = skb->data + PTP_V2_UUID_OFFSET + 2;
		} else {
			match_data_012 = skb->data + PTP_V2_UUID_OFFSET + 0;
			BUG_ON(ptp->mode != MC_CMD_PTP_MODE_V2_ENHANCED);
		}
	}

	/* Does this packet require timestamping? */
	if (ntohs(*(__be16 *)&skb->data[PTP_DPORT_OFFSET]) == PTP_EVENT_PORT) {
		struct skb_shared_hwtstamps *timestamps;

#if defined(EFX_NOT_UPSTREAM)
		if (ptp->mode == MC_CMD_PTP_MODE_V1) {
			uuid = &skb->data[PTP_V1_UUID_OFFSET];
			uuid_len = PTP_V1_UUID_LENGTH;
		} else {
			uuid = &skb->data[PTP_V2_UUID_OFFSET];
			uuid_len = PTP_V2_UUID_LENGTH;
			
			domain = skb->data[PTP_V2_DOMAIN_OFFSET];
			if (ptp->domain_filter.enable &&
			    (ptp->domain_filter.domain != domain)) {
				return false;
			}
		}

		if (ptp->uuid_filter.enable &&
		    (memcmp(ptp->uuid_filter.uuid, uuid, uuid_len) != 0)) {
			return false;
		}

#if defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
		/* bug 33071 only singly tagged VLAN packets are currently
		 * supported for PTP. */
		if (((rx_buff->flags & EFX_RX_BUF_VLAN_XTAG) == 0) &&
		    (ptp->vlan_filter.num_vlan_tags != 0)) {
			return false;
		}

		if ((rx_buff->flags & EFX_RX_BUF_VLAN_XTAG) &&
		    ((ptp->vlan_filter.num_vlan_tags == 0) ||
		     (ptp->vlan_filter.vlan_tags[0] != rx_buff->vlan_tci))) {
			return false;
		}
#endif
#endif
		
		match->state = PTP_PACKET_STATE_UNMATCHED;

		/* Clear all timestamps held: filled in later */
		timestamps = skb_hwtstamps(skb);
		memset(timestamps, 0, sizeof(*timestamps));

		/* We expect the sequence number to be in the same position in
		 * the packet for PTP V1 and V2 */
		BUILD_BUG_ON(PTP_V1_SEQUENCE_OFFSET != PTP_V2_SEQUENCE_OFFSET);
		BUILD_BUG_ON(PTP_V1_SEQUENCE_LENGTH != PTP_V2_SEQUENCE_LENGTH);
		
		/* Extract UUID/Sequence information */
		match->words[0] = (match_data_012[0]         |
				   (match_data_012[1] << 8)  |
				   (match_data_012[2] << 16) |
				   (match_data_345[0] << 24));
		match->words[1] = (match_data_345[1]         |
				   (match_data_345[2] << 8)  |
				   (skb->data[PTP_V1_SEQUENCE_OFFSET +
					      PTP_V1_SEQUENCE_LENGTH - 1] <<
				    16));
	} else {
		match->state = PTP_PACKET_STATE_MATCH_UNWANTED;
	}
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	if (rx_buff->flags & EFX_RX_BUF_VLAN_XTAG) {
		match->vlan_tci = rx_buff->vlan_tci;
		match->flags = rx_buff->flags;
	}
#endif

	skb_queue_tail(&ptp->rxq, skb);
	queue_work(ptp->workwq, &ptp->work);

	return true;
}

/* Transmit a PTP packet.  This has to be transmitted by the MC
 * itself, through an MCDI call.  MCDI calls aren't permitted
 * in the transmit path so defer the actual transmission to a suitable worker.
 */
int efx_ptp_tx(struct efx_nic *efx, struct sk_buff *skb)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	
	skb_queue_tail(&ptp->txq, skb);

	if ((udp_hdr(skb)->dest == htons(PTP_EVENT_PORT)) &&
	    (skb->len <= MC_CMD_PTP_IN_TRANSMIT_PACKET_MAXNUM))
		efx_xmit_hwtstamp_pending(skb);
	queue_work(ptp->workwq, &ptp->work);

	return NETDEV_TX_OK;
}

static int efx_ptp_change_mode(struct efx_nic *efx, bool enable_wanted,
			       unsigned int new_mode)
{
	if ((enable_wanted != efx->ptp_data->enabled) ||
	    (enable_wanted && (efx->ptp_data->mode != new_mode))) {
		int rc;

		if (enable_wanted) {
			/* Change of mode requires disable */
			if (efx->ptp_data->enabled &&
			    (efx->ptp_data->mode != new_mode)) {
				efx->ptp_data->enabled = false;
				rc = efx_ptp_stop(efx);
				if (rc != 0)
					return rc;
			}

			/* Set new operating mode and establish
			 * baseline synchronisation, which must
			 * succeed.
			 */
			efx->ptp_data->mode = new_mode;
			rc = efx_ptp_start(efx);
			if (rc == 0) {
				rc = efx_ptp_synchronize(efx,
							 PTP_SYNC_ATTEMPTS * 2);
				if (rc != 0)
					efx_ptp_stop(efx);
			}
		} else {
			rc = efx_ptp_stop(efx);
		}

		if (rc != 0)
			return rc;

		efx->ptp_data->enabled = enable_wanted;
	}

	return 0;
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
int efx_ptp_ts_init(struct efx_nic *efx, struct hwtstamp_config *init,
		    bool try_improved_filtering)
#else
static int efx_ptp_ts_init(struct efx_nic *efx, struct hwtstamp_config *init,
			   bool try_improved_filtering)
#endif
{
	bool enable_wanted = false;
	unsigned int new_mode;
	int rc;

	if (!efx->ptp_data)
		return -ENOTTY;

	if (init->flags)
		return -EINVAL;

	if ((init->tx_type != HWTSTAMP_TX_OFF) &&
	    (init->tx_type != HWTSTAMP_TX_ON))
		return -ERANGE;

	new_mode = efx->ptp_data->mode;
	/* Determine whether any PTP HW operations are required */
	switch (init->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		break;
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
		init->rx_filter = HWTSTAMP_FILTER_PTP_V1_L4_EVENT;
		new_mode = MC_CMD_PTP_MODE_V1;
		enable_wanted = true;
		break;
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
		init->rx_filter = HWTSTAMP_FILTER_PTP_V2_L4_EVENT;
		new_mode = try_improved_filtering?
			MC_CMD_PTP_MODE_V2_ENHANCED: MC_CMD_PTP_MODE_V2;
		enable_wanted = true;
		break;
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
		/* Non-IP + IPv6 timestamping not supported */
		return -ERANGE;
		break;
	default:
		return -ERANGE;
	}

	if (init->tx_type != HWTSTAMP_TX_OFF)
		enable_wanted = true;

	rc = efx_ptp_change_mode(efx, enable_wanted, new_mode);
	/* bug 33070 - old versions of the firmware do not support the
	 * improved UUID filtering option. Similarly old versions of the
	 * application do not expect it to be enabled. If the firmware
	 * does not accept the enhanced mode, fall back to the standard
	 * PTP v2 UUID filtering. */
	if ((rc != 0) && (new_mode == MC_CMD_PTP_MODE_V2_ENHANCED))
		rc = efx_ptp_change_mode(efx, enable_wanted, MC_CMD_PTP_MODE_V2);
	if (rc != 0)
		return rc;

	efx->ptp_data->config = *init;

	return 0;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_PHC_SUPPORT)
int efx_ptp_get_ts_info(struct net_device *net_dev, struct ethtool_ts_info *ts_info)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	struct efx_ptp_data *ptp = efx->ptp_data;

	if (!ptp) {
		printk(KERN_ERR "ptp structure not set\n");
		return -EOPNOTSUPP;
	}

	ts_info->so_timestamping = (SOF_TIMESTAMPING_TX_HARDWARE |
				    SOF_TIMESTAMPING_RX_HARDWARE |
				    SOF_TIMESTAMPING_RAW_HARDWARE);
	ts_info->phc_index = ptp_clock_index(ptp->phc_clock);
	ts_info->tx_types = 1 << HWTSTAMP_TX_OFF | 1 << HWTSTAMP_TX_ON;
	ts_info->rx_filters = (1 << HWTSTAMP_FILTER_NONE |
			       1 << HWTSTAMP_FILTER_PTP_V1_L4_EVENT |
			       1 << HWTSTAMP_FILTER_PTP_V1_L4_SYNC |
			       1 << HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ |
			       1 << HWTSTAMP_FILTER_PTP_V2_L4_EVENT |
			       1 << HWTSTAMP_FILTER_PTP_V2_L4_SYNC |
			       1 << HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ);
	return 0;
}
#endif

int efx_ptp_ioctl(struct efx_nic *efx, struct ifreq *ifr, int cmd)
{
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)
	return -ENOTTY;
#else
	struct hwtstamp_config config;
	int rc;

	/* Not a PTP enabled port */
	if (!efx->ptp_data)
		return -ENOTTY;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	rc = efx_ptp_ts_init(efx, &config, true);
	if (rc != 0)
		return rc;

	return copy_to_user(ifr->ifr_data, &config, sizeof(config))
		? -EFAULT : 0;
#endif
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_NET_TSTAMP)

int efx_ptp_ts_read(struct efx_nic *efx, struct efx_ts_read *read)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	struct timespec uts;

	if (!ptp)
		return -ENOTTY;

	local_bh_disable();
	read->tx_valid = ptp->tx_ts_valid;
	if (ptp->tx_ts_valid) {
		ptp->tx_ts_valid = 0;
		uts = ktime_to_timespec(ptp->tx_ts.syststamp);
		read->tx_ts.tv_sec = uts.tv_sec;
		read->tx_ts.tv_nsec = uts.tv_nsec;
		uts = ktime_to_timespec(ptp->tx_ts.hwtstamp);
		read->tx_ts_hw.tv_sec = uts.tv_sec;
		read->tx_ts_hw.tv_nsec = uts.tv_nsec;
	}
	read->rx_valid = 0;
	if (ptp->rx_ts_head != ptp->rx_ts_tail) {
		struct efx_ptp_rx_timestamp *ts;

		ts = &ptp->rx_ts[ptp->rx_ts_head];
		uts = ktime_to_timespec(ts->ts.syststamp);
		read->rx_ts.tv_sec = uts.tv_sec;
		read->rx_ts.tv_nsec = uts.tv_nsec;
		uts = ktime_to_timespec(ts->ts.hwtstamp);
		read->rx_ts_hw.tv_sec = uts.tv_sec;
		read->rx_ts_hw.tv_nsec = uts.tv_nsec;
		memcpy(read->uuid, ts->uuid, sizeof(read->uuid));
		memcpy(read->seqid, ts->seqid, sizeof(read->seqid));
		read->rx_valid = 1;

		ptp->rx_ts_head++;
		if (ptp->rx_ts_head >= MAX_RX_TS_ENTRIES)
			ptp->rx_ts_head = 0;
	}
	local_bh_enable();

	return 0;
}
#endif

#if defined(EFX_NOT_UPSTREAM)
int efx_ptp_ts_settime(struct efx_nic *efx, struct efx_ts_settime *settime)
{
	int ret;
	struct timespec ts;
	s64 delta;

	ts.tv_sec = settime->ts.tv_sec;
	ts.tv_nsec = settime->ts.tv_nsec;

	if (settime->iswrite) {
		delta = timespec_to_ns(&ts);

		return efx_phc_adjtime(&efx->ptp_data->phc_clock_info, delta);
	} else {
		ret = efx_phc_gettime(&efx->ptp_data->phc_clock_info, &ts);
		if (!ret) {
			settime->ts.tv_sec = ts.tv_sec;
			settime->ts.tv_nsec = ts.tv_nsec;
		}
		return ret;
	}
}

int efx_ptp_ts_adjtime(struct efx_nic *efx, struct efx_ts_adjtime *adjtime)
{
	if (adjtime->adjustment > MAX_PPB)
		adjtime->adjustment = MAX_PPB;
	else if (adjtime->adjustment < -MAX_PPB)
		adjtime->adjustment = -MAX_PPB;

	return efx_phc_adjfreq(&efx->ptp_data->phc_clock_info, adjtime->adjustment);
}

int efx_ptp_ts_sync(struct efx_nic *efx, struct efx_ts_sync *sync)
{
	int rc;

	if (!efx->ptp_data)
		return -ENOTTY;

	rc = efx_ptp_synchronize(efx, PTP_SYNC_ATTEMPTS);
	if (rc == 0) {
		sync->ts.tv_sec = efx->ptp_data->last_delta.tv_sec;
		sync->ts.tv_nsec = efx->ptp_data->last_delta.tv_nsec;
	}

	return rc;
}

int efx_ptp_ts_set_vlan_filter(struct efx_nic *efx,
			       struct efx_ts_set_vlan_filter *vlan_filter)
{
	u8 mcdi_req[MC_CMD_PTP_IN_RX_SET_VLAN_FILTER_LEN];
	u32 *tag;
	int i, rc;

	if (!efx->ptp_data)
		return -ENOTTY;

	if (vlan_filter->num_vlan_tags > TS_MAX_VLAN_TAGS)
		return -ERANGE;

	MCDI_SET_DWORD(mcdi_req, PTP_IN_OP, MC_CMD_PTP_OP_RX_SET_VLAN_FILTER);
	MCDI_SET_DWORD(mcdi_req, PTP_IN_RX_SET_VLAN_FILTER_NUM_VLAN_TAGS,
		       vlan_filter->num_vlan_tags);
	tag = (u32 *)MCDI_PTR(mcdi_req, PTP_IN_RX_SET_VLAN_FILTER_VLAN_TAG);
	for (i = 0; i < vlan_filter->num_vlan_tags; i++)
		tag[i] = vlan_filter->vlan_tags[i];
	
	rc = efx_mcdi_rpc(efx, MC_CMD_PTP, mcdi_req, sizeof(mcdi_req),
			  NULL, 0, NULL);
	if (rc == 0)
		efx->ptp_data->vlan_filter = *vlan_filter;
	
	return rc;
}

int efx_ptp_ts_set_uuid_filter(struct efx_nic *efx,
			       struct efx_ts_set_uuid_filter *uuid_filter)
{
	u8 mcdi_req[MC_CMD_PTP_IN_RX_SET_UUID_FILTER_LEN];
	u8 *uuid;
	int rc;

	if (!efx->ptp_data)
		return -ENOTTY;

	MCDI_SET_DWORD(mcdi_req, PTP_IN_OP, MC_CMD_PTP_OP_RX_SET_UUID_FILTER);
	MCDI_SET_DWORD(mcdi_req, PTP_IN_RX_SET_UUID_FILTER_ENABLE,
		       uuid_filter->enable);
	uuid = (u8 *)MCDI_PTR(mcdi_req, PTP_IN_RX_SET_UUID_FILTER_UUID);
	memcpy(uuid, uuid_filter->uuid,
	       MC_CMD_PTP_IN_RX_SET_UUID_FILTER_UUID_LEN);

	rc = efx_mcdi_rpc(efx, MC_CMD_PTP, mcdi_req, sizeof(mcdi_req),
			  NULL, 0, NULL);
	if (rc == 0)
		efx->ptp_data->uuid_filter = *uuid_filter;
	
	return rc;
}

int efx_ptp_ts_set_domain_filter(struct efx_nic *efx,
				 struct efx_ts_set_domain_filter *domain_filter)
{
	u8 mcdi_req[MC_CMD_PTP_IN_RX_SET_DOMAIN_FILTER_LEN];
	int rc;

	if (!efx->ptp_data)
		return -ENOTTY;

	MCDI_SET_DWORD(mcdi_req, PTP_IN_OP,
		       MC_CMD_PTP_OP_RX_SET_DOMAIN_FILTER);
	MCDI_SET_DWORD(mcdi_req, PTP_IN_RX_SET_DOMAIN_FILTER_ENABLE,
		       domain_filter->enable);
	MCDI_SET_DWORD(mcdi_req, PTP_IN_RX_SET_DOMAIN_FILTER_DOMAIN,
		       domain_filter->domain);

	rc = efx_mcdi_rpc(efx, MC_CMD_PTP, mcdi_req, sizeof(mcdi_req),
			  NULL, 0, NULL);
	if (rc == 0)
		efx->ptp_data->domain_filter = *domain_filter;
	
	return rc;
}
#endif

static void ptp_event_failure(struct efx_nic *efx, int expected_frag_len)
{
	struct efx_ptp_data *ptp = efx->ptp_data;

	netif_err(efx, hw, efx->net_dev,
		"PTP unexpected event length: got %d expected %d\n",
		ptp->evt_frag_idx, expected_frag_len);
	ptp->reset_required = true;
	queue_work(ptp->workwq, &ptp->work);
}

static inline void ptp_unpack_ts(struct efx_ptp_event_ts *ts,
				 efx_qword_t evt_frags[MAX_EVENT_FRAGS])
{
	ts->seq0 = EFX_QWORD_FIELD(evt_frags[2], MCDI_EVENT_DATA);
	ts->seq1 = (EFX_QWORD_FIELD(evt_frags[2], MCDI_EVENT_SRC) |
		    (EFX_QWORD_FIELD(evt_frags[1], MCDI_EVENT_SRC) << 8) |
		    (EFX_QWORD_FIELD(evt_frags[0], MCDI_EVENT_SRC) << 16));
	ts->hwtimestamp = ktime_set(
			EFX_QWORD_FIELD(evt_frags[0], MCDI_EVENT_DATA),
			EFX_QWORD_FIELD(evt_frags[1], MCDI_EVENT_DATA));
}

/* Process a completed receive event.  Put it on the event queue and
 * start worker thread.  This is required because event and their
 * correspoding packets may come in either order.
 */
static void ptp_event_rx(struct efx_nic *efx, struct efx_ptp_data *ptp)
{
	struct efx_ptp_event_rx *evt = NULL;

	if (ptp->evt_frag_idx != 3) {
		ptp_event_failure(efx, 3);
		return;
	}

	spin_lock_bh(&ptp->evt_lock);
	if (!list_empty(&ptp->evt_free_list)) {
		evt = list_first_entry(&ptp->evt_free_list,
				       struct efx_ptp_event_rx, link);
		list_del(&evt->link);

		ptp_unpack_ts(&evt->ts, ptp->evt_frags);

		evt->expiry = jiffies + msecs_to_jiffies(PKT_EVENT_LIFETIME_MS);
		list_add_tail(&evt->link, &ptp->evt_list);

		queue_work(ptp->workwq, &ptp->work);
	} else {
		netif_err(efx, rx_err, efx->net_dev, "No free PTP event");
	}
	spin_unlock_bh(&ptp->evt_lock);
}

static void ptp_event_fault(struct efx_nic *efx, struct efx_ptp_data *ptp)
{
	int code = EFX_QWORD_FIELD(ptp->evt_frags[0], MCDI_EVENT_DATA);
	if (ptp->evt_frag_idx != 1) {
		ptp_event_failure(efx, 1);
		return;
	}

	netif_err(efx, hw, efx->net_dev, "PTP error %d\n", code);
}

static void ptp_event_pps(struct efx_nic *efx, struct efx_ptp_data *ptp)
{
#if defined(EFX_HAVE_PHC_SUPPORT)
	if (ptp->nic_ts_enabled)
		queue_work(ptp->pps_workwq, &ptp->pps_work);
#endif
}

static void hw_pps_event_pps(struct efx_nic *efx, struct efx_ptp_data *ptp)
{
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
	struct efx_pps_data *pps = efx->ptp_data->pps_data;

	ptp_unpack_ts(&pps->n_assert, ptp->evt_frags);

	if (pps->nic_hw_pps_enabled)
		queue_work(pps->hw_pps_workwq, &pps->hw_pps_work);
#endif
}

void efx_ptp_event(struct efx_nic *efx, efx_qword_t *ev)
{
	struct efx_ptp_data *ptp = efx->ptp_data;
	int code = EFX_QWORD_FIELD(*ev, MCDI_EVENT_CODE);
	bool enabled = ptp->enabled;

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_PPS)
	enabled = enabled || ptp->pps_data->nic_hw_pps_enabled;
#endif
	if (!enabled)
		return;

	if (ptp->evt_frag_idx == 0) {
		ptp->evt_code = code;
	} else if (ptp->evt_code != code) {
		netif_err(efx, hw, efx->net_dev,
			  "PTP out of sequence event %d\n", code);
		ptp->evt_frag_idx = 0;
	}

	ptp->evt_frags[ptp->evt_frag_idx++] = *ev;
	if (!MCDI_EVENT_FIELD(*ev, CONT)) {
		/* Process resulting event */
		switch (code) {
		case MCDI_EVENT_CODE_PTP_RX:
			ptp_event_rx(efx, ptp);
			break;
		case MCDI_EVENT_CODE_PTP_FAULT:
			ptp_event_fault(efx, ptp);
			break;
		case MCDI_EVENT_CODE_PTP_PPS:
			ptp_event_pps(efx, ptp);
			break;
		case MCDI_EVENT_CODE_HW_PPS:
			hw_pps_event_pps(efx, ptp);
			break;
		default:
			netif_err(efx, hw, efx->net_dev,
				  "PTP unknown event %d\n", code);
			break;
		}
		ptp->evt_frag_idx = 0;
	} else if (MAX_EVENT_FRAGS == ptp->evt_frag_idx) {
		netif_err(efx, hw, efx->net_dev,
			  "PTP too many event fragments\n");
		ptp->evt_frag_idx = 0;
	}
}

static int efx_phc_adjfreq(struct ptp_clock_info *ptp, s32 delta)
{
	struct efx_ptp_data *ptp_data = container_of(ptp,
						     struct efx_ptp_data,
						     phc_clock_info);
	struct efx_nic *efx = ptp_data->channel->efx;
	u8 inadj[MC_CMD_PTP_IN_CLOCK_FREQ_ADJUST_LEN];
	s64 adjustment_ns;
	int rc;

	if (delta > MAX_PPB)
		delta = MAX_PPB;
	else if (delta < -MAX_PPB)
		delta = -MAX_PPB;

	/* Convert ppb to fixed point ns. */
	adjustment_ns = (((s64)delta * PPB_SCALE_WORD) >>
			 (PPB_EXTRA_BITS + MAX_PPB_BITS));

	MCDI_SET_DWORD(inadj, PTP_IN_OP, MC_CMD_PTP_OP_CLOCK_FREQ_ADJUST);
	MCDI_SET_DWORD(inadj, PTP_IN_CLOCK_FREQ_ADJUST_FREQ_LO,
		       (u32)adjustment_ns);
	MCDI_SET_DWORD(inadj, PTP_IN_CLOCK_FREQ_ADJUST_FREQ_HI,
		       (u32)(adjustment_ns >> 32));
	rc = efx_mcdi_rpc(efx, MC_CMD_PTP, inadj, sizeof(inadj),
			  NULL, 0, NULL);
	if (rc != 0)
		return rc;

	ptp_data->current_adjfreq = delta;
	return 0;
}

static int efx_phc_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct efx_ptp_data *ptp_data = container_of(ptp,
						     struct efx_ptp_data,
						     phc_clock_info);
	struct efx_nic *efx = ptp_data->channel->efx;
	struct timespec delta_ts = ns_to_timespec(delta);
	u8 inbuf[MC_CMD_PTP_IN_CLOCK_OFFSET_ADJUST_LEN];

	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_CLOCK_OFFSET_ADJUST);
	MCDI_SET_DWORD(inbuf, PTP_IN_CLOCK_OFFSET_ADJUST_SECONDS,
		       (u32)delta_ts.tv_sec);
	MCDI_SET_DWORD(inbuf, PTP_IN_CLOCK_OFFSET_ADJUST_NANOSECONDS,
		       (u32)delta_ts.tv_nsec);
	return efx_mcdi_rpc(efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

static int efx_phc_gettime(struct ptp_clock_info *ptp, struct timespec *ts)
{
	struct efx_ptp_data *ptp_data = container_of(ptp,
						     struct efx_ptp_data,
						     phc_clock_info);
	struct efx_nic *efx = ptp_data->channel->efx;
	u8 inbuf[MC_CMD_PTP_IN_READ_NIC_TIME_LEN];
	u8 outbuf[MC_CMD_PTP_OUT_READ_NIC_TIME_LEN];
	int rc;

	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_READ_NIC_TIME);

	rc = efx_mcdi_rpc(efx, MC_CMD_PTP, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), NULL);
	if (rc != 0)
		return rc;

	ts->tv_sec = MCDI_DWORD(outbuf, PTP_OUT_READ_NIC_TIME_SECONDS);
	ts->tv_nsec = MCDI_DWORD(outbuf, PTP_OUT_READ_NIC_TIME_NANOSECONDS);
	return 0;
}

#if defined(EFX_HAVE_PHC_SUPPORT)
static int efx_phc_settime(struct ptp_clock_info *ptp,
			   const struct timespec *e_ts)
{
	/* Get the current NIC time, efx_phc_gettime.
	 * Subtract from the desired time to get the offset
	 * call efx_phc_adjtime with the offset
	 */
	int rc;
	struct timespec time_now;
	struct timespec delta;

	rc = efx_phc_gettime(ptp, &time_now);
	if (rc != 0)
		return rc;

	delta = timespec_sub(*e_ts, time_now);

	efx_phc_adjtime(ptp, timespec_to_ns(&delta));
	if (rc != 0)
		return rc;

	return 0;
}


static int efx_phc_enable(struct ptp_clock_info *ptp,
			  struct ptp_clock_request *request,
			  int enable)
{
	struct efx_ptp_data *ptp_data = container_of(ptp,
						     struct efx_ptp_data,
						     phc_clock_info);
	if (request->type != PTP_CLK_REQ_PPS)
		return -EOPNOTSUPP;

	ptp_data->nic_ts_enabled = !!enable;
	return 0;
}
#endif

static const struct efx_channel_type efx_ptp_channel_type = {
	.handle_no_channel	= efx_ptp_handle_no_channel,
	.pre_probe		= efx_ptp_probe_channel,
	.post_remove		= efx_ptp_remove_channel,
	.get_name		= efx_ptp_get_channel_name,
	/* no copy operation; there is no need to reallocate this channel */
	.receive_skb		= efx_ptp_rx,
	.keep_eventq		= false,
};

void efx_ptp_probe(struct efx_nic *efx)
{
	/* Check whether PTP is implemented on this NIC.  The DISABLE
	 * operation will succeed if and only if it is implemented.
	 */
	if (efx_ptp_disable(efx) == 0)
		efx->extra_channel_type[EFX_EXTRA_CHANNEL_PTP] =
			&efx_ptp_channel_type;
}
