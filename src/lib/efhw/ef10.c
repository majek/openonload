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
 * This file contains EF10 hardware support.
 *
 * Copyright 2005-2008: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
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

#include <ci/driver/efab/hardware.h>
#include <ci/efhw/debug.h>
#include <ci/efhw/iopage.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/checks.h>
#include <ci/efhw/efhw_buftable.h>

#include <driver/linux_net/driverlink_api.h>
#include <driver/linux_net/mcdi_pcol.h>
#include <ci/driver/resource/linux_efhw_nic.h>

#if EFX_DRIVERLINK_API_VERSION >= 9
#include <ci/efhw/ef10.h>
#include "ef10_mcdi.h"

/* We base owner ids from 1 within Onload so that we can use owner id 0 as
 * as easy check whether a pd is using physical addressing mode.  However, we
 * don't want to use up part of our actual owner id space, which is 0 based,
 * so subtract back to 0 based when talking to the firmware.
 */
#define REAL_OWNER_ID(owner_id) ((owner_id) ? ((owner_id) - 1) : 0)

/*----------------------------------------------------------------------------
 *
 * Helper for MCDI operations
 *
 *---------------------------------------------------------------------------*/

static int ef10_mcdi_rpc(struct efhw_nic *nic, unsigned int cmd,
			 size_t inlen, size_t outlen, size_t *outlen_actual,
			 const u8 *inbuf, u8 *outbuf)
{
	if( nic->resetting )
		return 0;
	return efx_dl_mcdi_rpc(linux_efhw_nic(nic)->dl_device, cmd, 
			       inlen, outlen, outlen_actual, inbuf, outbuf);
}


static void check_response(const char* caller, const char* failed_cmd, 
			   int rc, int expected_len, int actual_len)
{
	/* The NIC will return error if we gave it invalid arguments
	 * or if something has gone wrong in the hardware at which
	 * point, we should try to reset the NIC or something similar.
	 * At this layer, we assume that the caller has not passed us
	 * bogus arguments.  Since we do not have the ability to
	 * initiate reset of NICs.  We will just print a scary warning
	 * and continue. */
	if (rc != 0) {
		EFHW_ERR("%s: %s failed rc=%d", caller, failed_cmd, rc);
	}
	else if ( expected_len != actual_len ) {
		EFHW_ERR("%s: %s failed, expected response len %d, got %d",
			 caller, failed_cmd, expected_len, actual_len);
	}
}


/*----------------------------------------------------------------------------
 *
 * Initialisation and configuration discovery
 *
 *---------------------------------------------------------------------------*/

static void ef10_nic_close_hardware(struct efhw_nic *nic)
{
	return;
}


static int _ef10_nic_check_35388_workaround(struct efhw_nic *nic) {
	int rc;
	size_t out_size;

	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_WORKAROUND_IN_LEN);

	EFHW_MCDI_SET_DWORD(in, WORKAROUND_IN_ENABLED, 1);
	EFHW_MCDI_SET_DWORD(in, WORKAROUND_IN_TYPE,
		MC_CMD_WORKAROUND_BUG35388);

	rc = ef10_mcdi_rpc(nic, MC_CMD_WORKAROUND, sizeof(in), 0,
		&out_size, (const char const*)&in, NULL);

	if ( rc == 0 )
		/* Workaround is enabled on this hardware. */
		return 1;
	else if ( rc == EINVAL )
		/* Workaround is not enabled on this hardware. */
		return 0;
	else
		/* MCDI failure. */
		EFHW_ERR("%s: failed rc=%d", __FUNCTION__, rc);

	return -1;
}


static int
_ef10_nic_check_supported_filter(struct efhw_nic *nic, unsigned filter) {
	int rc, num_matches, i;
	size_t out_size;

	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_GET_PARSER_DISP_INFO_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMAX);

	EFHW_MCDI_SET_DWORD(in, GET_PARSER_DISP_INFO_IN_OP,
		MC_CMD_GET_PARSER_DISP_INFO_IN_OP_GET_SUPPORTED_RX_MATCHES);

	rc = ef10_mcdi_rpc(nic, MC_CMD_GET_PARSER_DISP_INFO,
			   sizeof(in), sizeof(out), &out_size,
			   (const char*)&in, (char*)&out);
	if( rc != 0 )
		EFHW_ERR("%s: failed rc=%d", __FUNCTION__, rc);
	else if ( out_size < MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMIN )
		EFHW_ERR("%s: failed, expected response min len %d, got %d",
			__FUNCTION__, MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMIN,
			(int)out_size);

	num_matches = EFHW_MCDI_VAR_ARRAY_LEN(out_size,
		GET_PARSER_DISP_INFO_OUT_SUPPORTED_MATCHES);

	for(i = 0; i < num_matches; i++)
		if ( EFHW_MCDI_ARRAY_DWORD(out,
		     GET_PARSER_DISP_INFO_OUT_SUPPORTED_MATCHES, i) == filter )
			return 1;

	return 0;
}


static int
_ef10_nic_check_licence(struct efhw_nic *nic) {
	size_t out_size;
	int rc;
	int licenced;

	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_GET_LICENSED_APP_STATE_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_GET_LICENSED_APP_STATE_OUT_LEN);

	EFHW_MCDI_SET_DWORD(in, GET_LICENSED_APP_STATE_IN_APP_ID,
			    LICENSED_APP_ID_ONLOAD);

	rc = ef10_mcdi_rpc(nic, MC_CMD_GET_LICENSED_APP_STATE,
			   sizeof(in), sizeof(out), &out_size,
			   (const char*)&in, (char*)&out);
	check_response("_ef10_nic_init_license", __FUNCTION__, rc,
		       MC_CMD_GET_LICENSED_APP_STATE_OUT_LEN, out_size);
	if (rc != 0)
		return rc;

	licenced = 
		EFHW_MCDI_DWORD(out, GET_LICENSED_APP_STATE_OUT_STATE);
	return licenced == MC_CMD_GET_LICENSED_APP_STATE_OUT_LICENSED;
}


static int
ef10_nic_license_challenge(struct efhw_nic *nic, 
			   const uint32_t feature, 
			   const uint8_t* challenge, 
			   uint32_t* expiry,
			   uint8_t* signature) {
	size_t out_size;
	int rc;

	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_LICENSED_APP_OP_VALIDATE_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_LICENSED_APP_OP_VALIDATE_OUT_LEN);

	EFHW_TRACE("%s:", __FUNCTION__);

	EFHW_ASSERT(challenge);
	EFHW_ASSERT(expiry);
	EFHW_ASSERT(signature);

	EFHW_MCDI_SET_DWORD(in, LICENSED_APP_OP_VALIDATE_IN_APP_ID, feature);
	EFHW_MCDI_SET_DWORD(in, LICENSED_APP_OP_VALIDATE_IN_OP, 
			    MC_CMD_LICENSED_APP_OP_IN_OP_VALIDATE);

	memcpy(_EFHW_MCDI_ARRAY_PTR(in, LICENSED_APP_OP_VALIDATE_IN_CHALLENGE, 0, 4),
	       challenge, MC_CMD_LICENSED_APP_OP_VALIDATE_IN_CHALLENGE_LEN);

	rc = ef10_mcdi_rpc(nic, MC_CMD_LICENSED_APP_OP,
			   sizeof(in), sizeof(out), &out_size,
			   (const char*)&in, (char*)&out);
	if (rc != 0)
	  return rc;

	check_response("ef10_nic_challenge_licence", __FUNCTION__, rc,
		       MC_CMD_LICENSED_APP_OP_VALIDATE_OUT_LEN, out_size);

	*expiry = EFHW_MCDI_DWORD(out, LICENSED_APP_OP_VALIDATE_OUT_EXPIRY);

	memcpy(signature, 
	       _EFHW_MCDI_ARRAY_PTR(out, LICENSED_APP_OP_VALIDATE_OUT_RESPONSE, 0, 4), 
	       MC_CMD_LICENSED_APP_OP_VALIDATE_OUT_RESPONSE_LEN);

	return 0;
}


static int _ef10_nic_check_capabilities(struct efhw_nic *nic,
					unsigned* capabitlity_flags,
					const char* caller)
{
	/* Initialise out_size so that we can pass it to check_response even
	 * when the MCDI command fails without upsetting the compiler. */
	size_t out_size = 0;
	size_t ver_out_size;
	unsigned flags;
	char ver_buf[32];
	const __le16 *ver_words;
	int rc;

	EFHW_MCDI_DECLARE_BUF(ver_out, MC_CMD_GET_VERSION_OUT_LEN);
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_GET_CAPABILITIES_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_GET_CAPABILITIES_OUT_LEN);

	rc = ef10_mcdi_rpc(nic, MC_CMD_GET_CAPABILITIES,
			   sizeof(in), sizeof(out), &out_size,
			   (const char*)&in, (char*)&out);
	check_response(caller, __FUNCTION__, rc,
		       MC_CMD_GET_CAPABILITIES_OUT_LEN, out_size);
	if (rc != 0)
		return rc;
	flags = EFHW_MCDI_DWORD(out, GET_CAPABILITIES_OUT_FLAGS1);
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_OUT_RX_PREFIX_LEN_14_LBN))
		*capabitlity_flags |= NIC_FLAG_14BYTE_PREFIX;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_OUT_TX_MCAST_UDP_LOOPBACK_LBN))
		*capabitlity_flags |= NIC_FLAG_MCAST_LOOP_HW;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_OUT_RX_PACKED_STREAM_LBN)) {
		rc = ef10_mcdi_rpc(nic, MC_CMD_GET_VERSION, 0, sizeof(ver_out),
				   &ver_out_size, NULL, (char*)&ver_out);
		if (rc == 0 && ver_out_size == MC_CMD_GET_VERSION_OUT_LEN) {
			ver_words = (__le16*)EFHW_MCDI_PTR(
				ver_out, GET_VERSION_OUT_VERSION);
			snprintf(ver_buf, 32, "%u.%u.%u.%u",
				 le16_to_cpu(ver_words[0]),
				 le16_to_cpu(ver_words[1]),
				 le16_to_cpu(ver_words[2]),
				 le16_to_cpu(ver_words[3]));
			if (!strcmp(ver_buf, "4.1.1.1022"))
				EFHW_ERR("%s: Error: Due to a known firmware "
					 "bug, packed stream mode is disabled "
					 "on version %s.  Please upgrade "
					 "firmware to use packed stream.",
					 __FUNCTION__, ver_buf);
			else
				*capabitlity_flags |= NIC_FLAG_PACKED_STREAM;
		}
		else {
			*capabitlity_flags |= NIC_FLAG_PACKED_STREAM;
		}
	}
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_OUT_RX_RSS_LIMITED_LBN))
		*capabitlity_flags |= NIC_FLAG_RX_RSS_LIMITED;
	return rc;
}


static int _ef10_nic_get_rx_timestamp_correction(struct efhw_nic *nic,
						  int *rx_ts_correction,
						  const char* caller)
{
	int rc;
	size_t out_size;

	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PTP_IN_GET_TIMESTAMP_CORRECTIONS_LEN);
	EFHW_MCDI_DECLARE_BUF(out,
			      MC_CMD_PTP_OUT_GET_TIMESTAMP_CORRECTIONS_LEN);

	EFHW_MCDI_SET_DWORD(in, PTP_IN_OP,
			    MC_CMD_PTP_OP_GET_TIMESTAMP_CORRECTIONS);
	EFHW_MCDI_SET_DWORD(in, PTP_IN_PERIPH_ID, 0);

	rc = ef10_mcdi_rpc(nic, MC_CMD_PTP, sizeof(in), sizeof(out), &out_size,
			   (const char*)in, (char*)out);
	check_response(caller, __FUNCTION__, rc,
		       MC_CMD_PTP_OUT_GET_TIMESTAMP_CORRECTIONS_LEN, out_size);
	if( rc == 0 )
		*rx_ts_correction =
		EFHW_MCDI_DWORD(out, PTP_OUT_GET_TIMESTAMP_CORRECTIONS_RECEIVE);
	return rc;
}


static void
ef10_nic_tweak_hardware(struct efhw_nic *nic)
{
	/* No need to set RX_USR_BUF_SIZE for ef10, it's done
	 * per-descriptor
	 */


	/* EF10 TODO: anything needed for Huntington that wasn't
	 * needed for Falcon 
	 */

#define VLAN_IP_WILD   (1 << MC_CMD_FILTER_OP_IN_MATCH_DST_IP_LBN |     \
                        1 << MC_CMD_FILTER_OP_IN_MATCH_DST_PORT_LBN |   \
                        1 << MC_CMD_FILTER_OP_IN_MATCH_ETHER_TYPE_LBN | \
                        1 << MC_CMD_FILTER_OP_IN_MATCH_OUTER_VLAN_LBN | \
                        1 << MC_CMD_FILTER_OP_IN_MATCH_IP_PROTO_LBN)

	nic->flags &= ~(NIC_FLAG_MCAST_LOOP_HW | NIC_FLAG_14BYTE_PREFIX |
			NIC_FLAG_VLAN_FILTERS | NIC_FLAG_BUG35388_WORKAROUND);

	if( _ef10_nic_check_supported_filter(nic, VLAN_IP_WILD) )
		nic->flags |= NIC_FLAG_VLAN_FILTERS;

	if( _ef10_nic_check_35388_workaround(nic) )
		nic->flags |= NIC_FLAG_BUG35388_WORKAROUND;

	_ef10_nic_check_capabilities(nic, &nic->flags, __FUNCTION__);

	nic->rx_prefix_len = (nic->flags & NIC_FLAG_14BYTE_PREFIX) ?
			      14 :
			      0;

#if EFX_DRIVERLINK_API_VERSION < 15
	nic->flags &= ~NIC_FLAG_MCAST_LOOP_HW;
#endif
}


static int
ef10_nic_init_hardware(struct efhw_nic *nic,
		       struct efhw_ev_handler *ev_handlers,
		       const uint8_t *mac_addr, int non_irq_evq,
		       int bt_min, int bt_lim)
{
	int rc;
	EFHW_TRACE("%s:", __FUNCTION__);

	nic->flags |= NIC_FLAG_10G;

	memcpy(nic->mac_addr, mac_addr, ETH_ALEN);

	ef10_nic_tweak_hardware(nic);

	rc = _ef10_nic_check_licence(nic);
	if( rc < 0 ) return rc;
	if( rc == 0 ) {
		EFHW_ERR("%s: Firmware reports no Onload licence present",
			 __FUNCTION__);
		return -EOPNOTSUPP;
	}

	/* No buffer_table_ctor() on EF10 */
	/* No non_irq_evq on EF10 */

	return 0;
}


/*--------------------------------------------------------------------
 *
 * Events - MCDI cmds and register interface
 *
 *--------------------------------------------------------------------*/


static int
_ef10_mcdi_cmd_event_queue_enable(struct efhw_nic *nic,
				  uint evq, /* evq id */
				  uint evq_size, /* Number of events */
				  dma_addr_t *dma_addrs,
				  uint n_pages,
				  uint interrupting,
				  uint enable_dos_p,
				  uint enable_cut_through,
				  int wakeup_evq)
{
	int rc, i;
	uint32_t out;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_INIT_EVQ_IN_LEN(n_pages));
	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_SIZE, evq_size);
	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_INSTANCE, evq);
	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_TMR_LOAD, 0);
	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_TMR_RELOAD, 0);

	/* TX merging is needed for good throughput with small
	 * packets.  TX and RX event merging must be requested
	 * together (or not at all). Cut through reduces latency, but
	 * is incompatible with RX event merging.  Enabling cut
	 * through causes firmware to disables RX event merging.  So
	 * by requesting all three we get what we want: cut through
	 * and tx event merging. Onload drivers don't support RX event
	 * merging yet, so this is good...
	 */
	EFHW_MCDI_POPULATE_DWORD_5(in, INIT_EVQ_IN_FLAGS,
		INIT_EVQ_IN_FLAG_INTERRUPTING, interrupting ? 1 : 0,
		INIT_EVQ_IN_FLAG_RPTR_DOS, enable_dos_p ? 1 : 0,
		INIT_EVQ_IN_FLAG_CUT_THRU, enable_cut_through ? 1 : 0,
		INIT_EVQ_IN_FLAG_RX_MERGE, 1,
		INIT_EVQ_IN_FLAG_TX_MERGE, 1);

	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_TMR_MODE, 
			    MC_CMD_INIT_EVQ_IN_TMR_MODE_DIS);

	/* EF10 TODO We may want to direct the wakeups to another EVQ,
	 * but by default do Falcon-style spreading
	 */
	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_TARGET_EVQ, wakeup_evq);

	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_COUNT_MODE,
			    MC_CMD_INIT_EVQ_IN_COUNT_MODE_DIS);
	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_COUNT_THRSHLD, 0);

	for( i = 0; i < n_pages; ++i ) {
		EFHW_MCDI_SET_ARRAY_QWORD(in, INIT_EVQ_IN_DMA_ADDR, i, 
					  dma_addrs[i]);
	}

	EFHW_ASSERT(evq >= 0);
	EFHW_ASSERT(evq < nic->num_evqs);

	rc = ef10_mcdi_rpc(nic, MC_CMD_INIT_EVQ, sizeof(in), sizeof(out),
			   &out_size, (const char const*)&in, (char *)&out);
	check_response("ef10_nic_event_queue_enable", __FUNCTION__, rc,
		       MC_CMD_INIT_EVQ_OUT_LEN, out_size);
        return rc;
}


static void
_ef10_mcdi_cmd_event_queue_disable(struct efhw_nic *nic, uint evq)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FINI_EVQ_IN_LEN);
	EFHW_MCDI_SET_DWORD(in, FINI_EVQ_IN_INSTANCE, evq);

	EFHW_ASSERT(evq >= 0);
	EFHW_ASSERT(evq < nic->num_evqs);

	rc = ef10_mcdi_rpc(nic, MC_CMD_FINI_EVQ, sizeof(in), 0,
			   &out_size, (const char const*)&in, NULL);
	check_response("ef10_nic_event_queue_disable", __FUNCTION__, rc,
		       MC_CMD_FINI_EVQ_OUT_LEN, out_size);
}


/*--------------------------------------------------------------------
 *
 * Event Management - and SW event posting
 *
 *--------------------------------------------------------------------*/


static void
_ef10_mcdi_cmd_driver_event(struct efhw_nic *nic, uint64_t data, uint32_t evq)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_DRIVER_EVENT_IN_LEN);
	EFHW_MCDI_SET_DWORD(in, DRIVER_EVENT_IN_EVQ, evq);
	EFHW_MCDI_SET_QWORD(in, DRIVER_EVENT_IN_DATA, data);

	rc = ef10_mcdi_rpc(nic, MC_CMD_DRIVER_EVENT, sizeof(in), 0, &out_size,
			   (const char*)&in, NULL);

	check_response("ef10_nic_sw_event", __FUNCTION__, rc, 
		       MC_CMD_DRIVER_EVENT_OUT_LEN, out_size);
}


static int
_ef10_mcdi_cmd_ptp_time_event_subscribe(struct efhw_nic *nic, uint32_t evq,
					unsigned* out_flags, const char* caller)
{
	int rc;
	size_t out_size;
	static const uint32_t rs =
	    (1 << MC_CMD_PTP_IN_TIME_EVENT_SUBSCRIBE_REPORT_SYNC_STATUS_LBN);
	int sync_flag = EFHW_VI_CLOCK_SYNC_STATUS;

	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PTP_IN_TIME_EVENT_SUBSCRIBE_LEN);

	EFHW_MCDI_SET_DWORD(in, PTP_IN_OP, MC_CMD_PTP_OP_TIME_EVENT_SUBSCRIBE);
	EFHW_MCDI_SET_DWORD(in, PTP_IN_PERIPH_ID, 0); 
	EFHW_MCDI_SET_DWORD(in, PTP_IN_TIME_EVENT_SUBSCRIBE_QUEUE, evq | rs);

	rc = ef10_mcdi_rpc(nic, MC_CMD_PTP, sizeof(in), 0, &out_size,
			   (const char*)&in, NULL);
	if (rc == -ERANGE) {
		sync_flag = 0;
		EFHW_MCDI_SET_DWORD(in, PTP_IN_TIME_EVENT_SUBSCRIBE_QUEUE, evq);
		rc = ef10_mcdi_rpc(nic, MC_CMD_PTP,sizeof(in), 0, &out_size,
				   (const char*)&in, NULL);
	}
	check_response(caller, __FUNCTION__, rc,
		       MC_CMD_PTP_OUT_TIME_EVENT_SUBSCRIBE_LEN, out_size);
	if( rc == 0 && out_flags != NULL) {
		*out_flags |= sync_flag;
	}
	return rc;
}

static int _ef10_mcdi_cmd_ptp_time_event_unsubscribe(struct efhw_nic *nic,
						     uint32_t evq,
						     const char* caller)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PTP_IN_TIME_EVENT_UNSUBSCRIBE_LEN);

	EFHW_MCDI_SET_DWORD(in, PTP_IN_OP,
			    MC_CMD_PTP_OP_TIME_EVENT_UNSUBSCRIBE);
	EFHW_MCDI_SET_DWORD(in, PTP_IN_PERIPH_ID, 0);
	EFHW_MCDI_SET_DWORD(in, PTP_IN_TIME_EVENT_UNSUBSCRIBE_CONTROL,
			    MC_CMD_PTP_IN_TIME_EVENT_UNSUBSCRIBE_SINGLE);
	EFHW_MCDI_SET_DWORD(in, PTP_IN_TIME_EVENT_UNSUBSCRIBE_QUEUE, evq);

	rc = ef10_mcdi_rpc(nic, MC_CMD_PTP, sizeof(in), 0, &out_size,
			   (const char*)&in, NULL);
	check_response(caller, __FUNCTION__, rc,
		       MC_CMD_PTP_OUT_TIME_EVENT_UNSUBSCRIBE_LEN, out_size);
	return rc;
}


/* This function will enable the given event queue with the requested
 * properties.  If enable_time_sync_events is set, then on success,
 * this function will also return rx_ts_correction_out as the
 * correction factor to be applied to every rx timestamp.
 */
static int
ef10_nic_event_queue_enable(struct efhw_nic *nic, uint evq, uint evq_size,
			    uint buf_base_id, dma_addr_t *dma_addrs,
			    uint n_pages, int interrupting, int enable_dos_p,
			    int wakeup_evq, int enable_time_sync_events,
			    int enable_cut_through, int *rx_ts_correction_out,
			    int* flags_out)
{
        int rc;
	rc = _ef10_mcdi_cmd_event_queue_enable(nic, evq, evq_size, dma_addrs, 
                                               n_pages, interrupting, 
                                               enable_dos_p, enable_cut_through,
                                               wakeup_evq);

	EFHW_TRACE("%s: enable evq %u size %u rc %d", __FUNCTION__, evq,
		   evq_size, rc);

	if( rc == 0 && enable_time_sync_events ) {
		rc = _ef10_nic_get_rx_timestamp_correction
			(nic, rx_ts_correction_out, __FUNCTION__);
		if( rc == 0 ) {
			rc = _ef10_mcdi_cmd_ptp_time_event_subscribe
				(nic, evq, flags_out, __FUNCTION__);
		}
		if( rc != 0 ) {
			_ef10_mcdi_cmd_event_queue_disable(nic, evq);
			/* Firmware returns EPERM if you do not have
			 * the licence to subscribe to time sync
			 * events.  We convert it to ENOKEY which in
			 * Onload means you are lacking the
			 * appropriate licence.
			 *
			 * Firmware returns ENOSYS in case it does not
			 * support timestamping.  We convert it to
			 * EOPNOTSUPP.
			 */
			if( rc == -ENOSYS )
				return -EOPNOTSUPP;
			if( rc == -EPERM )
				return -ENOKEY;
		}
	}
	return rc;
}

static void
ef10_nic_event_queue_disable(struct efhw_nic *nic, uint evq,
			     int time_sync_events_enabled)
{
	if( time_sync_events_enabled )
		_ef10_mcdi_cmd_ptp_time_event_unsubscribe
			(nic, evq, __FUNCTION__);
	_ef10_mcdi_cmd_event_queue_disable(nic, evq);		
}

static void
ef10_nic_wakeup_request(struct efhw_nic *nic, volatile void __iomem* io_page,
			int rptr)
{
	u32 rptr_lo, rptr_hi;
	__DWCHCK(ERF_DZ_EVQ_RPTR);
	__RANGECHCK(rptr, ERF_DZ_EVQ_RPTR_WIDTH);

	if( nic->flags & NIC_FLAG_BUG35388_WORKAROUND ) {
		/* Workaround for the lockup issue: bug35981,
		 * bug35887, bug35388, bug36064.
		 */

#define REV0_OP_RPTR_HI 0x800
#define REV0_OP_RPTR_LO 0x900

		rptr_hi = REV0_OP_RPTR_HI | ((rptr >> 8) & 0xff);
		rptr_lo = REV0_OP_RPTR_LO | (rptr & 0xff);
		writel(rptr_hi, (char *)io_page + ER_DZ_TX_DESC_UPD_REG + 8);
		wmb();
		writel(rptr_lo, (char *)io_page + ER_DZ_TX_DESC_UPD_REG + 8);
		mmiowb();
	}
	else {
		/* We know that revisions 0 and 1 both require the workaround.
		 */
		EFHW_ASSERT(nic->devtype.revision > 1);
		writel(rptr << ERF_DZ_EVQ_RPTR_LBN,
		       io_page + ER_DZ_EVQ_RPTR_REG);
		mmiowb();
	}
}


static void ef10_nic_sw_event(struct efhw_nic *nic, int data, int evq)
{
	uint64_t ev_data = data;

	ev_data &= ~EF10_EVENT_CODE_MASK;
	ev_data |= EF10_EVENT_CODE_SW;

	/* No MCDI event code is set for a sw event so it is implicitly 0 */

	_ef10_mcdi_cmd_driver_event(nic, ev_data, evq);
	EFHW_NOTICE("%s: evq[%d]->%x", __FUNCTION__, evq, data);
}

/*--------------------------------------------------------------------
 *
 * EF10 specific event callbacks
 *
 *--------------------------------------------------------------------*/

static int
ef10_handle_event(struct efhw_nic *nic, struct efhw_ev_handler *h,
		  efhw_event_t *ev)
{
	unsigned evq;

	if (EF10_EVENT_CODE(ev) == EF10_EVENT_CODE_CHAR) {
		switch (EF10_EVENT_DRIVER_SUBCODE(ev)) {
		case ESE_DZ_DRV_WAKE_UP_EV:
			evq = EF10_EVENT_WAKE_EVQ_ID(ev) - nic->vi_base;
			if (evq < nic->vi_lim && evq >= nic->vi_min) {
				efhw_handle_wakeup_event(nic, h, evq);
				return 1;
			}
			else {
				EFHW_NOTICE("%s: wakeup evq out of range: "
					    "%d %d %d %d",
					    __FUNCTION__, evq, nic->vi_base,
					    nic->vi_min, nic->vi_lim);
				return 0;
			}
		case ESE_DZ_DRV_TIMER_EV:
			evq = EF10_EVENT_WAKE_EVQ_ID(ev) - nic->vi_base;
			if (evq < nic->vi_lim && evq >= nic->vi_min) {
				efhw_handle_timeout_event(nic, h, evq);
				return 1;
			}
			else {
				EFHW_NOTICE("%s: timer evq out of range: "
					    "%d %d %d %d",
					    __FUNCTION__, evq, nic->vi_base,
					    nic->vi_min, nic->vi_lim);
				return 0;
			}
		default:
			EFHW_TRACE("UNKNOWN DRIVER EVENT: " EF10_EVENT_FMT,
				 EF10_EVENT_PRI_ARG(*ev));
			return 0;
		}
	}

	if (EF10_EVENT_CODE(ev) == EF10_EVENT_CODE_SW) {
		int code = EF10_EVENT_SW_SUBCODE(ev);
		switch (code) {
		case MCDI_EVENT_CODE_TX_FLUSH:
			evq = EF10_EVENT_TX_FLUSH_Q_ID(ev);
			EFHW_TRACE("%s: tx flush done %d", __FUNCTION__, evq);
			return efhw_handle_txdmaq_flushed(nic, h, evq);
		case MCDI_EVENT_CODE_RX_FLUSH:
			evq = EF10_EVENT_RX_FLUSH_Q_ID(ev);
			EFHW_TRACE("%s: rx flush done %d", __FUNCTION__, evq);
			return efhw_handle_rxdmaq_flushed(nic, h, evq, false);
		default:
			EFHW_NOTICE("%s: unexpected MCDI event code %d",
				    __FUNCTION__, code);
			return 0;
		}
	}

	EFHW_TRACE("%s: unknown event type=%x", __FUNCTION__,
		   (unsigned)EF10_EVENT_CODE(ev));

	return 0;
}


/*----------------------------------------------------------------------------
 *
 * multicast loopback - MCDI cmds
 *
 *---------------------------------------------------------------------------*/

static int
_ef10_mcdi_cmd_enable_multicast_loopback(struct efhw_nic *nic,
					 int instance, int enable)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_SET_PARSER_DISP_CONFIG_IN_LEN(1));
	EFHW_MCDI_SET_DWORD(in, SET_PARSER_DISP_CONFIG_IN_TYPE,
			MC_CMD_SET_PARSER_DISP_CONFIG_IN_TXQ_MCAST_UDP_DST_LOOKUP_EN);
	EFHW_MCDI_SET_DWORD(in, SET_PARSER_DISP_CONFIG_IN_ENTITY, instance);
	EFHW_MCDI_SET_DWORD(in, SET_PARSER_DISP_CONFIG_IN_VALUE, enable ? 1 : 0);

	rc = ef10_mcdi_rpc(nic, MC_CMD_SET_PARSER_DISP_CONFIG, sizeof(in), 0,
			   &out_size, (const char*)&in, NULL);
	check_response("ef10_enable_multicast_loopback", __FUNCTION__, rc,
		       MC_CMD_SET_PARSER_DISP_CONFIG_OUT_LEN, out_size);
	return rc;
}


static int
_ef10_mcdi_cmd_set_multicast_loopback_suppression
		(struct efhw_nic *nic,
		 int suppress_self_transmission,
		 uint32_t port_id )
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_SET_PARSER_DISP_CONFIG_IN_LEN(1));
	EFHW_MCDI_SET_DWORD(in, SET_PARSER_DISP_CONFIG_IN_TYPE,
			MC_CMD_SET_PARSER_DISP_CONFIG_IN_VADAPTOR_SUPPRESS_SELF_TX);
	EFHW_MCDI_SET_DWORD(in, SET_PARSER_DISP_CONFIG_IN_ENTITY, port_id);
	EFHW_MCDI_SET_DWORD(in, SET_PARSER_DISP_CONFIG_IN_VALUE,
			    suppress_self_transmission ? 1 : 0);
	rc = ef10_mcdi_rpc(nic, MC_CMD_SET_PARSER_DISP_CONFIG, sizeof(in), 0,
			   &out_size, (const char*)&in, NULL);
	check_response("ef10_enable_loopback_self_suppression", __FUNCTION__, rc,
		       MC_CMD_SET_PARSER_DISP_CONFIG_OUT_LEN, out_size);
	return rc;
}



/*----------------------------------------------------------------------------
 *
 * DMAQ low-level register interface - MCDI cmds
 *
 *---------------------------------------------------------------------------*/

static int
_ef10_mcdi_cmd_init_txq(struct efhw_nic *nic, dma_addr_t *dma_addrs,
			int n_dma_addrs, uint32_t port_id, uint32_t owner_id,
			int flag_timestamp, int crc_mode, int flag_tcp_udp_only,
			int flag_tcp_csum_dis, int flag_ip_csum_dis,
			int flag_buff_mode, int flag_pacer_bypass,
			uint32_t instance, uint32_t label,
			uint32_t target_evq, uint32_t numentries)
{
	int i, rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_INIT_TXQ_IN_LEN(n_dma_addrs));
	EFHW_MCDI_SET_DWORD(in, INIT_TXQ_IN_SIZE, numentries);
	EFHW_MCDI_SET_DWORD(in, INIT_TXQ_IN_TARGET_EVQ, target_evq);
	EFHW_MCDI_SET_DWORD(in, INIT_TXQ_IN_LABEL, label);
	EFHW_MCDI_SET_DWORD(in, INIT_TXQ_IN_INSTANCE, instance);
	EFHW_MCDI_SET_DWORD(in, INIT_TXQ_IN_OWNER_ID, owner_id);
	EFHW_MCDI_SET_DWORD(in, INIT_TXQ_IN_PORT_ID, port_id);

	EFHW_MCDI_POPULATE_DWORD_7(in, INIT_TXQ_IN_FLAGS,
		INIT_TXQ_IN_FLAG_BUFF_MODE, flag_buff_mode ? 1 : 0,
		INIT_TXQ_IN_FLAG_IP_CSUM_DIS, flag_ip_csum_dis ? 1 : 0,
		INIT_TXQ_IN_FLAG_TCP_CSUM_DIS, flag_tcp_csum_dis ? 1 : 0,
		INIT_TXQ_IN_FLAG_TCP_UDP_ONLY, flag_tcp_udp_only ? 1 : 0,
		INIT_TXQ_IN_CRC_MODE, crc_mode,
		INIT_TXQ_IN_FLAG_TIMESTAMP, flag_timestamp ? 1 : 0,
		INIT_TXQ_IN_FLAG_PACER_BYPASS, flag_pacer_bypass ? 1 : 0);
	
	for (i = 0; i < n_dma_addrs; ++i)
		EFHW_MCDI_SET_ARRAY_QWORD(in, INIT_TXQ_IN_DMA_ADDR, i, 
					  dma_addrs[i]);

	rc = ef10_mcdi_rpc(nic, MC_CMD_INIT_TXQ, sizeof(in), 0,
			   &out_size, (const char*)&in, NULL);
        check_response("ef10_dmaq_tx_q_init", __FUNCTION__, rc, 
                       MC_CMD_INIT_TXQ_OUT_LEN, out_size);
        return rc;
}


static int
_ef10_mcdi_cmd_init_rxq(struct efhw_nic *nic, dma_addr_t *dma_addrs,
			int n_dma_addrs, uint32_t port_id, uint32_t owner_id,
			int crc_mode, int flag_timestamp, int flag_hdr_split,
			int flag_buff_mode, int flag_rx_prefix,
			int flag_packed_stream, uint32_t instance,
			uint32_t label, uint32_t target_evq,
			uint32_t numentries)
{
	int i, rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_INIT_RXQ_IN_LEN(n_dma_addrs));

	/* Bug45759: This should really be checked in the fw or 2048
	 * should be exposed via mcdi headers. */
	if (flag_packed_stream && numentries > 2048) {
		EFHW_ERR("%s: ERROR: rxq_size=%d > 2048 in packed stream mode",
			 __FUNCTION__, numentries);
		return -EINVAL;
	}

	EFHW_MCDI_SET_DWORD(in, INIT_RXQ_IN_SIZE, numentries);
	EFHW_MCDI_SET_DWORD(in, INIT_RXQ_IN_TARGET_EVQ, target_evq);
	EFHW_MCDI_SET_DWORD(in, INIT_RXQ_IN_LABEL, label);
	EFHW_MCDI_SET_DWORD(in, INIT_RXQ_IN_INSTANCE, instance);
	EFHW_MCDI_SET_DWORD(in, INIT_RXQ_IN_OWNER_ID, owner_id);
	EFHW_MCDI_SET_DWORD(in, INIT_RXQ_IN_PORT_ID, port_id);

	EFHW_MCDI_POPULATE_DWORD_6(in, INIT_RXQ_IN_FLAGS,
		INIT_RXQ_IN_FLAG_BUFF_MODE, flag_buff_mode ? 1 : 0,
		INIT_RXQ_IN_FLAG_HDR_SPLIT, flag_hdr_split ? 1 : 0,
		INIT_RXQ_IN_FLAG_TIMESTAMP, flag_timestamp ? 1 : 0,
		INIT_RXQ_IN_FLAG_PREFIX, flag_rx_prefix ? 1 : 0,
		INIT_RXQ_IN_CRC_MODE, crc_mode,
		INIT_RXQ_IN_DMA_MODE, flag_packed_stream ?
			MC_CMD_INIT_RXQ_IN_PACKED_STREAM :
			MC_CMD_INIT_RXQ_IN_SINGLE_PACKET);

	for (i = 0; i < n_dma_addrs; ++i)
		EFHW_MCDI_SET_ARRAY_QWORD(in, INIT_RXQ_IN_DMA_ADDR, i, 
					  dma_addrs[i]);

	rc = ef10_mcdi_rpc(nic, MC_CMD_INIT_RXQ, sizeof(in), 0,
			   &out_size, (const char*)&in, NULL);
	check_response("ef10_dmaq_rx_q_init", __FUNCTION__, rc, 
		       MC_CMD_INIT_RXQ_OUT_LEN, out_size);
        return rc;
}


/*----------------------------------------------------------------------------
 *
 * DMAQ low-level register interface
 *
 *---------------------------------------------------------------------------*/
static uint32_t ef10_gen_port_id(struct efhw_nic *nic, uint stack_id)
{
	return EVB_PORT_ID_ASSIGNED | EVB_STACK_ID( stack_id );
}


static int
ef10_dmaq_tx_q_init(struct efhw_nic *nic, uint dmaq, uint evq_id, uint own_id,
		    uint tag, uint dmaq_size, uint buf_idx,
		    dma_addr_t *dma_addrs, int n_dma_addrs, uint stack_id, uint flags)
{
	int rc;
	uint32_t port_id = EVB_PORT_ID_ASSIGNED;

	int flag_timestamp = (flags & EFHW_VI_TX_TIMESTAMPS) != 0;
	int flag_tcp_udp_only = (flags & EFHW_VI_TX_TCPUDP_ONLY) != 0;
	int flag_tcp_csum_dis = (flags & EFHW_VI_TX_TCPUDP_CSUM_DIS) != 0;
	int flag_ip_csum_dis = (flags & EFHW_VI_TX_IP_CSUM_DIS) != 0;
	int flag_buff_mode = (flags & EFHW_VI_TX_PHYS_ADDR_EN) == 0;
	int flag_loopback = (flags & EFHW_VI_TX_LOOPBACK) != 0;

	/* No option for this yet, but we want it on as it cuts latency. */
	int flag_pacer_bypass = 1;

	if (nic->flags & NIC_FLAG_MCAST_LOOP_HW) {
		rc = _ef10_mcdi_cmd_enable_multicast_loopback
			(nic, dmaq, flag_loopback);
		if(rc != 0) {
			/* We are greaceful in case there is firmware
			 * with incomplete support */
			if (flag_loopback || rc != ENOSYS)
				return rc;
		}
	}

	if (flag_loopback) {
		port_id = ef10_gen_port_id(nic, stack_id);

		if (nic->flags & NIC_FLAG_MCAST_LOOP_HW) {
			rc = _ef10_mcdi_cmd_set_multicast_loopback_suppression
				(nic, 1, port_id);
			if( rc != 0 )
				return rc;
		}
	}

	rc = _ef10_mcdi_cmd_init_txq
		(nic, dma_addrs, n_dma_addrs, port_id,
		 REAL_OWNER_ID(own_id), flag_timestamp, QUEUE_CRC_MODE_NONE,
		 flag_tcp_udp_only, flag_tcp_csum_dis, flag_ip_csum_dis,
		 flag_buff_mode, flag_pacer_bypass,
		 dmaq, tag, evq_id, dmaq_size);
	if (rc == -EOPNOTSUPP)
		rc = -ENOKEY;

	return rc;
}


static int 
ef10_dmaq_rx_q_init(struct efhw_nic *nic, uint dmaq, uint evq_id, uint own_id,
		    uint tag, uint dmaq_size, uint buf_idx,
		    dma_addr_t *dma_addrs, int n_dma_addrs, uint stack_id, uint flags)
{
	int rc;
	uint32_t port_id = EVB_PORT_ID_ASSIGNED;

	int flag_rx_prefix = (flags & EFHW_VI_RX_PREFIX) != 0;
	int flag_timestamp = (flags & EFHW_VI_RX_TIMESTAMPS) != 0;
	int flag_hdr_split = (flags & EFHW_VI_RX_HDR_SPLIT) != 0;
	int flag_buff_mode = (flags & EFHW_VI_RX_PHYS_ADDR_EN) == 0;
	int flag_packed_stream = (flags & EFHW_VI_RX_PACKED_STREAM) != 0;

	if (flag_packed_stream && !(nic->flags & NIC_FLAG_PACKED_STREAM))
		return -EOPNOTSUPP;

	if (stack_id)
		port_id = ef10_gen_port_id(nic, stack_id);

	rc = _ef10_mcdi_cmd_init_rxq
		(nic, dma_addrs, n_dma_addrs, port_id,
		 REAL_OWNER_ID(own_id), QUEUE_CRC_MODE_NONE, flag_timestamp,
		 flag_hdr_split, flag_buff_mode, flag_rx_prefix,
		 flag_packed_stream, dmaq, tag, evq_id, dmaq_size);
	return rc == 0 ?
		flag_rx_prefix ? nic->rx_prefix_len : 0 :
		rc;
}

static void ef10_dmaq_tx_q_disable(struct efhw_nic *nic, uint dmaq)
{
}

static void ef10_dmaq_rx_q_disable(struct efhw_nic *nic, uint dmaq)
{
}


/*--------------------------------------------------------------------
 *
 * DMA Queues - MCDI cmds
 *
 *--------------------------------------------------------------------*/

static int
_ef10_mcdi_cmd_fini_rxq(struct efhw_nic *nic, uint32_t instance)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FINI_RXQ_IN_LEN);
	EFHW_MCDI_SET_DWORD(in, FINI_RXQ_IN_INSTANCE, instance);

	rc = ef10_mcdi_rpc(nic, MC_CMD_FINI_RXQ, sizeof(in), 0, &out_size,
			   (const char*)&in, NULL);
	check_response("ef10_nic_event_queue_disable", __FUNCTION__, rc, 
		       MC_CMD_FINI_RXQ_OUT_LEN, out_size);
	return rc;
}


static int
_ef10_mcdi_cmd_fini_txq(struct efhw_nic *nic, uint32_t instance)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FINI_TXQ_IN_LEN);
	EFHW_MCDI_SET_DWORD(in, FINI_TXQ_IN_INSTANCE, instance);

	rc = ef10_mcdi_rpc(nic, MC_CMD_FINI_TXQ, sizeof(in), 0, &out_size,
			   (const char*)&in, NULL);
	check_response("ef10_nic_event_queue_disable", __FUNCTION__, rc, 
		       MC_CMD_FINI_RXQ_OUT_LEN, out_size);
	return rc;
}


/*--------------------------------------------------------------------
 *
 * DMA Queues - mid level API
 *
 *--------------------------------------------------------------------*/


static int ef10_flush_tx_dma_channel(struct efhw_nic *nic, uint dmaq)
{
	return _ef10_mcdi_cmd_fini_txq(nic, dmaq);
}


static int ef10_flush_rx_dma_channel(struct efhw_nic *nic, uint dmaq)
{
	return _ef10_mcdi_cmd_fini_rxq(nic, dmaq);
}


/*--------------------------------------------------------------------
 *
 * Rate pacing - Low level interface
 *
 *--------------------------------------------------------------------*/

static int ef10_nic_pace(struct efhw_nic *nic, uint dmaq, int pace)
{
	/* TODO Should be able to implement priority queuing
	 * (EF_TX_QOS_CLASS) using TCM buckets.  See
	 * chip_test/src/tests/nic/eftests/tx_pacer.c
	 */
	if (pace != 0) {
		EFHW_ERR("%s: not yet implemented for EF10 NICs",
			 __FUNCTION__);
		return -EOPNOTSUPP;
	}
	return 0;
}


/*--------------------------------------------------------------------
 *
 * Buffer table - MCDI cmds
 *
 *--------------------------------------------------------------------*/

static int
_ef10_mcdi_cmd_buffer_table_alloc(struct efhw_nic *nic, int page_size, 
				  int owner_id, int *btb_index,
				  int *numentries, efhw_btb_handle *handle)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_ALLOC_BUFTBL_CHUNK_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_ALLOC_BUFTBL_CHUNK_OUT_LEN);

	EFHW_MCDI_SET_DWORD(in, ALLOC_BUFTBL_CHUNK_IN_OWNER, owner_id);
	EFHW_MCDI_SET_DWORD(in, ALLOC_BUFTBL_CHUNK_IN_PAGE_SIZE, page_size);

	rc = ef10_mcdi_rpc(nic, MC_CMD_ALLOC_BUFTBL_CHUNK,
			   sizeof(in), sizeof(out), &out_size,
			   (const char*)&in, (char*)&out);
	check_response("__ef10_nic_buffer_table_alloc", __FUNCTION__, rc, 
		       MC_CMD_ALLOC_BUFTBL_CHUNK_OUT_LEN, out_size);
	if ( rc != 0 )
		return rc;

	*btb_index = EFHW_MCDI_DWORD(out, ALLOC_BUFTBL_CHUNK_OUT_ID);
	*numentries = EFHW_MCDI_DWORD(out, ALLOC_BUFTBL_CHUNK_OUT_NUMENTRIES);
	*handle = EFHW_MCDI_DWORD(out, ALLOC_BUFTBL_CHUNK_OUT_HANDLE);
	return rc;
}


static void
_ef10_mcdi_cmd_buffer_table_free(struct efhw_nic *nic,
				 efhw_btb_handle handle)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FREE_BUFTBL_CHUNK_IN_LEN);
	EFHW_MCDI_SET_DWORD(in, FREE_BUFTBL_CHUNK_IN_HANDLE, handle);

	rc = ef10_mcdi_rpc(nic, MC_CMD_FREE_BUFTBL_CHUNK, sizeof(in), 0,
			   &out_size, (const char*)&in, NULL);
	check_response("ef10_nic_buffer_table_free", __FUNCTION__, rc, 
		       MC_CMD_FREE_BUFTBL_CHUNK_OUT_LEN, out_size);
}


static int
_ef10_mcdi_cmd_buffer_table_program(struct efhw_nic *nic, dma_addr_t *dma_addrs,
				    int n_entries, int first_entry,
				    efhw_btb_handle handle)
{

	/* chip_src uses eftest_func_dma_to_dma48_addr() to convert
	 * the dma addresses.  Do I need to do something similar?
	 */
	int i, rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, 
			      MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_LEN(n_entries));

	EFHW_MCDI_SET_DWORD(in, PROGRAM_BUFTBL_ENTRIES_IN_HANDLE, handle);
	EFHW_MCDI_SET_DWORD(in, PROGRAM_BUFTBL_ENTRIES_IN_FIRSTID, first_entry);
	EFHW_MCDI_SET_DWORD(in, PROGRAM_BUFTBL_ENTRIES_IN_NUMENTRIES, 
			    n_entries);

	if (n_entries > MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM) {
		EFHW_ERR("%s: n_entries (%d) cannot be greater than "
			 "MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM (%d)",
			 __FUNCTION__, n_entries,
			 MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM);
		return -EINVAL;
	}

	for (i = 0; i < n_entries; ++i)
		EFHW_MCDI_SET_ARRAY_QWORD(in, PROGRAM_BUFTBL_ENTRIES_IN_ENTRY,
					  i, dma_addrs[i]);

	rc = ef10_mcdi_rpc(nic, MC_CMD_PROGRAM_BUFTBL_ENTRIES, sizeof(in), 0,
			   &out_size, (const char*)&in, NULL);
	check_response("__ef10_nic_buffer_table_set", __FUNCTION__, rc, 
		       MC_CMD_PROGRAM_BUFTBL_ENTRIES_OUT_LEN, out_size);
	return rc;
}


/*--------------------------------------------------------------------
 *
 * Buffer table - API
 *
 *--------------------------------------------------------------------*/

static const int __ef10_nic_buffer_table_get_orders[] = {0,4,8,10};

static int __ef10_nic_buffer_table_alloc(struct efhw_nic *nic, int owner,
					 int order,
					 struct efhw_buffer_table_block *block)
{
	int numentries, rc, btb_index;

	rc = _ef10_mcdi_cmd_buffer_table_alloc
		(nic, EFHW_NIC_PAGE_SIZE << order, owner, &btb_index,
		 &numentries, &block->btb_hw.ef10.handle);
	if (rc != 0) {
		if( rc == -ENOSPC)
			rc = -ENOMEM;
		return rc;
	}
	if (numentries != 32) {
		EFHW_ERR("%s: _ef10_mcdi_cmd_buffer_table_alloc expected 32"
			 " but allocated %d entries", __FUNCTION__, numentries);
		return -EINVAL;
	}

	block->btb_vaddr = EF10_BUF_ID_ORDER_2_VADDR(btb_index, order);
	EFHW_DO_DEBUG(efhw_buffer_table_alloc_debug(block));
	return 0;
}


static int
ef10_nic_buffer_table_alloc(struct efhw_nic *nic, int owner, int order,
			    struct efhw_buffer_table_block **block_out)
{
	int rc;
	struct efhw_buffer_table_block *block;

	block = kmalloc(sizeof(*block), GFP_KERNEL);
	if (block == NULL)
		return -ENOMEM;

	memset(block, 0, sizeof(*block));

	rc = __ef10_nic_buffer_table_alloc(nic, REAL_OWNER_ID(owner), order,
					   block);
	if ( rc != 0 ) {
		kfree(block);
		return rc;
	}

	*block_out = block;
	return 0;
}


static int
ef10_nic_buffer_table_realloc(struct efhw_nic *nic, int owner, int order,
			      struct efhw_buffer_table_block *block)
{
	return __ef10_nic_buffer_table_alloc(nic, REAL_OWNER_ID(owner),
					     order, block);
}


static void
ef10_nic_buffer_table_free(struct efhw_nic *nic,
			   struct efhw_buffer_table_block *block)
{
	_ef10_mcdi_cmd_buffer_table_free(nic, block->btb_hw.ef10.handle);
	EFHW_DO_DEBUG(efhw_buffer_table_free_debug(block));
	kfree(block);
}


static int
__ef10_nic_buffer_table_set(struct efhw_nic *nic,
			    struct efhw_buffer_table_block *block,
			    int first_entry, int n_entries,
			    dma_addr_t *dma_addrs)
{
	int i, rc, batch;
	i = 0;
	while (i < n_entries) {
		batch = n_entries - i <
			        MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM ?
			n_entries - i :
			MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM;
		rc = _ef10_mcdi_cmd_buffer_table_program
			(nic, dma_addrs + i, batch, first_entry + i,
			 block->btb_hw.ef10.handle);
		if (rc != 0)
			/* XXX: unprogram entries already made.  Not
			 * bothering for now as all current callers do
			 * not handle error anyways. */
			return rc;
		i += batch;
	}
	return 0;
}


static void
ef10_nic_buffer_table_set(struct efhw_nic *nic,
			  struct efhw_buffer_table_block *block,
			  int first_entry, int n_entries,
			  dma_addr_t *dma_addrs)
{
	int rc;
	int buffer_id = EF10_BUF_VADDR_2_ID(block->btb_vaddr) + first_entry;
	rc = __ef10_nic_buffer_table_set(nic, block, buffer_id, n_entries,
					 dma_addrs);
	EFHW_DO_DEBUG(efhw_buffer_table_set_debug(block, first_entry,
						  n_entries));
}


static void
ef10_nic_buffer_table_clear(struct efhw_nic *nic,
			    struct efhw_buffer_table_block *block,
			    int first_entry, int n_entries)
{
	int rc;
	int buffer_id = EF10_BUF_VADDR_2_ID(block->btb_vaddr) +
							first_entry;
	dma_addr_t null_addrs[MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM];

	memset(null_addrs, 0, sizeof(null_addrs));
	rc = __ef10_nic_buffer_table_set(nic, block, buffer_id, n_entries,
					 null_addrs);
	EFHW_DO_DEBUG(efhw_buffer_table_clear_debug(block, first_entry,
						    n_entries));
}


/*--------------------------------------------------------------------
 *
 * PIO mgmt
 *
 *--------------------------------------------------------------------*/


static int
_ef10_mcdi_cmd_piobuf_alloc(struct efhw_nic *nic, unsigned *handle_out)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_ALLOC_PIOBUF_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_ALLOC_PIOBUF_OUT_LEN);

	rc = ef10_mcdi_rpc(nic, MC_CMD_ALLOC_PIOBUF,
			   sizeof(in), sizeof(out), &out_size,
			   (const char*)&in, (char*)&out);
	if ( rc != 0 )
		return rc;

	*handle_out = EFHW_MCDI_DWORD(out, ALLOC_PIOBUF_OUT_PIOBUF_HANDLE);
	return rc;
}


static int
_ef10_mcdi_cmd_piobuf_free(struct efhw_nic *nic, unsigned handle)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FREE_PIOBUF_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_FREE_PIOBUF_OUT_LEN);

	EFHW_MCDI_SET_DWORD(in, FREE_PIOBUF_IN_PIOBUF_HANDLE, handle);

	rc = ef10_mcdi_rpc(nic, MC_CMD_FREE_PIOBUF,
			   sizeof(in), sizeof(out), &out_size,
			   (const char*)&in, (char*)&out);
	return rc;
}


static int
_ef10_mcdi_cmd_piobuf_link(struct efhw_nic *nic, unsigned txq, unsigned handle)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_LINK_PIOBUF_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_LINK_PIOBUF_OUT_LEN);

	EFHW_MCDI_SET_DWORD(in, LINK_PIOBUF_IN_PIOBUF_HANDLE, handle);
	EFHW_MCDI_SET_DWORD(in, LINK_PIOBUF_IN_TXQ_INSTANCE, txq);

	rc = ef10_mcdi_rpc(nic, MC_CMD_LINK_PIOBUF,
			   sizeof(in), sizeof(out), &out_size,
			   (const char*)&in, (char*)&out);
	return rc;
}


static int
_ef10_mcdi_cmd_piobuf_unlink(struct efhw_nic *nic, unsigned txq)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_UNLINK_PIOBUF_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_UNLINK_PIOBUF_OUT_LEN);

	EFHW_MCDI_SET_DWORD(in, UNLINK_PIOBUF_IN_TXQ_INSTANCE, txq);

	rc = ef10_mcdi_rpc(nic, MC_CMD_UNLINK_PIOBUF,
			   sizeof(in), sizeof(out), &out_size,
			   (const char*)&in, (char*)&out);
	return rc;
}


int ef10_nic_piobuf_alloc(struct efhw_nic *nic, unsigned *handle_out)
{
	return _ef10_mcdi_cmd_piobuf_alloc(nic, handle_out);
}


int ef10_nic_piobuf_free(struct efhw_nic *nic, unsigned handle)
{
	return _ef10_mcdi_cmd_piobuf_free(nic, handle);
}


int ef10_nic_piobuf_link(struct efhw_nic *nic, unsigned txq, unsigned handle)
{
	return _ef10_mcdi_cmd_piobuf_link(nic, txq, handle);
}


int ef10_nic_piobuf_unlink(struct efhw_nic *nic, unsigned txq)
{
	return _ef10_mcdi_cmd_piobuf_unlink(nic, txq);
}


/*--------------------------------------------------------------------
 *
 * RSS
 *
 *--------------------------------------------------------------------*/


static int
_ef10_mcdi_cmd_rss_context_alloc(struct efhw_nic *nic, int num_qs, int shared,
				 int *handle_out)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_RSS_CONTEXT_ALLOC_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_RSS_CONTEXT_ALLOC_OUT_LEN);

	EFHW_MCDI_SET_DWORD(in, RSS_CONTEXT_ALLOC_IN_NUM_QUEUES, num_qs);
	EFHW_MCDI_SET_DWORD(in, RSS_CONTEXT_ALLOC_IN_TYPE,
		shared ? MC_CMD_RSS_CONTEXT_ALLOC_IN_TYPE_SHARED
		       : MC_CMD_RSS_CONTEXT_ALLOC_IN_TYPE_EXCLUSIVE);
	EFHW_MCDI_SET_DWORD(in, RSS_CONTEXT_ALLOC_IN_UPSTREAM_PORT_ID,
		EVB_PORT_ID_ASSIGNED);

	rc = ef10_mcdi_rpc(nic, MC_CMD_RSS_CONTEXT_ALLOC,
			   sizeof(in), sizeof(out), &out_size,
			   (const char*)&in, (char*)&out);

	if ( rc != 0 )
		return rc;

	*handle_out = EFHW_MCDI_DWORD(out,
		RSS_CONTEXT_ALLOC_OUT_RSS_CONTEXT_ID);
	return rc;
}


static int
_ef10_mcdi_cmd_rss_context_free(struct efhw_nic *nic, int handle)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_RSS_CONTEXT_FREE_IN_LEN);

	EFHW_MCDI_SET_DWORD(in, RSS_CONTEXT_FREE_IN_RSS_CONTEXT_ID, handle);

	rc = ef10_mcdi_rpc(nic, MC_CMD_RSS_CONTEXT_FREE,
			   sizeof(in), 0, &out_size,
			   (const char*)&in, NULL);

	return rc;
}


int _ef10_mcdi_cmd_rss_context_set_table(struct efhw_nic *nic, int handle,
					 const uint8_t *table)
{
	int rc;
	int i;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_RSS_CONTEXT_SET_TABLE_IN_LEN);

	EFHW_MCDI_SET_DWORD(in, RSS_CONTEXT_SET_TABLE_IN_RSS_CONTEXT_ID,
			    handle);

	for (i = 0; i < MC_CMD_RSS_CONTEXT_SET_TABLE_IN_INDIRECTION_TABLE_LEN;
	     i++)
		EFHW_MCDI_PTR(in,
			      RSS_CONTEXT_SET_TABLE_IN_INDIRECTION_TABLE)[i] =
			      table[i];

	rc = ef10_mcdi_rpc(nic, MC_CMD_RSS_CONTEXT_SET_TABLE,
			   sizeof(in), 0, &out_size,
			   (const char*)&in, NULL);

	return rc;
}


int _ef10_mcdi_cmd_rss_context_set_key(struct efhw_nic *nic, int handle,
				       const uint8_t *key)
{
	int rc;
	int i;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_RSS_CONTEXT_SET_KEY_IN_LEN);

	EFHW_MCDI_SET_DWORD(in, RSS_CONTEXT_SET_KEY_IN_RSS_CONTEXT_ID, handle);

	for (i = 0; i < MC_CMD_RSS_CONTEXT_SET_KEY_IN_TOEPLITZ_KEY_LEN; i++)
		EFHW_MCDI_PTR(in, RSS_CONTEXT_SET_KEY_IN_TOEPLITZ_KEY)[i] =
			      key[i];

	rc = ef10_mcdi_rpc(nic, MC_CMD_RSS_CONTEXT_SET_KEY,
			   sizeof(in), 0, &out_size,
			   (const char*)&in, NULL);

	return rc;
}


int ef10_nic_rss_context_alloc(struct efhw_nic *nic, int num_qs, int shared,
			       int *handle_out)
{
	return _ef10_mcdi_cmd_rss_context_alloc(nic, num_qs, shared,
						handle_out);
}


int ef10_nic_rss_context_free(struct efhw_nic *nic, int handle)
{
	return _ef10_mcdi_cmd_rss_context_free(nic, handle);
}


int ef10_nic_rss_context_set_table(struct efhw_nic *nic, int handle,
				   const uint8_t *table)
{
	return _ef10_mcdi_cmd_rss_context_set_table(nic, handle, table);
}


int ef10_nic_rss_context_set_key(struct efhw_nic *nic, int handle,
				 const uint8_t *key)
{
	return _ef10_mcdi_cmd_rss_context_set_key(nic, handle, key);
}


/*--------------------------------------------------------------------
 *
 * Port Sniff
 *
 *--------------------------------------------------------------------*/

static int
_ef10_mcdi_cmd_set_tx_port_sniff(struct efhw_nic *nic, int instance, int enable,
				 int rss_context)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_SET_TX_PORT_SNIFF_CONFIG_IN_LEN);

	EFHW_MCDI_SET_DWORD(in, SET_TX_PORT_SNIFF_CONFIG_IN_RX_CONTEXT,
			    rss_context);
	EFHW_MCDI_SET_DWORD(in, SET_TX_PORT_SNIFF_CONFIG_IN_RX_MODE,
		rss_context == -1 ?
		MC_CMD_SET_TX_PORT_SNIFF_CONFIG_IN_RX_MODE_SIMPLE :
		MC_CMD_SET_TX_PORT_SNIFF_CONFIG_IN_RX_MODE_RSS);
	EFHW_MCDI_SET_DWORD(in, SET_TX_PORT_SNIFF_CONFIG_IN_RX_QUEUE, instance);
	EFHW_MCDI_POPULATE_DWORD_1(in, SET_TX_PORT_SNIFF_CONFIG_IN_FLAGS,
		SET_TX_PORT_SNIFF_CONFIG_IN_ENABLE, enable ? 1 : 0);

	rc = ef10_mcdi_rpc(nic, MC_CMD_SET_TX_PORT_SNIFF_CONFIG,
			   sizeof(in), 0, &out_size,
			   (const char*)&in, NULL);
	return rc;
}


int ef10_nic_set_tx_port_sniff(struct efhw_nic *nic, int instance, int enable,
			       int rss_context)
{
	return _ef10_mcdi_cmd_set_tx_port_sniff(nic, instance, enable,
						rss_context);
}


static int
_ef10_mcdi_cmd_set_port_sniff(struct efhw_nic *nic, int instance, int enable,
			      int promiscuous, int rss_context)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_SET_PORT_SNIFF_CONFIG_IN_LEN);

	EFHW_MCDI_POPULATE_DWORD_2(in, SET_PORT_SNIFF_CONFIG_IN_FLAGS,
		SET_PORT_SNIFF_CONFIG_IN_ENABLE, enable ? 1 : 0,
		SET_PORT_SNIFF_CONFIG_IN_PROMISCUOUS, promiscuous ? 1 : 0);
	EFHW_MCDI_SET_DWORD(in, SET_PORT_SNIFF_CONFIG_IN_RX_QUEUE, instance);
	EFHW_MCDI_SET_DWORD(in, SET_PORT_SNIFF_CONFIG_IN_RX_MODE,
		rss_context == -1 ?
		MC_CMD_SET_PORT_SNIFF_CONFIG_IN_RX_MODE_SIMPLE :
		MC_CMD_SET_PORT_SNIFF_CONFIG_IN_RX_MODE_RSS);
	EFHW_MCDI_SET_DWORD(in, SET_PORT_SNIFF_CONFIG_IN_RX_CONTEXT,
		rss_context);

	rc = ef10_mcdi_rpc(nic, MC_CMD_SET_PORT_SNIFF_CONFIG,
			   sizeof(in), 0, &out_size,
			   (const char*)&in, NULL);
	return rc;
}


int ef10_nic_set_port_sniff(struct efhw_nic *nic, int instance, int enable,
                            int promiscuous, int rss_context)
{
	return _ef10_mcdi_cmd_set_port_sniff(nic, instance, enable,
					     promiscuous, rss_context);
}


/*--------------------------------------------------------------------
 *
 * Port Sniff
 *
 *--------------------------------------------------------------------*/

int ef10_get_rx_error_stats(struct efhw_nic *nic, int instance,
                            void *data, int data_len, int do_reset)
{
	int rc;
	size_t out_size;
	int flags = 0;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_RMON_STATS_RX_ERRORS_IN_LEN);

	if (data_len != DIV_ROUND_UP(MC_CMD_RMON_STATS_RX_ERRORS_OUT_LEN, 4))
		return -EINVAL;

	EFHW_MCDI_SET_DWORD(in, RMON_STATS_RX_ERRORS_IN_RX_QUEUE, instance);
	if (do_reset) {
		flags = 1 << MC_CMD_RMON_STATS_RX_ERRORS_IN_RST_LBN;
	}
	EFHW_MCDI_SET_DWORD(in, RMON_STATS_RX_ERRORS_IN_FLAGS, flags);

	rc = ef10_mcdi_rpc(nic, MC_CMD_RMON_STATS_RX_ERRORS, sizeof(in), 
			   data_len, &out_size, (const char*)&in, 
			   (char*)data);
	EFHW_ASSERT(data_len == out_size);

	return rc;
}


/*--------------------------------------------------------------------
 *
 * Abstraction Layer Hooks
 *
 *--------------------------------------------------------------------*/

struct efhw_func_ops ef10_char_functional_units = {
	ef10_nic_close_hardware,
	ef10_nic_init_hardware,
	ef10_nic_tweak_hardware,
	ef10_nic_event_queue_enable,
	ef10_nic_event_queue_disable,
	ef10_nic_wakeup_request,
	ef10_nic_sw_event,
	ef10_handle_event,
	ef10_dmaq_tx_q_init,
	ef10_dmaq_rx_q_init,
	ef10_dmaq_tx_q_disable,
	ef10_dmaq_rx_q_disable,
	ef10_flush_tx_dma_channel,
	ef10_flush_rx_dma_channel,
	ef10_nic_pace,
	__ef10_nic_buffer_table_get_orders,
	sizeof(__ef10_nic_buffer_table_get_orders) /
		sizeof(__ef10_nic_buffer_table_get_orders[0]),
	ef10_nic_buffer_table_alloc,
	ef10_nic_buffer_table_realloc,
	ef10_nic_buffer_table_free,
	ef10_nic_buffer_table_set,
	ef10_nic_buffer_table_clear,
	ef10_nic_set_port_sniff,
	ef10_nic_set_tx_port_sniff,
	ef10_nic_rss_context_alloc,
	ef10_nic_rss_context_free,
	ef10_nic_rss_context_set_table,
	ef10_nic_rss_context_set_key,
        ef10_nic_license_challenge,
	ef10_get_rx_error_stats,
};

#else /* #if EFX_DRIVERLINK_API_VERSION >= 9 */

int ef10_nic_piobuf_alloc(struct efhw_nic *nic, unsigned *handle_out)
{
	return -EINVAL;
}


int ef10_nic_piobuf_free(struct efhw_nic *nic, unsigned handle)
{
	return -EINVAL;
}


int ef10_nic_piobuf_link(struct efhw_nic *nic, unsigned txq, unsigned handle)
{
	return -EINVAL;
}


int ef10_nic_piobuf_unlink(struct efhw_nic *nic, unsigned txq)
{
	return -EINVAL;
}

struct efhw_func_ops ef10_char_functional_units;

#endif
