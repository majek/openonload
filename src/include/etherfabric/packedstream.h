/*
** Copyright 2005-2015  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

/****************************************************************************
 * Copyright 2014-2015: Solarflare Communications Inc,
 *                      7505 Irvine Center Drive, Suite 100
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
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

/**************************************************************************\
*//*! \file
** \author    Solarflare Communications, Inc.
** \brief     Packed streams for EtherFabric Virtual Interface HAL.
** \date      2015/02/16
** \copyright Copyright &copy; 2015 Solarflare Communications, Inc. All
**            rights reserved. Solarflare, OpenOnload and EnterpriseOnload
**            are trademarks of Solarflare Communications, Inc.
*//*
\**************************************************************************/

#ifndef __EFAB_PACKEDSTREAM_H__
#define __EFAB_PACKEDSTREAM_H__

#include <etherfabric/base.h>

#ifdef __cplusplus
extern "C" {
#endif


/*! \brief Per-packet meta-data. */
typedef struct {
  /** Offset of next packet from start of this struct. */
  uint16_t  ps_next_offset;
  /** Offset of packet payload from start of this struct. */
  uint8_t   ps_pkt_start_offset;
  /** EF_VI_PS_FLAG_* flags. */
  uint8_t   ps_flags;
  /** Number of bytes of packet payload stored. */
  uint16_t  ps_cap_len;
  /** Length of the frame on the wire. */
  uint16_t  ps_orig_len;
  /** Hardware timestamp (seconds). */
  uint32_t  ps_ts_sec;
  /** Hardware timestamp (nanoseconds). */
  uint32_t  ps_ts_nsec;
} ef_packed_stream_packet;


/*! \brief Set if the adapter clock has ever been set (in sync with system). */
#define EF_VI_PS_FLAG_CLOCK_SET        0x1
/*! \brief Set if the adapter clock is in sync with the external clock (PTP). */
#define EF_VI_PS_FLAG_CLOCK_IN_SYNC    0x2
/*! \brief Set if a bad Frame Check Sequence has occurred. */
#define EF_VI_PS_FLAG_BAD_FCS          0x4
/*! \brief Set if a bad IP Checksum has occurred. */
#define EF_VI_PS_FLAG_BAD_IP_CSUM      0x8


/*! \brief Packed-stream mode parameters.
**
** The application should query these parameters using
** ef_vi_packed_stream_get_params() to determine buffer size etc.
*/
typedef struct {
  /** Size of each packed-stream buffer. */
  int  psp_buffer_size;

  /** Alignment requirement for start of packed-stream buffers. */
  int  psp_buffer_align;

  /** Offset from the start of a packed-stream buffer to where the
   * first packet will be delivered.
   */
  int  psp_start_offset;

  /** The maximum number of packed-stream buffers that the adapter can
   * deliver packets into without software consuming any completion
   * events. The application can post more buffers, but they will
   * only be used as events are consumed.
   */
  int  psp_max_usable_buffers;
} ef_packed_stream_params;


/*! \brief Get the parameters for packed-stream mode.
**
** \param vi      The virtual interface to query.
** \param psp_out Pointer to an ef_packed_stream_params, that is updated on
**                return with the parameters for packed-stream mode.
**
** \return 0 on success, or a negative error code:\n
**         -EINVAL if the virtual interface is not in packed-stream mode.
**
** Get the parameters for packed-stream mode.
*/
extern int ef_vi_packed_stream_get_params(ef_vi* vi,
                                          ef_packed_stream_params* psp_out);


/*! \brief Unbundle an event of type EF_EVENT_TYPE_RX_PACKED_STREAM
**
** \param vi          The virtual interface that has raised the event.
** \param ev          The event, of type EF_EVENT_TYPE_RX_PACKED_STREAM.
** \param pkt_iter    Pointer to an ef_packed_stream_packet*, that is
**                    updated on return with the value for the next call to
**                    this function. See below for more details.
** \param n_pkts_out  Pointer to an int, that is updated on return with the
**                    number of packets unpacked.
** \param n_bytes_out Pointer to an int, that is updated on return with the
**                    number of bytes unpacked.
**
** \return 0 on success, or a negative error code.
**
** Unbundle an event of type EF_EVENT_TYPE_RX_PACKED_STREAM.
**
** This function should be called once for each
** EF_EVENT_TYPE_RX_PACKED_STREAM event received.
**
** If EF_EVENT_RX_PS_NEXT_BUFFER(*ev) is true, *pkt_iter should be
** initialized to the value returned by ef_packed_stream_packet_first().
**
** When EF_EVENT_RX_PS_NEXT_BUFFER(*ev) is not true, *pkt_iter should
** contain the value left by the previous call. After each call *pkt_iter
** points at the location where the next packet will be delivered.
**
** The return value is 0, or a negative error code. If the error code is
** -ENOMSG, -ENODATA or -EL2NSYNC then there was a problem with the
** hardware timestamp: see ef_vi_receive_get_timestamp_with_sync_flags()
** for details.
*/
extern int ef_vi_packed_stream_unbundle(ef_vi* vi, const ef_event* ev,
                                        ef_packed_stream_packet** pkt_iter,
                                        int* n_pkts_out,
                                        int* n_bytes_out);


/*! \brief Get the metadata for the first packet in a packed stream
**
** \param start_of_buffer  Pointer to the start of the buffer.
** \param psp_start_offset Offset within the buffer to the start of the
**                         packet.
**
** \return Pointer to packet metadata
**
** Get the metadata for the first packet in a packed stream.
**
** The packet is identified by its storage location, as an offset within a
** buffer.
*/
static inline ef_packed_stream_packet*
ef_packed_stream_packet_first(void* start_of_buffer, int psp_start_offset)
{
  return (void*) ((uint8_t*) (start_of_buffer) + psp_start_offset);
}


/*! \brief Get the metadata for the next packet in a packed stream
**
** \param ps_pkt Pointer to a packed stream packet.
**
** \return Pointer to the next packed stream packet.
**
** Get the metadata for the next packet in a packed stream.
**
** The packet is identified by giving the current packet in the iteration.
*/
static inline ef_packed_stream_packet*
ef_packed_stream_packet_next(ef_packed_stream_packet* ps_pkt)
{
  return (void*) ((char*) ps_pkt + ps_pkt->ps_next_offset);
}


/*! \brief Return a pointer to the packet payload
**
** \param ps_pkt Pointer to a packed stream packet.
**
** \return Pointer to the packet payload.
**
** Return a pointer to the packet payload.
*/
static inline void*
ef_packed_stream_packet_payload(ef_packed_stream_packet* ps_pkt)
{
  return (char*) ps_pkt + ps_pkt->ps_pkt_start_offset;
}


#ifdef __cplusplus
}
#endif

#endif  /* __EFAB_PACKEDSTREAM_H__ */
