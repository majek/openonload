/*
** Copyright 2005-2018  Solarflare Communications Inc.
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

/**************************************************************************\
*//*! \file
**  \brief  TCPDirect types
*//*
\**************************************************************************/

#ifndef __ZF_TYPES_H__
#define __ZF_TYPES_H__

#ifndef __IN_ZF_TOP_H__
# error "Please include zf.h to use TCPDirect."
#endif


struct zf_stack;

/*! \brief Report structure providing timestamp and other packet information
**
** This is provided by zfut_pkt_get_reports() and zft_pkt_get_reports() to
** associate timestamps with packet data.
*/
struct zf_pkt_report {
  /** Hardware timestamp for packet transmission */
  struct timespec timestamp;
  /** Total count for the socket up to the start of this packet.
   ** For UDP, this is a count of datagrams.
   ** For TCP, this is a count of bytes.
   ** The counter will wrap when it reaches the end of its 32-bit range. */
  uint32_t start;
  /** Byte count for this packet */
  uint16_t bytes;
  /** Adapter clock has been set */
  #define ZF_PKT_REPORT_CLOCK_SET    0x0001
  /** Adapter clock is in sync */
  #define ZF_PKT_REPORT_IN_SYNC      0x0002
  /** No timestamp available */
  #define ZF_PKT_REPORT_NO_TIMESTAMP 0x0004
  /** Dropped reports before this */
  #define ZF_PKT_REPORT_DROPPED      0x0008
  /** Retransmitted TCP packet */
  #define ZF_PKT_REPORT_TCP_RETRANS  0x2000
  /** Initial TCP SYN packet */
  #define ZF_PKT_REPORT_TCP_SYN      0x4000
  /** Final TCP FIN packet */
  #define ZF_PKT_REPORT_TCP_FIN      0x8000
  /** Flags set for this packet */
  uint16_t flags;
};


#endif /* __ZF_TYPES_H__ */
/** @} */
