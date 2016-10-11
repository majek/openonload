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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  mj
**  \brief  ZF UDP API
**   \date  2015/10/20
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ZF_UDP_RX_H__
#define __ZF_UDP_RX_H__

#include <zf/zf_platform.h>
#include <zf/types.h>
#include <zf/attr.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <assert.h>

/*! \struct zfur
**
** \brief Opaque structure describing a UDP receive zocket
*/
struct zfur {
  /** TBD */
  int release_n;
};

/*
 * ------------------------------------------------------------------------
 * UDP receive
 * ------------------------------------------------------------------------
 */

/*! \brief Creates UDP receive zocket
**
** \param us_out  Pointer to receive new UDP receive zocket's address.
** \param st      Initialised zf_stack in which to create the zocket
** \param attr    Attributes to apply to this zocket
**
** \return 0 on success, or a negative error code.
**
** Associates UDP receive zocket with semi-wild or full hardware filter.
** Creates software filter and initialzes receive queue.
** The zocket becomes ready to receive packets after this call.
*/
LIBENTRY ZF_COLD int
zfur_alloc(struct zfur** us_out, struct zf_stack* st,
           const struct zf_attr* attr);


/*! \brief Release UDP receive zocket previously created with zfur_alloc() 
**
** \param us The UDP zocket to release
**
** \return 0 on success, or a negative error code.
**
*/
LIBENTRY ZF_COLD int
zfur_free(struct zfur* us);

/*! \brief Associates UDP receive zocket with semi-wild or full hardware filter.
** 
** \param us    The zocket to bind
** \param laddr Local address. Cannot be NULL.
** \param raddr Remote address. Can be NULL to set semi-wild filter.
** \param flags Flags
**
** \return 0 on success, or a negative error code.
**
*/
LIBENTRY ZF_COLD int
zfur_addr_bind(struct zfur* us, const struct sockaddr_in* laddr,
               const struct sockaddr_in* raddr, int flags);

/*! \brief Unbind UDP receive zocket from address
**
** \param us    The zocket to unbind
** \param laddr Local address. Cannot be NULL.
** \param raddr Remote address. Can be NULL to set semi-wild filter.
** \param flags Flags
**
** \return 0 on success, or a negative error code.
**
** If wildcard filter this will unbind from some or all addresses
** e.g. with laddr == raddr == NULL, it will remove all filters
*/
LIBENTRY ZF_COLD int
zfur_addr_unbind(struct zfur* us, const struct sockaddr_in* laddr,
                 const struct sockaddr_in* raddr, int flags);


/*! \brief A zero copy UDP receive request */
struct zfur_msg {
  /** reserved */
  int reserved[4];
  /** out: outstanding packets/pkt buffers in the queue after this read */
  int pkts_left;
  /** out: some flags: e.g. FLUSHING, FLUSHED */
  int flags;
  /** in: size of iovec, out: actual pkt buffer count */
  int iovcnt;
  /** in: base of iovec array, out: filled with iovecs pointing to the payload
      of the received packets */
  struct iovec iov[0];
};


/*! \brief Zero copy read of single message
**
** \param us        UDP zocket
** \param msg       Message to read, within which:\n
**                  _iov_ is an array with vectors pointing to packet
**                  payloads.\n
**                  _iov.iov_cnt_ carrying ZF_IOVEC_CONTINUE flag indicates
**                  that the next buffer belongs to the same packet.\n
**                  _iovcnt_ in: the maximum number of buffers requested,
**                  out: the actual number of buffers filled.\n
**                  _flags_ out: FLUSHING, FLUSHED.
** \param flags     None yet.
**
** \return 0 on success, or a negative error code.
**
** Reads information on received buffers that is scatter gather array
** over pkt buffers (for standard MTU this is guaranteed to be single iovec).
**
** Buffers are 'locked' until zfur_zc_recv_done() is performed.
*/
LIBENTRY ZF_HOT int
zfur_zc_recv(struct zfur *us,
             struct zfur_msg* msg,
             int flags);


/*! \brief Concludes pending zc_recv operation as done.
**
** \param us        UDP zocket
** \param msg       Message.
**
** Must be called after each successful zfur_zc_recv() operation.
** This releases resources and enables subseqent call to zfur_zc_recv()
** or zfur_recv().
*/
ZF_HOT static inline void
zfur_zc_recv_done(struct zfur* us, struct zfur_msg* msg)
  { assert(us->release_n); us->release_n = msg->iovcnt; }



/*! \brief Retrieves remote address from the header of a received
** packet.
**
** \param us        UDP zocket
** \param msg       Message.
** \param iphdr     Location to receive IP header.
** \param udphdr    Location to receive UDP header.
** \param pktind    TBD
**
** This is needed for zockets that can receive from many remote address,
** i.e. those with wild filters.
*/
LIBENTRY ZF_HOT int
zfur_pkt_get_header(struct zfur* us, const struct zfur_msg* msg,
                    const struct iphdr**, const struct udphdr**, int pktind);

					
/*! \brief Retrieve the timestamp of a received packet
**
** \param us        TCP zocket
** \param msg       Received packet
** \param ts        Location to write the retrieved timestamp
**
** \return 0 on success, or a negative error code.
**
** This function retrieves the timestamp of a received packet and writes it
** to the location specified by @p timespec.
**
** This function is not yet implemented
*/
LIBENTRY ZF_HOT int
zfur_pkt_get_timestamp(struct zfur* us, const struct zfur_msg* msg,
                       const struct timespec* ts);


/*! \brief Copy-based receive 
** 
** \param us        UDP zocket
** \param iov_out   An array with vectors pointing to packet payloads.
** \param iovcnt_in_out In: the maximum number of buffers requested,
**                  out: the actual number of buffers filled.\n**
**                  _flags_ out: FLUSHING, FLUSHED.
** \param flags     None yet.
**
** \return 0 on success, or a negative error code.
**
** This function is not yet implemented
*/
LIBENTRY ZF_HOT int
zfur_recv(struct zfur* us,
          struct iovec* iov_out,
          int* iovcnt_in_out,
          int flags);


/*! \brief Returns a #zf_waitable representing the given #zfur.
**
** \param us The #zfur to return as a #zf_waitable
**
** \return The #zf_waitable
**
** This is necessary for use with the zf_muxer.
*/
LIBENTRY struct zf_waitable*
zfur_to_waitable(struct zfur* us);


/*
 * ------------------------------------------------------------------------
 * UDP transmit
 * ------------------------------------------------------------------------
 */


/*! \struct zfut
**
** \brief Opaque structure describing a UDP transmit zocket
**
** Single destination address per zocket.
*/
struct zfut {
};


/*! \brief Alloc UDP transmit zocket, only supports a single destination address
**
** \param us_out  On success contains pointer to newly created UDP transmit
**                zocket
** \param st      Stack in which to create zocket
** \param laddr   Local address, or if NULL get IP addr from stack's interface
** \param raddr   Remote address
** \param flags   No flags yet
** \param attr    Attributes to apply to the zocket. Can be NULL to use stack 
**                attributes.
**
** \return 0 on success, or a negative error code.
**
** Once zocket is created neither laddr nor raddr can be changed.
*/
LIBENTRY ZF_COLD int
zfut_alloc(struct zfut** us_out,
           struct zf_stack* st,
           const struct sockaddr_in* laddr,
           const struct sockaddr_in* raddr,
           int flags,
           const struct zf_attr* attr);

/*! \brief Free UDP transmit zocket
**
** \param us UDP transmit zocket to free
**
** \return 0 on success, or a negative error code.
**
*/
LIBENTRY ZF_COLD int
zfut_free(struct zfut* us);


/**
 * \brief Get the maximum segment size which can be transmitted
 *
 * Find the maximum buflen parameter which can be passed to
 * zfut_send_single().
 */
LIBENTRY int
zfut_get_mss(struct zfut *us);


/*! \brief Flags for zfut_send() */
#define ZFUT_FLAG_DONT_FRAGMENT IP_DF /* 0x2000*/


/*! \brief Copy-based send of single non-fragmented UDP packet
**
** \param us      The UDP zocket to send on
** \param buf     A buffer of the data to send
** \param buflen  The length of the buffer, in bytes
**
** \return        Payload bytes sent (i.e. buflen) on success, or a negative
**                error code.
**
** The function uses PIO when possible (i.e. for small datagrams), and
** always sets the DontFragment bit in the IP header.
**
** \see zfut_get_mss() zfut_send()
*/
LIBENTRY ZF_HOT int
zfut_send_single(struct zfut *us, const void* buf, size_t buflen);


/**
** \brief Copy-based send of single UDP packet (possibly fragmented)
**
** \param us      The UDP zocket to send on
** \param iov     The iovec of data to send
** \param iov_cnt The length of iov
** \param flags   Flags
**
** \return        Payload bytes sent (i.e. buflen) on success, or a negative
**                error code.
**
** For a small packet in a plain buffer with the ZFUT_FLAG_DONT_FRAGMENT flag
** set, this function just calls zfut_send_single().  Otherwise it handles
** IO vector and fragments a UDP packet into multiple IP fragments as
** needed.
**
** If ZFUT_FLAG_DONT_FRAGMENT flag is specified, then the datagram should
** fit to the MSS value (see zfut_get_mss() above), and the DontFragment bit in
** the IP header will be set.
**
** \see zfut_send_single()
*/
LIBENTRY ZF_HOT int
zfut_send(struct zfut *us, const struct iovec* iov, int iov_cnt, int flags);


/*! \brief Returns a #zf_waitable representing the given #zfut.
**
** \param us The #zfut to return as a #zf_waitable
**
** \return The #zf_waitable
**
** This function is necessary to use UDP transmit zockets with the zf_muxer. 
*/
LIBENTRY struct zf_waitable*
zfut_to_waitable(struct zfut* us);


#endif /* __ZF_UDP_RX_H__ */
