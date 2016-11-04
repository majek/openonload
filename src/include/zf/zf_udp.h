/*
** This file is part of Solarflare TCPDirect.
**
** Copyright 2015-2016  Solarflare Communications Inc.
**                       7505 Irvine Center Drive, Irvine, CA 92618, USA
**
** Proprietary and confidential.  All rights reserved.
**
** Please see TCPD-LICENSE.txt included in this distribution for terms of use.
*/

/**************************************************************************\
*//*! \file
**  \brief  TCPDirect UDP API
*//*
\**************************************************************************/

#ifndef __ZF_UDP_RX_H__
#define __ZF_UDP_RX_H__

#ifndef __IN_ZF_TOP_H__
# error "Please include zf.h to use TCPDirect."
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <assert.h>


/*! \struct zfur
**
** \brief Opaque structure describing a UDP-receive zocket.
*/
struct zfur {
};

/*
 * ------------------------------------------------------------------------
 * UDP receive
 * ------------------------------------------------------------------------
 */

/*! \brief Creates UDP-receive zocket.
**
** \param us_out  Pointer to receive new UDP-receive zocket's address.
** \param st      Initialized #zf_stack in which to create the zocket.
** \param attr    Attributes to apply to this zocket. Note that not all
**                attributes are relevant; only those which apply to objects
**                of type "zf_socket" are applicable here. Refer to the
**                attribute documentation in \ref attributes for details.
**
** \return 0         Success.
** \return -ENOBUFS  No zockets of this type available.
**
** Associates UDP-receive zocket with semi-wild or full hardware filter.
** Creates software filter and initializes receive queue.
** The zocket becomes ready to receive packets after this call.
*/
ZF_LIBENTRY ZF_COLD int
zfur_alloc(struct zfur** us_out, struct zf_stack* st,
           const struct zf_attr* attr);


/*! \brief Release UDP-receive zocket previously created with zfur_alloc().
**
** \param us The UDP zocket to release.
**
** \return 0 on success.  Negative values are reserved for future use as error
** codes, but are not returned at present.
**
*/
ZF_LIBENTRY ZF_COLD int
zfur_free(struct zfur* us);

/*! \brief Configures UDP-receive zocket to receive on a specified address.
**
** \param us    The zocket to bind
** \param laddr Local address. Cannot be NULL or INADDR_ANY, but the port may
**              be zero, in which case an ephemeral port is allocated.
** \param laddrlen Length of the structure pointed to by laddr.
** \param raddr Remote address. If NULL, traffic will be accepted from all
**              remote addresses.
** \param raddrlen Length of the structure pointed to by raddr.
** \param flags Flags.  Must be zero.
**
** \return 0            Success.
** \return -EADDRINUSE  Address already in use.
** \return -EAFNOSUPPORT laddr and/or raddr are not AF_INET addresses
** \return -EBUSY       Out of hardware resources.
** \return -EINVAL      Invalid address length supplied.
** \return -EFAULT      Invalid address supplied.
** \return -ENOMEM      Out of memory.
**
** The port number in @p laddr is updated if it was set to 0 by the caller.
**
** If the specified local address is multicast then this has the effect of
** joining the multicast group as well as setting the filter.  The group
** membership will persist until either the address is unbound (see
** zfur_addr_unbind()), or the zocket is closed.
*/
ZF_LIBENTRY ZF_COLD int
zfur_addr_bind(struct zfur* us, struct sockaddr* laddr,
               socklen_t laddrlen, const struct sockaddr* raddr,
               socklen_t raddrlen, int flags);

/*! \brief Unbind UDP-receive zocket from address.
**
** \param us    The zocket to unbind.
** \param laddr Local address. Can be NULL to match any local address.
** \param laddrlen Length of the structure pointed to by laddr.
** \param raddr Remote address. Can be NULL to match any remote address.
** \param raddrlen Length of the structure pointed to by raddr.
** \param flags Flags.  Must be zero.
**
** \return 0            Success.
** \return -EINVAL      The zocket is not bound to the specified address.
**
** The addresses specified must match those used in zfur_addr_bind().
*/
ZF_LIBENTRY ZF_COLD int
zfur_addr_unbind(struct zfur* us, const struct sockaddr* laddr,
                 socklen_t laddrlen, const struct sockaddr* raddr,
                 socklen_t raddrlen, int flags);


/*! \brief UDP zero-copy RX message structure.
**
** This structure is passed to zfur_zc_recv(), which will populate it with
** pointers to received packets.
*/
struct zfur_msg {
  /** Reserved. */
  int reserved[4];
  /** Out: Number of outstanding datagrams in the queue after this read. */
  int dgrams_left;
  /** Reserved. */
  int flags;
  /** In: Length of #iov array expressed as a count of iovecs; out: number of
      entries of #iov populated with pointers to packets. */
  int iovcnt;
  /** In: base of iovec array; out: filled with iovecs pointing to the payload
      of the received packets. */
  struct iovec iov[ZF_FLEXIBLE_ARRAY_COUNT];
};


/*! \brief Zero-copy read of single datagram.
**
** \param us        UDP zocket.
** \param msg       Message structure.
** \param flags     Must be zero.
**
** This function completes the supplied @p msg structure with details
** of a received UDP datagram.
**
** The function may not fill all the supplied iovecs in @p msg even in
** the case where further data is available, but you can discover if
** there is more data available using the dgrams_left field in
** zfur_msg after making this call.
**
** TCPDirect does not yet support fragmented datagrams, but in the
** future such datagrams will be represented in the @p msg iovec as a
** scatter-gather array of packet buffers.  If the iovec is not long
** enough it may return a partial datagram.
**
** Buffers are 'locked' until zfur_zc_recv_done() is performed.  The caller
** must not modify the contents of @p msg until after it has been passed to
** zfur_zc_recv_done().
*/
ZF_LIBENTRY ZF_HOT void
zfur_zc_recv(struct zfur *us,
             struct zfur_msg* msg,
             int flags);


/*! \brief Concludes pending zero-copy receive operation as done.
**
** \param us        UDP zocket.
** \param msg       Message.
**
** Must be called after each successful zfur_zc_recv() operation that returns
** at least one packet.  It must not be called otherwise (in particular, when
** zfur_zc_recv() returned no packets).  The function releases resources and
** enables subseqent calls to zfur_zc_recv().  @p msg must be passed unmodified
** from the call to zfur_zc_recv().
*/
ZF_LIBENTRY ZF_HOT void
zfur_zc_recv_done(struct zfur* us, struct zfur_msg* msg);



/*! \brief Retrieves remote address from the header of a received
** packet.
**
** \param us        UDP zocket.
** \param msg       Message.
** \param iphdr     Location to receive IP header.
** \param udphdr    Location to receive UDP header.
** \param pktind    Index of packet within @p msg->iov.
**
** This is useful for zockets that can receive from many remote addresses,
** i.e. those for which zfur_addr_bind() was called with `raddr == NULL`.
*/
ZF_LIBENTRY ZF_HOT int
zfur_pkt_get_header(struct zfur* us, const struct zfur_msg* msg,
                    const struct iphdr** iphdr, const struct udphdr** udphdr,
                    int pktind);


/*! \brief Returns a #zf_waitable representing the given #zfur.
**
** \param us The #zfur to return as a #zf_waitable
**
** \return The #zf_waitable
**
** This is necessary for use with the multiplexer.
*/
ZF_LIBENTRY struct zf_waitable*
zfur_to_waitable(struct zfur* us);


/*
 * ------------------------------------------------------------------------
 * UDP transmit
 * ------------------------------------------------------------------------
 */


/*! \struct zfut
**
** \brief Opaque structure describing a UDP-transmit zocket.
**
** A UDP-transmit zocket encapsulates the state required to send UDP datagrams.
** Each such zocket supports only a single destination address.
*/
struct zfut {
};


/*! \brief Allocate a UDP-transmit zocket.
**
** \param us_out  On success contains pointer to newly created UDP transmit
**                zocket
** \param st      Stack in which to create zocket
** \param laddr   Local address.  If INADDR_ANY is specified, the local address
**                will be selected according to the route to @p raddr, but the
**                port must be non-zero.
** \param laddrlen Length of the structure pointed to by laddr.
** \param raddr   Remote address.
** \param raddrlen Length of the structure pointed to by raddr.
** \param flags   Must be zero.
** \param attr    Attributes to apply to the zocket. Note that not all
**                attributes are relevant; only those which apply to objects
**                of type "zf_socket" are applicable here. Refer to the
**                attribute documentation in \ref attributes for details.
**
** \return 0               Success.
** \return -EFAULT         Invalid pointer.
** \return -EHOSTUNREACH   No route to remote host.
** \return -EINVAL         Invalid local or remote address, or address lengths.
** \return -ENOBUFS        No zockets of this type available.
**
** \note Once the zocket is created, neither the local address nor the remote
** address can be changed.
*/
ZF_LIBENTRY ZF_COLD int
zfut_alloc(struct zfut** us_out,
           struct zf_stack* st,
           const struct sockaddr* laddr,
           socklen_t laddrlen,
           const struct sockaddr* raddr,
           socklen_t raddrlen,
           int flags,
           const struct zf_attr* attr);

/*! \brief Free UDP-transmit zocket.
**
** \param us UDP-transmit zocket to free.
**
** \return 0 on success.  Negative values are reserved for future use as error
** codes, but are not returned at present.
**
*/
ZF_LIBENTRY ZF_COLD int
zfut_free(struct zfut* us);


/**
 * \brief Get the maximum segment size which can be transmitted.
 *
 * \return Maximum buflen parameter which can be passed to zfut_send_single().
 *         This value is constant for a given zocket.
 */
ZF_LIBENTRY int
zfut_get_mss(struct zfut *us);


/*! \brief Flags for zfut_send() */
#define ZFUT_FLAG_DONT_FRAGMENT IP_DF /* 0x2000*/


/*! \brief Copy-based send of single non-fragmented UDP packet.
**
** \param us      The UDP zocket to send on.
** \param buf     A buffer of the data to send.
** \param buflen  The length of the buffer, in bytes.
**
** \return  Payload bytes sent (i.e. @p buflen) on success.
** \return -EAGAIN         Hardware queue full.  Call zf_reactor_perform()
**                         until it returns non-zero and try again.
** \return -ENOBUFS        Out of packet buffers.
**
** The function uses PIO when possible (i.e. for small datagrams), and
** always sets the DontFragment bit in the IP header.  @p buflen must be no
** larger than the value returned by zfut_get_mss().
**
** \see zfut_get_mss() zfut_send()
*/
ZF_LIBENTRY ZF_HOT int
zfut_send_single(struct zfut *us, const void* buf, size_t buflen);


/**
** \brief Copy-based send of single UDP packet (possibly fragmented).
**
** \param us      The UDP zocket to send on.
** \param iov     The iovec of data to send.
** \param iov_cnt The length of iov.
** \param flags   Flags.
**
** \return Payload bytes sent (i.e. @p buflen) on success.
** \return -EAGAIN         Hardware queue full.  Call zf_reactor_perform()
**                         until it returns non-zero and try again.
** \return -EMSGSIZE       Message too large.
** \return -ENOBUFS        Out of packet buffers.
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
ZF_LIBENTRY ZF_HOT int
zfut_send(struct zfut *us, const struct iovec* iov, int iov_cnt, int flags);


/*! \brief Returns a #zf_waitable representing the given #zfut.
**
** \param us The #zfut to return as a #zf_waitable.
**
** \return The #zf_waitable.
**
** This function is necessary to use UDP-transmit zockets with the multiplexer.
*/
ZF_LIBENTRY struct zf_waitable*
zfut_to_waitable(struct zfut* us);


/*! \brief Return protocol header size for this zocket.
**
** \param us      The UDP-TX zocket to query the header size for.
**
** \return        Protocol header size in bytes.
**
** This function returns the total size of all protocol headers in
** bytes. An outgoing packet's size will be exactly the sum of this
** value and the number of payload data bytes it contains.
**
** This function cannot fail.
*/
ZF_LIBENTRY unsigned
zfut_get_header_size(struct zfut *us);


#endif /* __ZF_UDP_RX_H__ */
/** @} */
