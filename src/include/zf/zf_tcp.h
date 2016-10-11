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
** \author  
**  \brief  ZF TCP API
**   \date  
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ZF_TCP_H__
#define __ZF_TCP_H__

#include <zf/zf_platform.h>
#include <zf/types.h>
#include <zf/attr.h>

#include <netinet/in.h>
#include <sys/uio.h>

struct zftl;
struct zft;
struct zft_alternative;
struct zft_alt_packet;
struct zft_msg;

/*
 * ------------------------------------------------------------------------
 * TCP Passive Open
 *
 * These functions do not block
 * ------------------------------------------------------------------------
 */

/*! \struct zftl
**
** \brief Opaque structure describing a TCP listening zocket 
*/
struct zftl {
};


/*! \brief Allocate TCP listening zocket
**
** \param st      Initialised zf_stack in which to created the listener
** \param laddr   Local address on which to listen
** \param attr    Attributes to apply to this zocket
** \param tl_out  On successful return filled with pointer to created TCP
**                listening zocket
**
** \return 0      Success
*/
LIBENTRY ZF_COLD int
zftl_listen(struct zf_stack* st, const struct sockaddr_in* laddr,
            const struct zf_attr* attr, struct zftl** tl_out);


/*! \brief Accept incoming TCP connect
**
** \param tl      The listener from which to accept the connection
** \param ts_out  On successful return filled with pointer to a TCP zocket
**
** \return 0       Success
** \return -EAGAIN No incoming connections available
*/
LIBENTRY ZF_COLD int zftl_accept(struct zftl* tl, struct zft** ts_out);


/*! \brief Returns a @p zf_waitable representing @p tl.
**
** \param tl      The #zftl to return as a #zf_waitable
**
** \return        The #zf_waitable
**
** This function is necessary to use TCP listening zockets with the zf_muxer. 
*/
LIBENTRY ZF_COLD struct zf_waitable* zftl_to_waitable(struct zftl* tl);


/*! \brief Release resources associated with a TCP listening zocket
**
** \param ts      A shutdown TCP listening zocket
**
** \return 0      Success
*/
LIBENTRY ZF_COLD int zftl_free(struct zftl* ts);


/*
 * ------------------------------------------------------------------------
 * TCP Active Open
 *
 * These functions do not block
 * ------------------------------------------------------------------------
 */

/*! \struct zft_handle
**
** \brief Opaque structure describing a TCP zocket that is passive and not 
** connected
*/
struct zft_handle;

/*! \struct zft
**
** \brief Opaque structure describing a TCP zocket that is connected
*/
struct zft {
};


/*! \brief Returns a #zf_waitable representing the given #zft.
**
** \param ts The #zft to return as a #zf_waitable
**
** \return The #zf_waitable
**
** This function is necessary to use with the zf_muxer.
*/
LIBENTRY struct zf_waitable*
zft_to_waitable(struct zft* ts);


/*! \brief Allocate active open TCP zocket.
**
** \param st             Initialised zf_stack
** \param attr           Attributes required for this TCP zocket
** \param handle_out     On successful return filled with pointer to a zocket
**                       handle.  This handle can be used to refer to the
**                       zocket before it is connected.
**
** \return 0      Success
**
** This function initialises the datastructures needed to make an outgoing
** TCP connection.
**
** The returned handle can be used to refer to the zocket before it is
** connected.
**
** The handle must be released either by explicit release with
** zft_handle_free(), or by conversion to a connected zocket via
** zft_connect().
**
** \see zft_bind() zft_connect() zft_handle_release()
*/
LIBENTRY ZF_COLD int
zft_alloc(struct zf_stack* st, const struct zf_attr* attr,
          struct zft_handle** handle_out);


/*! \brief Release a handle to a TCP zocket
**
** \param handle        Handle to be released
**
** This function releases resources associated with a zft_handle.
*/
LIBENTRY ZF_COLD int
zft_handle_free(struct zft_handle* handle);


/*! \brief Bind to a specific local address
** 
** \param handle TCP zocket handle
** \param laddr  Local address
** \param flags  TBD
**
** \return 0      Success
*/
LIBENTRY ZF_COLD int
zft_addr_bind(struct zft_handle* handle, const struct sockaddr_in* laddr,
              int flags);


/*! \brief Connect a TCP zocket
**
** \param handle    TCP zocket handle, to be replaced by the returned zocket
** \param raddr     Remote address to connect to
** \param ts_out    On successful return a pointer to a TCP zocket
**
** \return 0      Success
**
** This replaces the zocket handle with a TCP zocket.  On successful return
** the zocket handle has been released and is no longer valid.
**
** If a specific local address has not been set via zft_bind() then an
** appropriate one will be selected.
**
** This function does not block.  Functions that attempt to transfer data on
** the zocket between zft_connect() and establishment of the successful
** establishment of the underlying TCP connection will return error.
**
** \see zft_bind()
*/
LIBENTRY ZF_COLD int
zft_connect(struct zft_handle* handle, const struct sockaddr_in* raddr,
            struct zft** ts_out);


/*! \brief Shutdown outgoing TCP connection
** 
** \param ts      A connected TCP zocket
**
** \return 0      Success
**
** This function closes the TCP connection, preventing further data
** transmission.
*/
LIBENTRY ZF_COLD int
zft_shutdown_tx(struct zft* ts);


/*! \brief Release resources associated with a TCP zocket
**
** \param ts      A shutdown TCP zocket
**
** \return 0      Success
*/
LIBENTRY ZF_COLD int
zft_free(struct zft* ts);


/*! \brief Find out the TCP state of a TCP zocket.
**
** \param ts      A TCP zocket
**
** \return TCP_* state
*/
LIBENTRY int
zft_state(struct zft* ts);


/**
 * \brief Find out the error type happened on the TCP zocket.
 *
 * \param ts      A TCP zocket
 *
 * \retval errno value, similar to SO_ERROR value for sockets
 */
LIBENTRY int
zft_error(struct zft* ts);


/*! \brief Retrieve the local address of the zocket
**
** \param ts        TCP zocket
** \param laddr_out Return the local address of the zocket
** \param raddr_out Return the remote address of the zocket
**
** This function returns local and/or remote IP address and TCP port of the
** given connection.  Caller may pass NULL pointer for local or remote
** address if he is interested in the other address only.
*/
LIBENTRY void
zft_getname(struct zft* ts, struct sockaddr_in* laddr_out,
            struct sockaddr_in* raddr_out);


/*
 * ------------------------------------------------------------------------
 * TCP RX
 * ------------------------------------------------------------------------
 */


/*! \brief Retrieve the timestamp of a received packet
**
** \param ts        TCP zocket
** \param pktbuf    iovec for received packet
** \param timespec  Location to write the retrieved timestamp
**
** \return 0      Success
**
** This function retrieves the timestamp of a received packet and writes it
** to the location specified by @p timespec.
*/
LIBENTRY ZF_HOT int
zft_pkt_get_timestamp(struct zft* ts, const struct iovec* pktbuf,
                      const struct timespec* timespec);


/*! \brief TBD Description of a TCP zerocopy RX request */
struct zft_msg {
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
** \param ts        TCP zocket
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
** \return 0      Success
**
** This function reads information on received buffers that is scatter gather
** array over pkt buffers (for standard MTU this is guaranteed to be single
** iovec).
**
** Buffers are 'locked' until zft_zc_recv_done() is performed.
*/
LIBENTRY ZF_HOT int
zft_zc_recv(struct zft *ts,
            struct zft_msg* msg,
            int flags);


/*! \brief Concludes pending zc_recv operation as done.
**
** \param ts        TCP zocket
** \param msg       Message
**
** Must be called after each successfull zft_zc_recv operation.
** This releasese resources and enables subseqent call to zft_zc_recv()
** or zft_recv().
*/
LIBENTRY ZF_HOT void
zft_zc_recv_done(struct zft* ts, struct zft_msg* msg);


/*! \brief Copy-based receive 
** 
** \param ts        TCP zocket
** \param iov_out   An array with vectors pointing to packet payloads.
** \param iovcnt_in_out In: the maximum number of buffers requested,
**                  out: the actual number of buffers filled.\n**
**                  _flags_ out: FLUSHING, FLUSHED.
** \param flags     None yet.
**
** \return 0      Success
**
** This function is not yet implemented
*/
LIBENTRY ZF_HOT int
zft_recv(struct zft* ts,
          struct iovec* iov_out,
          int* iovcnt_in_out,
          int flags);


/*
 * ------------------------------------------------------------------------
 * TCP TX
 *
 * These functions do not block
 * ------------------------------------------------------------------------
 */


/*! \brief Send data
**
** \param ts  The TCP zocket to send on
** \param iov The iovec of data to send
** \param iov_cnt The length of iov
** \param flags 
**
** Sends the supplied data.
**
** Provided buffers may be re-used on return from this function.
*/
LIBENTRY ZF_HOT int
zft_send(struct zft *ts, const struct iovec* iov, int iov_cnt, int flags);


/*
 * ------------------------------------------------------------------------
 * TCP Alternative Sends
 * ------------------------------------------------------------------------
 */

 
/*! \brief Acquire IDs for a set of alternative queues
**
** \param ts           TCP zocket
** \param attr         Requested attributes for the alternatives
** \param n_alts       Size of supplied zft_alternatives array
** \param alts_in_out  Array of zft_alternatives of size n_alts.  On return
**                     this is filled with identifiers of a set of alternative
**                     queues for use by this TCP zocket.
**
** \return >=0 Number of alternatives available
**
** The alternatives allocated are only able to be used with the TCP zocket
** provided to this function.
**
** \see zft_release_alternatives()
*/
LIBENTRY int
zft_alloc_alternatives(struct zft* ts, const struct zf_attr* attr,
                       int n_alts, struct zft_alternative* alts_in_out);


/*! \brief Release IDs for a set of alternative queues
**
** \param ts           TCP zocket
** \param alts         Array of zft_alternatives of size n_alts
** \param n_alts       Size of supplied zft_alternatives array
**
** \return 0           Success
**
** Releases allocated alternative queues.  If any packets are queued on the
** specified queues they will be flushed without being sent.
**
** \see zft_alloc_alternatives()
*/
LIBENTRY int
zft_release_alternatives(struct zft* ts, struct zft_alternative* alts,
                         int n_alts);


/*! \brief Queue a packet for sending
**
** \param ts          TCP zocket
** \param alt         ID of the queue to push this packet to.  Must have been
**                    allocated via zft_init_alternatives()
** \param iov
** \param iov_cnt
** \param flags
** \param handle      On successful return a handle to be used if this packet
**                    requires later edits
**
** \return >0         Number of bytes queued
**
** This function behaves similarly to zft_send(), but doesn't actually put
** the data on the wire.
**
** FIXME
** allow queueing zero data as placeholders for later edit to allow packet
** insertion?
**
** \see zft_init_alternatives()
** \see zft_send()
*/
LIBENTRY int
zft_queue_alternative(struct zft* ts, struct zft_alternative* alt,
                      const struct iovec* iov, int iov_cnt, int flags,
                      struct zft_alt_packet* handle);


/*! \brief Select an alternative and send those packets
**
** \param ts          TCP zocket
** \param alt         Selected alternative
**
** \return 0          Success
**
** On success packets queued on the selected alternative are sent.  The other
** alternatives owned by this zocket are flushed without being sent.
**
** This invalidates the handles for all queued packets on this zocket's
** alternatives.
*/
LIBENTRY int
zft_send_alternative(struct zft* ts, struct zft_alternative* alt);


/*! \brief Cancel an alternative
**
** \param ts          TCP zocket
** \param alt         Selected alternative
**
** \return 0          Success
**
** Drops packets queued on this alternative without sending.
**
** This invalidates the handles for all queued packets on this alternative.
*/
LIBENTRY int
zft_cancel_alternative(struct zft* ts, struct zft_alternative* alt);


/*! \brief Edit a packet queued on an alternative.
**
** \param ts            TCP zocket
** \param alt           ID of the alternative to perform the edit on
** \param alt_new       ID of the alternative to queue the edited packets on or
**                      NULL to re-use the same alternative
** \param iov
** \param iov_cnt
** \param flags
** \param handle_in_out On entry the handle of the packet to be edited.
**                      On successful return a new handle to the packet.
**
** \return 0          Success
**
** Replaces the packet data for the packet referenced by the supplied handle.
** Zero length data is equivalent to removing the packet from the queue.
**
** Due to hardware restrictions this operation requires re-queuing all packets
** queued on this alternative.  This means that a delay will be incurred
** between the edit operation and the data being able to be sent onto the
** wire as the new packets are transferred to the NIC.
**
** To avoid the additional delay of having to wait for the old packets to
** be canceled before requeing the edited packets a different alternative
** can be used to queue them.  This can be done if a replacement alternative
** is provided via the alt_new parameter.
**
** This invalidates the old handle for the replaced packet.
**
** FIXME
** consider how to represent packet handle - particularly does it convey a
** queue or is it scoped to a queue.  Restrictions may reduce clutter
** in this horribly large set of args.  It's implicit here that it is not
** scoped to a queue - if so then all handles for packets queued on this
** alternative would need updating.
*/
LIBENTRY int
zft_edit_alternative(struct zft* ts, struct zft_alternative* alt,
                     struct zft_alternative* alt_new,
                     const struct iovec* iov, int iov_cnt, int flags,
                     struct zft_alt_packet* handle_in_out);


#endif /* __ZF_TCP_H__ */
