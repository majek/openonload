/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
**  \brief  TCPDirect TCP API
*//*
\**************************************************************************/

#ifndef __ZF_TCP_H__
#define __ZF_TCP_H__

#ifndef __IN_ZF_TOP_H__
# error "Please include zf.h to use TCPDirect."
#endif

#include <netinet/in.h>
#include <sys/uio.h>


struct zftl;
struct zft;
struct zft_msg;
struct timespec;
struct zf_pkt_report;

/*
 * ------------------------------------------------------------------------
 * TCP Passive Open
 *
 * These functions do not block
 * ------------------------------------------------------------------------
 */

/*! \struct zftl
**
** \brief Opaque structure describing a TCP listening zocket.
*/
struct zftl {
};


/*! \brief Allocate TCP listening zocket.
**
** \param st      Initialized @p zf_stack in which to created the listener.
** \param laddr   Local address on which to listen.  Must be non-null, and
**                must be a single local address (not INADDR_ANY).
** \param laddrlen The size in bytes of the structure pointed to by laddr
** \param attr    Attributes to apply to this zocket. Note that not all
**                attributes are relevant; only those which apply to objects
**                of type "zf_socket" are applicable here. Refer to the
**                attribute documentation in \ref attributes for details.
** \param tl_out  On successful return filled with pointer to created TCP
**                listening zocket.
**
** \return 0               Success.
** \return -EFAULT         Invalid laddr pointer.
** \return -EADDRINUSE     Local address already in use.
** \return -EADDRNOTAVAIL  @p laddr is not a local address.
** \return -EAFNOSUPPORT   @p laddr is not an AF_INET address.
** \return -EINVAL         Zocket is already listening, or invalid addr length.
** \return -ENOBUFS        No zockets of this type available.
** \return -ENOMEM         Out of memory.
** \return -EOPNOTSUPP     @p laddr is INADDR_ANY.
*/
ZF_LIBENTRY ZF_COLD int
zftl_listen(struct zf_stack* st, const struct sockaddr* laddr,
            socklen_t laddrlen, const struct zf_attr* attr,
            struct zftl** tl_out);


/*! \brief Accept incoming TCP connection.
**
** \param tl      The listening zocket from which to accept the connection.
** \param ts_out  On successful return filled with pointer to a TCP zocket for
**                the new connection.
**
** \return 0       Success.
** \return -EAGAIN No incoming connections available.
*/
ZF_LIBENTRY ZF_COLD int zftl_accept(struct zftl* tl, struct zft** ts_out);


/*! \brief Returns a @p zf_waitable representing @p tl.
**
** \param tl      The #zftl to return as a #zf_waitable
**
** \return        The #zf_waitable
**
** This function is necessary to use TCP listening zockets with the
** multiplexer.
*/
ZF_LIBENTRY ZF_COLD struct zf_waitable* zftl_to_waitable(struct zftl* tl);


/**
 * \brief Retrieve the local address of the zocket.
 *
 * \param ts         TCP zocket.
 * \param laddr_out  Set on return to the local address of the zocket.

 * \param laddrlen   On entry, the size in bytes of the structure
 * pointed to by laddr_out.  Set on return to be the size in bytes of
 * the result.
 *
 * This function returns the local IP address and TCP port of the
 * listening zocket.  If the supplied structure is too small the
 * result will be truncated and laddrlen updated to a length greater
 * than that supplied.
 */
ZF_LIBENTRY void
zftl_getname(struct zftl* ts, struct sockaddr* laddr_out, socklen_t* laddrlen);


/*! \brief Release resources associated with a TCP listening zocket.
**
** \param ts      A TCP listening zocket.
**
** This call shuts down the listening zocket, closing any connections waiting
** on the zocket that have not yet been accepted.  The application must not
** use @p ts after this call.
**
** \note The listening zocket is not removed until all accepted zockets have
** also been freed. If any connections to the listening zocket have been
** accepted, but the resulting zocket has not been freed by calling
** zft_free(), the listening zocket remains. It will not accept any new
** connections, and is shown in the output from \ref zf_stackdump. Attempting
** to create an additional listening zocket on the same port results in an
** error.
**
** \return 0      Success.
*/
ZF_LIBENTRY ZF_COLD int zftl_free(struct zftl* ts);


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
** connected.
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
** This function is necessary to use TCP zockets with the multiplexer.
*/
ZF_LIBENTRY struct zf_waitable*
zft_to_waitable(struct zft* ts);


/*! \brief Allocate active-open TCP zocket.
**
** \param st             Initialized #zf_stack.
** \param attr           Attributes required for this TCP zocket. Note that
**                       not all attributes are relevant; only those which
**                       apply to objects of type "zf_socket" are applicable
**                       here. Refer to the \ref attributes documentation for
**                       details.
** \param handle_out     On successful return filled with pointer to a zocket
**                       handle.  This handle can be used to refer to the
**                       zocket before it is connected.
**
** \return 0         Success.
** \return -ENOBUFS  No zockets of this type available.
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
** \see zft_addr_bind() zft_connect() zft_handle_free()
*/
ZF_LIBENTRY ZF_COLD int
zft_alloc(struct zf_stack* st, const struct zf_attr* attr,
          struct zft_handle** handle_out);


/*! \brief Release a handle to a TCP zocket.
**
** \param handle        Handle to be released.
**
** This function releases resources associated with a zft_handle.
**
** \return 0         Success.
*/
ZF_LIBENTRY ZF_COLD int
zft_handle_free(struct zft_handle* handle);

/*! \brief Retrieve the local address to which a #zft_handle is bound.
**
** \param ts        TCP zocket handle
** \param laddr_out Return the local address of the zocket
** \param laddrlen  On entry, the size in bytes of the structure
** pointed to by laddr_out.  Set on return to be the size in bytes of
** the result.
**
** This function returns the local IP address and TCP port of the
** given listener.  The behavior is undefined if the zocket is not bound.
**
** If the supplied structure is too small the result will be truncated
** and laddrlen updated to a length greater than that supplied.
*/
ZF_LIBENTRY void
zft_handle_getname(struct zft_handle* ts, struct sockaddr* laddr_out,
                   socklen_t* laddrlen);

/*! \brief Bind to a specific local address.
**
** \param handle TCP zocket handle.
** \param laddr  Local address.
** \param laddrlen Length of structure pointed to by laddr
** \param flags  Reserved.  Must be zero.
**
** \return 0               Success.
** \return -EADDRINUSE     Local address already in use.
** \return -EADDRNOTAVAIL  @p laddr is not a local address.
** \return -EAFNOSUPPORT   @p laddr is not an AF_INET address.
** \return -EFAULT         Invalid pointer.
** \return -EINVAL         Zocket is already bound, invalid @p flags, or
**                         invalid laddrlen.
** \return -ENOMEM         Out of memory.
*/
ZF_LIBENTRY ZF_COLD int
zft_addr_bind(struct zft_handle* handle, const struct sockaddr* laddr,
              socklen_t laddrlen, int flags);


/*! \brief Connect a TCP zocket.
**
** \param handle    TCP zocket handle, to be replaced by the returned zocket.
** \param raddr     Remote address to connect to.
** \param raddrlen  Length of structure pointed to by raddr.
** \param ts_out    On successful return, a pointer to a TCP zocket.
**
** This replaces the zocket handle with a TCP zocket.  On successful return
** the zocket handle has been released and is no longer valid.
**
** If a specific local address has not been set via zft_addr_bind()
** then an appropriate one will be selected.
**
** This function does not block.  Functions that attempt to transfer data on
** the zocket between zft_connect() and the successful establishment of the
** underlying TCP connection will return an error.  Furthermore, failure of the
** remote host to accept the connection will not be reported by this function,
** but instead by any attempts to read from the zocket (or by zft_error()).  As
** such, after calling zft_connect(), either
**
**  - read calls that fail with `-ENOTCONN` should be repeated after calling
**    zf_reactor_perform(), or
**  - the zocket should be polled for readiness using zf_muxer_wait().
**
** This is analogous to the non-blocking connection model for POSIX sockets.
**
** \return 0               Success.
** \return -EAFNOSUPPORT   raddr is not an AF_INET address
** \return -EADDRINUSE     Address already in use.
** \return -EBUSY          Out of hardware resources.
** \return -EFAULT         Invalid pointer.
** \return -EHOSTUNREACH   No route to remote host.
** \return -ENOMEM         Out of memory.
** \return -EINVAL         Zocket in unexpected TCP state, or no raddr supplied
**
** \see zft_addr_bind()
*/
ZF_LIBENTRY ZF_COLD int
zft_connect(struct zft_handle* handle, const struct sockaddr* raddr,
            socklen_t raddrlen, struct zft** ts_out);


/*! \brief Shut down outgoing TCP connection.
**
** \param ts      A connected TCP zocket.
**
** This function closes the TCP connection, preventing further data
** transmission except for already-queued data.  This function does
** not prevent the connection from receiving more data.
**
** \return 0 on success, or a negative error code.  Error codes returned are
**         similar to zft_send() ones:
** \return -ENOTCONN  Inappropriate TCP state: not connected or already shut
**                    down.
** \return -EAGAIN    Not enough space (either bytes or buffers) in the send
**                    queue.
** \return -ENOMEM    Not enough packet buffers available.
** \return -EBUSY     Delegated send in progress
*/
ZF_LIBENTRY ZF_COLD int
zft_shutdown_tx(struct zft* ts);


/*! \brief Release resources associated with a TCP zocket
**
** \param ts      TCP zocket.
**
** This call shuts down the zocket if necessary.  The application must not
** use @p ts after this call.
**
** \return 0 on success.  Negative values are reserved for future use as error
** codes, but are not returned at present.
*/
ZF_LIBENTRY ZF_COLD int
zft_free(struct zft* ts);


/*! \brief Return the TCP state of a TCP zocket.
**
** \param ts      TCP zocket.
**
** \return Standard `TCP_*` state constant (e.g. `TCP_ESTABLISHED`).
*/
ZF_LIBENTRY int
zft_state(struct zft* ts);


/*! \brief Find out the error type happened on the TCP zocket.
 *
 * \param ts      TCP zocket.
 *
 * \retval errno value, similar to SO_ERROR value for sockets.
 *
 * \retval Error values are designed to be similar to Linux SO_ERROR:
 * \retval ECONNREFUSED
 *   The connection attempt was refused by server.
 * \retval ECONNRESET
 *   The connection was reset by the peer after it was established.
 * \retval ETIMEDOUT
 *   The connection was timed out, probably because of network failure.
 * \retval EPIPE
 *   The connection was closed gracefully by the peer (i.e. we've received
 *   all the data they've sent to us), but the peer refused to receive the
 *   data we've tried to send.
 */
ZF_LIBENTRY int
zft_error(struct zft* ts);


/*! \brief Retrieve the local address of the zocket.
**
** \param ts        TCP zocket.
** \param laddr_out Return the local address of the zocket.
** \param laddrlen  The length of the structure pointed to by laddr_out
** \param raddr_out Return the remote address of the zocket.
** \param raddrlen  The length of the structure pointed to by raddr_out
**
** This function returns local and/or remote IP address and TCP port of the
** given connection.  Caller may pass NULL pointer for local or remote
** address if he is interested in the other address only.
**
** If the supplied address structures are too small the result will be
** truncated and addrlen updated to a length greater than that supplied.
*/
ZF_LIBENTRY void
zft_getname(struct zft* ts, struct sockaddr* laddr_out, socklen_t* laddrlen,
            struct sockaddr* raddr_out, socklen_t* raddrlen);


/*
 * ------------------------------------------------------------------------
 * TCP RX
 * ------------------------------------------------------------------------
 */


/*! \brief TCP zero-copy RX message structure.
**
** This structure is passed to zft_zc_recv(), which will populate it and a
** referenced iovec array with pointers to received packets.
*/
struct zft_msg {
  /** Reserved. */
  int reserved[4];
  /** Out: Number of outstanding packets in the queue after this read. */
  int pkts_left;
  /** Reserved. */
  int flags;
  /** In: Length of #iov array expressed as a count of iovecs.\n
      Out: number of entries of #iov populated with pointers to packets. */
  int iovcnt;
  /** In: A separate iovec array, available for writing, with @p iovcnt
      entries, must immediately follow this structure. This structure and
      the iovec array are typically wrapped by a structure. For an example,
      see the \ref zftcppingpong application.\n
      Out: iovec array is filled with iovecs pointing to the payload of
      the received packets. */
  struct iovec iov[ZF_FLEXIBLE_ARRAY_COUNT];
};


/*! \brief Zero-copy read of available packets.
**
** \param ts        TCP zocket.
** \param msg       Message structure.
** \param flags     Must be either: zero or one of zf_zc_flags values.
**
** This function completes the supplied @p msg structure and its referenced
** iovec array with details of received packet buffers.
**
** In case of EOF a zero-length buffer is appended at the end of data stream,
** and to identify the reason of stream termination check the result of
** zft_zc_recv_done() or of zft_zc_recv_done_some().
**
** The function will only fill fewer iovecs in @p msg than are provided in the
** case where no further data is available.
**
** Buffers are 'locked' until zft_zc_recv_done() or zft_zc_recv_done_some() is
** performed.  The caller must not modify the contents of @p msg until after it
** has been passed to zft_zc_recv_done() or to zft_zc_recv_done_some().
**
** The api supports looking into partially received frames.
** See \ref using_overlapped_receive.
*/
ZF_LIBENTRY ZF_HOT void
zft_zc_recv(struct zft *ts,
            struct zft_msg* msg,
            int flags);


/*! \brief Concludes pending zc_recv operation as done.
**
** \param ts        TCP zocket
** \param msg       Message
**
** \return >= 1   Connection still receiving.
** \return    0   EOF.
** \return -ECONNREFUSED  Connection refused.  This is possible as
**                        zft_connect() is non-blocking.
** \return -ECONNRESET    Connection reset by peer.
** \return -EPIPE         Peer closed connection gracefully, but refused to
**                        receive some data sent on this zocket.
** \return -ETIMEDOUT     Connection timed out.
**
** This function (or zft_zc_recv_done_some()) must be called after each
** successful zft_zc_recv() operation that returned at least one packet.  It
** must not be called otherwise (in particular, when zft_zc_recv() returned no
** packets).  The function releases resources and enables subseqent calls to
** zft_zc_recv() or zft_recv().  @p msg must be passed unmodified from the call
** to zft_zc_recv().
*/
ZF_LIBENTRY ZF_HOT int
zft_zc_recv_done(struct zft* ts, struct zft_msg* msg);


/*! \brief Concludes pending zc_recv operation as done acknowledging
**         all or some of the data to have been read.
**
** \param ts        TCP zocket.
** \param msg       Message.
** \param len       Total number of bytes read by the client.
**
** \return As for zft_zc_recv_done().
**
** Can be called after each successful zft_zc_recv() operation as an
** alternative to zft_zc_recv_done() or in cases where not all payload have
** been consumed.  The restictions on when it may be called are the same as for
** zft_zc_recv_done().  The function releases resources and enables subseqent
** calls to zft_zc_recv() or zft_recv().  zft_zc_recv() or zft_recv() functions
** will return data indicated as non-read when they are called next time.
** @p msg must be passed unmodified from the call to zft_zc_recv().
** @p len must not be greater than total payload returned by zft_zc_recv().
*/
ZF_LIBENTRY ZF_HOT int
zft_zc_recv_done_some(struct zft* ts, struct zft_msg* msg, size_t len);


/*! \brief Copy-based receive.
**
** \param ts        TCP zocket
** \param iov       Array with vectors pointing to buffers to fill with packet
**                  payloads.
** \param iovcnt    The maximum number of buffers supplied (i.e. size of @p
**                  iov), must be greater than zero.
** \param flags     None yet, must be zero.
**
** \return >0       Number of bytes successfully received
** \return  0       End of File - other end has closed the connection
** \return -EAGAIN  No data avaible to read.
** \return Other error codes are as for zft_zc_recv_done().
**
** Copies received data on a zocket into buffers provided by the caller.  The
** number of bytes received is returned.  The caller's buffers will be filled
** as far as possible, and so a positive return value of less than the total
** space available in @p iov implies that no further data is available.
**
** If no data is available, there are two possibilities: either the connection
** is still open, in which case @p -EAGAIN is returned, or else the connection
** has been closed by the peer, in which case the function succeeds and returns
** zero.
*/
ZF_LIBENTRY ZF_HOT int
zft_recv(struct zft* ts,
         const struct iovec* iov,
         int iovcnt,
         int flags);


/*! \brief Retrieve the UTC timestamp associated with a received packet,
 **        and the clock sync status flags.
 **
 ** \param ts     TCP zocket.
 ** \param msg    Pointer to the received message for which the RX timestamp
 **               will be retrieved.
 ** \param ts_out Pointer to a timespec that is updated on return with the
 **               UTC timestamp for the packet.
 ** \param pktind Index of packet within @p msg->iov.
 ** \param flags  Pointer to an unsigned that is updated on return with the
 **               sync flags for the packet.
 **
 ** \return 0          Success.
 ** \return -ENOMSG    Synchronisation with adapter has not yet been achieved.
 **                    This only happens with old firmware.
 ** \return -ENODATA   Packet does not have a timestamp.
 **                    On current Solarflare adapters, packets that are
 **                    switched from TX to RX do not get timestamped.
 ** \return -EL2NSYNC  Synchronisation with adapter has been lost.
 **                    This should never happen!
 **
 ** \note This function must be called after zf_reactor_perform() returns a value
 **       greater than zero, and before zf_reactor_perform() is called again.
 **
 ** \note If RX timestamps were not enabled during stack initialisation, the
 **       behaviour of this function is undefined.
 **
 ** On success the @p ts_out and @p flags_out fields are updated, and a value of
 ** zero is returned. The @p flags_out field contains the following flags:
 ** - EF_VI_SYNC_FLAG_CLOCK_SET is set if the adapter clock has ever been
 **   set (in sync with system)
 ** - EF_VI_SYNC_FLAG_CLOCK_IN_SYNC is set if the adapter clock is in sync
 **   with the external clock (PTP).
 **
 */
ZF_LIBENTRY ZF_HOT int
zft_pkt_get_timestamp(struct zft* ts, const struct zft_msg* msg,
                      struct timespec* ts_out, int pktind, unsigned* flags);

/*
 * ------------------------------------------------------------------------
 * TCP TX
 *
 * These functions do not block
 * ------------------------------------------------------------------------
 */


/*! \brief Send data specified in iovec array.
**
** \param ts       The TCP zocket to send on.
** \param iov      The iovec of data to send.
** \param iov_cnt  The length of iov.
** \param flags    Flags. 0 or MSG_MORE.
**
** This function adds the supplied data (as indicated by the iov
** argument) to the zocket's send queue and if possible will send it
** (or part of it) on the wire.  To prevent a small packet being sent
** the MSG_MORE flag can be used: it will prevent a packet that is not
** filled up to MSS from being sent.
**
** There is no guarantee that separate calls to this function, or
** separate entries in the iovec array, will result in separate
** packets.  To achieve control over packet boundaries the delegated
** sends API can be used instead.
**
** Provided buffers may be re-used on return from this function.
**
** \return Number of bytes sent on success.
** \return -EINVAL    Incorrect arguments supplied.
** \return -ENOTCONN  Zocket is not in a valid TCP state for sending.
** \return -EAGAIN    Not enough space (either bytes or buffers) in the send
**                    queue to send any portion of the data.
** \return -ENOMEM    Not enough packet buffers available.
**
** \note This function does not support sending zero-length data,
** and does not raise an error if you do so.  Every iovec in the iov array
** must have length greater than 0, and iov_cnt must also be greater than 0.
**
** \note The flags argument must be set to 0 or MSG_MORE.
**
** \note This function will send only part of the data provided if there is
** insufficient space in the send queue to send all of it (and there are
** no error conditions). Use zft_send_space() immediately before this call
** to determine in advance whether only part of the data would be sent.
**
** \note Notes on current implementation:
** 1. Currently, this function will return `-ENOMEM` without sending any data
** if it is unable to send the entire message due to shortage of packet buffers.
** This behaviour might change in future releases.
**
** 2. In case of partial send, the data is queued with MSG_MORE flag set, and
** so may not go out immediately.  See below for details of how to flush a
** MSG_MORE send.
**
** 3. MSG_MORE flag prevents the last partially filled segment from
** being sent immediately.  The only guaranteed way to flush such a segment
** is to follow MSG_MORE send with normal send - otherwise the segment
** might never get sent at all or it may take undefined amount of time.  Some
** non-guaranteed triggers that might induce flush of a MSG_MORE segment:
**  * further MSG_MORE send causes the segment to become full,
**  * preceding normal send left paritally filled segment in sendqueue, or
**  * during stack polling TCP state machine intends to send ACK in
**    response to incoming data.
*/
ZF_LIBENTRY ZF_HOT ssize_t
zft_send(struct zft *ts, const struct iovec* iov, int iov_cnt, int flags);


/*! \brief Send data given in single buffer.
**
** \param ts       The TCP zocket to send on.
** \param buf      The buffer of data to send.
** \param buflen   The length of buffer.
** \param flags    Flags. 0 or MSG_MORE.
**
** This function adds the supplied data (as indicated by the buf
** argument) to the zocket's send queue and if possible will send it
** (or part of it) on the wire.  To prevent a small packet being sent
** the MSG_MORE flag can be used: it will prevent a packet that is not
** filled up to MSS from being sent.
**
** There is no guarantee that separate calls to this function will
** result in separate packets.  To achieve control over packet
** boundaries the delegated sends API can be used instead.  The
** "single" in the name of the function refers to it taking a single
** buffer rather than an iovec of buffers.
**
** Provided buffer may be re-used on return from this function.
**
** \return Number of bytes sent on success.
** \return -EINVAL    Incorrect arguments supplied.
** \return -ENOTCONN  Zocket is not in a valid TCP state for sending.
** \return -EAGAIN    Not enough space (either bytes or buffers) in the send
**                    queue to send any portion of the data.
** \return -ENOMEM    Not enough packet buffers available.
**
** \note This function does not support sending zero-length data,
** and does not raise an error if you do so.
**
** \note The flags argument must be set to 0 or MSG_MORE.
**
** \note This function will send only part of the data provided if there is
** insufficient space in the send queue to send all of it (and there are
** no error conditions). Use zft_send_space() immediately before this call
** to determine in advance whether only part of the data would be sent.
**
** \note Notes on current implementation:
** 1. Currently, this function will return `-ENOMEM` without sending any data
** if it is unable to send the entire message due to shortage of packet buffers.
** This behaviour might change in future releases.
**
** 2. MSG_MORE flag prevents the last partially filled segment from
** being sent immediately.  The only guaranteed way to flush such a segment
** is to follow MSG_MORE send with normal send - otherwise the segment
** might never get sent at all or it may take undefined amount of time.  Some
** non-guaranteed triggers that might induce flush of a MSG_MORE segment:
**  * further MSG_MORE send causes the segment to become full,
**  * preceding normal send left paritally filled segment in sendqueue, or
**  * during stack polling TCP state machine intends to send ACK in
**    response to incoming data.
*/
ZF_LIBENTRY ZF_HOT ZF_NOCLONE ssize_t
zft_send_single(struct zft *ts, const void* buf, size_t buflen, int flags);


/*! \brief Warms code path used by zft_send_single() without sending data.
**
** \param ts       The TCP zocket to send on.
** \param buf      The buffer of data to send.
** \param buflen   The length of buffer.
**
** \return Number of bytes warmed on success.
** \return -EAGAIN    Events need to be processed before warming.
                      Call zf_reactor_perform()
** \return -EMSGSIZE  Data buffer too long.
** \return -ENOTCONN  Zocket is not in a valid TCP state for sending.
** \return -ENOMEM    Not enough packet buffers available.
**
** This function can be called repeatedly while the application waits
** for an input that will trigger a call to zft_send_single().
** Doing so warms the code path to avoid cache and TLB misses when
** actually sending data in the subsequent zft_send_single() call.
** @p buf need not contain the exact data that will eventually
** be sent.
**
** This function only supports warming the code path where the send
** queue is empty and a PIO or CTPIO send would be performed.  If @p buflen
** is too large for PIO then -EMSGSIZE will be returned.  If previous
** sends may still be in progress -EAGAIN will be returned.  In this case,
** the application can call zf_reactor_perform() and then try again.
**
** \see zft_send_single()
**/
ZF_LIBENTRY ZF_HOT ssize_t
zft_send_single_warm(struct zft *ts, const void* buf, size_t buflen);


/*! \brief Query available space in the send queue.
**
** \param ts    The TCP zocket to query the send queue for.
** \param space On successful return, the available space in bytes.
**
** This function will return the current space available in the send
** queue for the given zocket.  This can be used to avoid zft_send()
** returning `-EAGAIN`.
**
** \return 0          Success.
** \return -ENOTCONN  Zocket is not in a valid TCP state for sending.
**
** \note Available send queue space is a function of the number of the
** number of bytes queued, the number of internal buffers in the
** queue, and the MSS. Making many small sends can therefore consume
** more space than a single large send, and force zft_send() to
** compress the send queue to avoid returning `-EAGAIN`.
*/
ZF_LIBENTRY int
zft_send_space(struct zft *ts, size_t *space);


/*! \brief Retrieve the maximum segment size (MSS) for a TCP connection.
**
** \param ts    The TCP zocket to query.
**
** \return >= 0       The value of the MSS in bytes.
** \return -ENOTCONN  Zocket is not in a valid TCP state for sending.
*/
ZF_LIBENTRY int
zft_get_mss(struct zft *ts);


/*! \brief Return protocol header size for this connection.
**
** \param ts      The TCP zocket to query the header size for.
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
zft_get_header_size(struct zft *ts);


/*! \brief Retrieve timestamp reports from previously sent data
**
** \param ts           TCP zocket.
** \param reports      Array to fill with timestamp reports
** \param count_in_out IN: size of array, OUT: number of reports
**
** \return 0 on success, or negative error code.
**
** If transmit timestamps are enabled, then one report will be generated for
** each segment. The segment can be identified by the "start" field of the
** report, which begins at 0 and increments for each byte sent on this zocket.
** Retransmission will cause multiple reports for that segment, and is
** indicated by the ZF_PKT_REPORT_TCP_RETRANS flag as well as discontinuities
** in the reported location. Timestamps are also reported for the packets sent
** to open and close the stream, indicated by the ZF_PKT_REPORT_TCP_SYN and
** ZF_PKT_REPORT_TCP_FIN flags.
*/
ZF_LIBENTRY int
zft_get_tx_timestamps(struct zft* ts,
                      struct zf_pkt_report* reports,
                      int* count_in_out);


#endif /* __ZF_TCP_H__ */
/** @} */
