/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
**  \brief  TCPDirect Alternative Sends API
*//*
\**************************************************************************/

#ifndef __ZF_ALTS_H__
#define __ZF_ALTS_H__

/*! \brief Opaque handle for an alternative. */
typedef uint64_t zf_althandle;
 
/*! \brief Acquire an ID for an alternative queue
**
** \param stack        Stack to allocate the alternative for
** \param attr         Requested attributes for the alternative.  At the
**                     present time, the attributes are unused.  Refer to the
**                     attribute documentation in \ref attributes for details.
** \param alt_out      Handle for the allocated alternative
**
** \return 0           Success
** \return -ENOMEM     No alternative queues available
**
** The alternative queue is identified by opaque handles, and is only
** able to be used with zockets in the stack provided to this function.
**
** The number of alternatives available to a stack is controlled by the
** value of the `alt_count` attribute used when creating the stack.  This value
** defaults to zero.
**
** \note TX alternatives are not supported on stacks running on bonded network
** interfaces.
**
** \see zf_alternatives_release()
*/
ZF_LIBENTRY int
zf_alternatives_alloc(struct zf_stack* stack, const struct zf_attr* attr,
                      zf_althandle* alt_out);


/*! \brief Release an ID for an alternative queue
**
** \param stack        Stack to release the alternative for
** \param alt          zf_alternative to release
**
** \return 0           Success
**
** Releases allocated alternative queue.  If any messages are queued on the
** specified queue they will be flushed without being sent.
**
** \see zf_alternatives_alloc()
*/
ZF_LIBENTRY int
zf_alternatives_release(struct zf_stack* stack, zf_althandle alt);


/*! \brief Select an alternative and send those messages
**
** \param stack       Stack the alternative was allocated on
** \param alt         Selected alternative
**
** \return 0          Success
** \return -EBUSY     Unable to send due to a transient state (e.g. the
**                    alternative queue is being refreshed in response
**                    to receiving data).
** \return -EINVAL    Unable to send due to inconsistent TCP state
**                    (e.g. the zocket is not connected, or has been
**                    used via the normal send path after queueing
**                    messages on this alternative queue)
**
** On success messages queued on the selected alternative are sent.
** If other alternative queues have messages queued for the same
** zocket, their headers will now be out of date and you must call
** zf_alternatives_cancel() on those queues.  You are free to reuse
** this alternative queue, but until it has finished sending the
** current set of messages calls to zft_alternatives_queue() will return
** -EBUSY.
*/
ZF_LIBENTRY int
zf_alternatives_send(struct zf_stack* stack, zf_althandle alt);


/*! \brief Cancel an alternative
**
** \param stack       Stack the alternative was allocated on
** \param alt         Selected alternative
**
** \return 0          Success
**
** Drops messages queued on this alternative without sending.
**
** You can reuse the alternative queue immediately for new messages
** (including messages on a different zocket from the previous use)
** but zft_alternatives_queue() may return -EBUSY until the cancel
** operation is completed.
*/
ZF_LIBENTRY int
zf_alternatives_cancel(struct zf_stack* stack, zf_althandle alt);


/*! \brief Queue a TCP message for sending
**
** \param ts          TCP zocket
** \param alt         ID of the queue to push this message to.  Must have been
**                    allocated via zf_alternatives_alloc()
** \param iov         TCP payload data to send in this message.
** \param iov_cnt     Number of iovecs to send. Currently must be 1.
** \param flags       Reserved for future use; must be zero.
**
** \return 0          Success
**
** \return -EAGAIN    Unable to queue due to a transient problem,
**                    e.g. the TCP send queue is not empty. These
**                    errors may remain present for many milliseconds;
**                    the caller should decide whether to retry
**                    immediately or to perform other work in the
**                    meantime.
**
** \return -EBUSY     Unable to queue due to a transient problem, e.g. the
**                    alternative queue is still draining from a
**                    previous operation. These errors are expected to
**                    clear quickly without outside intervention; the
**                    caller can react by calling zf_reactor_perform()
**                    and retrying the operation.
**
** \return -EMSGSIZE  Enqueuing the message would exceed the total congestion
**                    window.
**
** \return -ENOMEM    Unable to queue due to all packet buffers being
**                    allocated already.
**
** \return -ENOBUFS   Unable to queue due to a lack of available buffer 
**                    space, either in TCP Direct or in the NIC hardware.
**
** \return -EINVAL    Invalid parameters.  This includes the case where the
**                    alternative already has data queued on another zocket.
**
** This function behaves similarly to zft_send(), but doesn't actually put
** the data on the wire.
**
** For now it is only possible to send a single buffer of data in each
** call to zft_alternatives_queue(); this function will return -EINVAL
** if 'iov_cnt' is not equal to 1. Future releases may change this.
** Multiple messages can be queued for sending on a single alternative
** by calling zft_alternatives_queue() for each message.
**
** The current implementation limits all messages enqueued on an
** alternative to be from the same zocket.  This may change in future.
**
** In some cases where an alternative is in the middle of an operation
** such as a send, cancel, etc. this function may return -EBUSY. In
** this case the caller should process some events and retry.
**
*/
ZF_LIBENTRY int
zft_alternatives_queue(struct zft* ts, zf_althandle alt,
                       const struct iovec* iov, int iov_cnt,
                       int flags);


/*! \brief Query the amount of free buffering on an alt
**
** \param stack       Stack the alternative was allocated on
** \param alt         Selected alternative
**
** \return            Number of bytes available
**
** The return value of this function is the payload size in bytes of
** the largest packet which can be sent into this alternative at this
** moment. Larger packets than this will cause -ENOMEM errors from
** functions which queue data on alternatives.
**
** Due to per-packet and other overheads, this amount may be different
** on different alternatives, and is not guaranteed to rise and fall
** by exactly the sizes of packets queued and sent.
**
** The returned value includes all packet headers. The maximum length
** of data accepted by zft_alternatives_queue() will be lower than
** this by the size of the TCP+IP+Ethernet headers. To find a zocket's
** header size, use zft_get_header_size() or zfut_get_header_size().
*/
ZF_LIBENTRY unsigned
zf_alternatives_free_space(struct zf_stack* stack, zf_althandle alt);

/*! \brief Per-packet overhead information
**
** This structure is used by ef_vi_transmit_alt_usage() to calculate
** the amount of buffering needed to store a packet.
**
** Include the <etherfabric/ef_vi.h> header if you need the definition
** of this structure. */
struct ef_vi_transmit_alt_overhead;

/*! \brief Query TCP per-packet overhead parameters
**
** \param ts          TCP connection to be queried
** \param out         Returned overhead parameters
**
** \return 0 on success or -EINVAL if this stack doesn't support
** alternatives.
**
** This function returns a set of parameters which can be used with
** ef_vi_transmit_alt_usage() to calculate the amount of buffer space
** used when sending data via TCP, taking into account the space taken
** up by headers, VLAN tags, IP options etc.
**
** Use of this function in this way assumes that the transmitted data
** fits entirely into a single TCP packet.
**
** See the documentation for ef_vi_transmit_alt_usage() for more.
*/
ZF_LIBENTRY int
zf_alternatives_query_overhead_tcp(struct zft* ts, 
                                   struct ef_vi_transmit_alt_overhead *out);


#endif /* __ZF_ALTS_H__ */
/** @} */
