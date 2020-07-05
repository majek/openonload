/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
**  \brief  TCPDirect multiplexer.
*//*
\**************************************************************************/

#ifndef __ZF_MUXER_H__
#define __ZF_MUXER_H__

#ifndef __IN_ZF_TOP_H__
# error "Please include zf.h to use TCPDirect."
#endif


/*! \file
**
** \brief The multiplexer, which allows multiple objects to be polled in
**        a single operation.
**
** The multiplexer allows multiple zockets to be polled in a single
** operation.  The basic unit of functionality is the <i>multiplexer set</i>
** implemented by #zf_muxer_set.  Each type of zocket that can be multiplexed
** is equipped with a method for obtaining a #zf_waitable that represents a
** given zocket; this #zf_waitable can then be added to a multiplexer set by
** calling zf_muxer_add().  Having added all of the desired zockets to a set,
** the set can be polled using zf_muxer_wait().
**
** The multiplexer owes much of its design (and some of its datatypes) to
** <tt>epoll(7)</tt>.
*/


#include <sys/epoll.h>


/*! \struct zf_muxer_set
**
** \brief Multiplexer set.
**
** Represents multiple objects (including zockets) that can be polled
** simultaneously.
*/
struct zf_muxer_set;

/** \struct zf_waitable
**
** \brief Abstract multiplexable object.
**
** Zockets that can be added to a multiplexer set can be represented by a
** pointer of this type, which can be obtained by making the appropriate API
** call for the given zocket.
**
** A waitable can also be retrieved for a stack by calling
** zf_stack_to_waitable().  Such waitables indicate whether a stack has
** quiesced, in the sense documented at zf_stack_is_quiescent().
*/
struct zf_waitable;


/*! \brief Allocates a multiplexer set.
**
** \param stack        Stack to associate with multiplexer set.
** \param muxer_out    Holds the address of the allocated multiplexer set on
**                     success.
**
** \return 0 on success, or a negative error code:
** \return -ENOMEM  Out of memory.
**
** Allocates a multiplexer set, which allows multiple waitable objects to be
** polled in a single operation.  Waitable objects, together with a mask of
** desired events, can be added to the set using zf_muxer_add().  The set can
** then be polled using zf_muxer_wait().
*/
ZF_LIBENTRY int
zf_muxer_alloc(struct zf_stack* stack, struct zf_muxer_set** muxer_out);


/*! \brief Frees a multiplexer set.
**
** \param muxer        The multiplexer set to free.
**
** \note If there are waitables in the set at the point at which it is freed,
**       the underlying memory will not be freed until all of those waitables
**       have been removed from the set.  Nonetheless, the caller should never
**       continue to use a pointer passed to this function.
*/
ZF_LIBENTRY void
zf_muxer_free(struct zf_muxer_set* muxer);

/*! Proprietary event type enabling overlapped receive - \see zf_muxer_wait */
#define ZF_EPOLLIN_OVERLAPPED 0x10000

/*! \brief Adds a waitable object to a multiplexer set.
**
** \param muxer        Multiplexer set.
** \param w            Waitable to add.
** \param event        Descriptor specifying the events that will be polled on
**                     the waitable, and the data to be returned when those
**                     events are detected.
**
** \return 0 on success, or a negative error code:
** \return -EXDEV     Waitable does not belong to the multiplexer set's stack.
** \return -EALREADY  Waitable is already in this multiplexer set.
** \return -EBUSY     Waitable is already in another multiplexer set.
**
** Adds a waitable object to a multiplexer set.  Each waitable may belong to at
** most one multiplexer set at a time.  The events of interest are specified by
** @p event.events, which is a bitfield that should be populated from one or
** more of `EPOLLIN`, `EPOLLOUT`, `EPOLLHUP`, `EPOLLERR` or `ZF_EPOLLIN_OVERLAPPED`
** as desired. @p
** event.data specifies the data to be returned to a caller of zf_muxer_wait()
** when that waitable is ready.  Note that the waitable itself is not in
** general returned to such callers; if this is desired, then @p event.data
** must be set in such a way that the waitable can be determined.
**
** \note Unlike epoll functions in Linux, you have to explicitly set
** `EPOLLHUP` and `EPOLLERR` if you want to be notified about these events.
*/
ZF_LIBENTRY int
zf_muxer_add(struct zf_muxer_set* muxer, struct zf_waitable* w,
             const struct epoll_event* event);


/*! \brief Modifies the event data for a waitable object in a multiplexer set.
**
** \param w            Waitable to modify.
** \param event        Descriptor specifying the events that will be polled on
**                     the waitable, and the data to be returned when those
**                     events are detected.
**
** \return 0 on success, or a negative error code:
** \return -EINVAL  @p w has not been added to a multiplexer set.
**
** \sa zf_muxer_add().
**
** \note This function can be used to re-arm waitable after it is returned
** by zf_muxer_wait() if user likes something like level-triggered events:
** ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.c}
**   zf_muxer_mod(w, zf_waitable_event(w));
** ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*/
ZF_LIBENTRY int
zf_muxer_mod(struct zf_waitable* w, const struct epoll_event* event);


/*! \brief Removes a waitable object from a multiplexer set.
**
** \param w            Waitable to remove.
**
** \return 0 on success, or a negative error code:
** \return -EINVAL  @p w has not been added to a multiplexer set.
**
** \note This operation should be avoided on fast paths.
*/
ZF_LIBENTRY int
zf_muxer_del(struct zf_waitable* w);


/*! \brief Polls a multiplexer set.
**
** \param muxer        Multiplexer set.
** \param events       Array into which to return event descriptors.
** \param maxevents    Maximum number of events to return.
** \param timeout_ns   Maximum time in nanoseconds to block.
**
** \return Number of events.  Negative values are reserved for future use as
** error codes, but are not returned at present.
**
** This function polls a multiplexer set and populates an array of event
** descriptors representing the waitables in that set that are ready.  The
** `events` member of each descriptor specifies the events for which the
** waitable is actually ready, and the `data` member is set to the user-data
** associated with that descriptor, as specified in the call to zf_muxer_add()
** or zf_muxer_mod().
**
** Before checking for ready objects, the function calls zf_reactor_perform()
** on the set's stack in order to process events from the hardware.  In
** contrast to the rest of the API, zf_muxer_wait() can block.  The maximum
** time to block is specified by @p timeout_ns, and a value of zero results in
** non-blocking behaviour.  A negative value for @p timeout_ns will allow the
** function to block indefinitely.  If the function blocks, it will call
** zf_reactor_perform() repeatedly in a tight loop.
**
** The multiplexer only supports edge-triggered events: that is, if
** zf_muxer_wait() reports that a waitable is ready, it need not do so again
** until a <i>new</i> event occurs on tha waitable, even if the waitable is
** in fact ready.  On the other hand, a waitable <i>may</i> be reported as
** ready even when a new event has not occurred, but only when the waitable is
** in fact ready.  A transition from "not ready" to "ready" always constitutes
** an edge, and in particular, for `EPOLLIN`, the arrival of any new data
** constitutes an edge.
**
** By default this function has relatively high CPU overhead when no events
** are ready to be processed and timeout_ns==0, because it polls repeatedly
** for events.  The amount of time spent polling is controlled by stack
** attribute reactor_spin_count.  Setting reactor_spin_count to 1 disables
** polling and minimises the cost of zf_muxer_wait(timeout_ns=0).
**
**
** <b>Overlapped receive</b>
**
** A zocket added to the muxer with the \ref ZF_EPOLLIN_OVERLAPPED event
** mask bit set can get access to the packet data while reception is
** still in progress, before the integrity of the frame is verified.
** See \ref using_overlapped_receive.
**
** \note The \ref ZF_EPOLLIN_OVERLAPPED event will not be reported in
** conjuction with other events, zf_muxer_wait() will return 1, and
** \ref ZF_EPOLLIN_OVERLAPPED will be the only flag set.
**
** \see `zfur_zc_recv` `zft_zc_recv` `zf_zc_flags`
*/
ZF_LIBENTRY int
zf_muxer_wait(struct zf_muxer_set* muxer, struct epoll_event* events,
              int maxevents, int64_t timeout_ns);


/** \brief Find out the epoll_event data in use with this waitable.
 *
 * \param w            Waitable to explore.
 *
 * \return The event data.
 *
 * \note Function behaviour is undefined if the waitable is not a member of
 * any multiplexer set.
 */
ZF_LIBENTRY const struct epoll_event* zf_waitable_event(struct zf_waitable* w);


/** \brief Create an fd that can be used within an epoll set or other
 * standard muxer
 *
 * \param stack         Stack the fd should indicate activity for
 * \param fd            Updated on success to contain the fd to use
 *
 * \return 0 on success, or a negative error code.  The possible error-codes
 * are returned from system calls and are system-dependent.
 *
 * This function creates a file descriptor that can be used within an
 * epoll set (or other standard muxer such as poll or select) to be
 * notified when there is activity on the corresponding stack.
 *
 * The fd supplied may indicate readiness for a variety of reasons not
 * directly related to the availability of data on a zocket. For
 * example, there is an event that needs processing, a timer has
 * expired, or a connection has changed state.  When this occurs the
 * caller should ensure they call zf_muxer_wait() to allow the
 * required activity to take place, and discover if this affected any
 * of the stack's zockets that the caller is interested in.  This may
 * or may not result in a zocket within the stack becoming readable or
 * writeable.
 *
 * Using a waitable FD with the `zf_waitable_fd...()` family of functions 
 * enables interrupts. For latency-critical applications, you should instead 
 * manually poll each reactor in turn, after first setting the 
 * \attrref{reactor_spin_count} attribute to 1.
 * 
 * Freeing the zf_stack will release all the resources associated with
 * this fd, so it must not be used afterwards.  You do not need to
 * call close() on the supplied fd, it will be closed when the stack
 * is freed as part of the zf_stack_free() call.
 */

ZF_LIBENTRY int
zf_waitable_fd_get(struct zf_stack* stack, int* fd);


/** \brief Prime the fd before blocking
 *
 * \param stack         Stack that matches the fd
 *
 * \return 0 on success, or a negative error code.  The possible error-codes
 * are returned from system calls and are system-dependent.
 *
 * This primes an fd previously allocated with zf_waitable_fd_get() so
 * it is ready for use with a standard muxer like epoll_wait.  The fd
 * should be primed in this way each time the caller blocks waiting
 * for activity.
 */

ZF_LIBENTRY int
zf_waitable_fd_prime(struct zf_stack* stack);


#endif /* __ZF_MUXER_H__ */
/** @} */
