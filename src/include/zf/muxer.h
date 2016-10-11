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
** \author  gd
**  \brief  Multiplexer.
**   \date  2015/11/20
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ZF_MUXER_H__
#define __ZF_MUXER_H__

/*! \file
**
** \brief The multiplexer, which allows multiple endpoints to be polled in
**        a single operation.
**
** The multiplexer allows multiple endpoints to be polled in a single
** operation.  The basic unit of functionality is the <i>multiplexer set</i>
** implemented by #zf_muxer_set.  Each type of endpoint that can be multiplexed
** is equipped with a method for obtaining a #zf_waitable that represents a
** given endpoint; this #zf_waitable can then be added to a multiplexer set by
** calling zf_muxer_add().  Having added all of the desired endpoints to a set,
** the set can be polled using zf_muxer_wait().
**
** The multiplexer owes much of its design (and some of its datatypes) to
** <tt>epoll(7)</tt>.
*/


#include <zf/types.h>

#include <sys/epoll.h>


/*! \struct zf_muxer_set
**
** \brief Multiplexer set.
**
** Represents multiple endpoints that can be polled simlutaneously.
*/
struct zf_muxer_set;

/** \struct zf_waitable
**
** \brief Abstract multiplexable endpoint.
**
** Endpoints that can be added to a multiplexer set can be represented by a
** pointer of this type, which can be obtained by making the appropriate API
** call for the given endpoint.
*/
struct zf_waitable;


/*! \brief Allocates a multiplexer set.
**
** \param stack        Stack to associate with multiplexer set.
** \param muxer_out    Holds the address of the allocated multiplexer set on
**                     success.
**
** \return 0 on success, or a negative error code.
**
** Allocates a multiplexer set, which allows multiple endpoints to be polled in
** a single operation.  Endpoints, together with a mask of desired events, can
** be added to the set using zf_muxer_add().  The set can then be polled using
** zf_muxer_wait().
 */
LIBENTRY int
zf_muxer_alloc(struct zf_stack* stack, struct zf_muxer_set** muxer_out);


/*! \brief Frees a multiplexer set.
**
** \param muxer        The multiplexer set to free.
**
** \note If there are endpoints in the set at the point at which it is freed,
**       the underlying memory will not be freed until all of those endpoints
**       have been removed from the set.  Nonetheless, the caller should never
**       continue to use a pointer passed to this function.
*/
LIBENTRY void
zf_muxer_free(struct zf_muxer_set* muxer);


/*! \brief Adds an endpoint to a multiplexer set.
**
** \param muxer        Multiplexer set.
** \param w            Endpoint to add.
** \param event        Descriptor specifying the events that will be polled on
**                     the endpoint, and the data to be returned when those
**                     events are detected.
**
** \return 0 on success, or a negative error code.
**
** Adds an endpoint to a multiplexer set.  Each endpoint may belong to at most
** one multiplexer set at a time.  The events of interest are specified by
** @p event.events, which is a bitfield that should be populated from one or more
** of `EPOLLIN`, `EPOLLOUT`, `EPOLLHUP` and `EPOLLERR` as desired. @p event.data
** specifies the data to be returned to a caller of zf_muxer_wait() when that
** endpoint is ready.  Note that the endpoint itself is not in general returned
** to such callers; if this is desired, then @p event.data must be set in such a
** way that the endpoint can be determined.
 *
 * \note Unlike epoll functions in Linux, you have to explicitly set
 * EPOLLHUP and EPOLLERR if you want to be notified about these events.
*/
LIBENTRY int
zf_muxer_add(struct zf_muxer_set* muxer, struct zf_waitable* w,
             const struct epoll_event* event);


/*! \brief Modifies the event data for an endpoint in a multiplexer set.
**
** \param w            Endpoint to modify.
** \param event        Descriptor specifying the events that will be polled on
**                     the endpoint, and the data to be returned when those
**                     events are detected.
**
** \return 0 on success, or a negative error code.
**
** \sa zf_muxer_add().
 *
 * \note This function can be used to re-arm waitable ater it is returned
 * by zf_muxer_wait() if user likes something like level-triggered events:
 *   zf_muxer_mod(w, zf_waitable_event(w));
*/
LIBENTRY int
zf_muxer_mod(struct zf_waitable* w, const struct epoll_event* event);


/*! \brief Removes an endpoint from a multiplexer set.
**
** \param w            Endpoint to remove.
**
** \return 0 on success, or a negative error code.
**
** \note This operation should be avoided on fast paths.
*/
LIBENTRY int
zf_muxer_del(struct zf_waitable* w);


/*! \brief Polls a multiplexer set.
**
** \param muxer        Multiplexer set.
** \param events       Array into which to return event descriptors.
** \param maxevents    Maximum number of events to return.
** \param timeout      Maximum time in milliseconds to block.
**
** \return Number of events on success, or a negative error code.
**
** This function polls a multiplexer set and populates an array of event
** descriptors representing the endpoints in that set that are ready.  The
** `events` member of each descriptor specifies the events for which the
** endpoint is actually ready, and the `data` member is set to the user-data
** associated with that descriptor, as specified in the call to zf_muxer_add()
** or zf_muxer_mod().
**
** Before checking for ready endpoints, the function calls zf_reactor_perform()
** on the set's stack in order to process events from the hardware.  In
** contrast to the rest of the API, zf_muxer_wait() can block.  The maximum
** time to block is specified by @p timeout, and a value of zero results in
** non-blocking behaviour.  A negative value for @p timeout will allow the
** function to block indefinitely.  If the function, blocks, it will call
** zf_reactor_perform() repeatedly in a tight loop.
**
** The multiplexer supports only edge-triggered events: that is, if
** zf_muxer_poll() reports that an endpoint is ready, it will not do so again
** until a <i>new</i> event occurs on that endpoint, even if the endpoint is
** in fact ready.
*/
LIBENTRY int
zf_muxer_wait(struct zf_muxer_set* muxer, struct epoll_event* events,
              int maxevents, int timeout);


/** \brief Find out the epoll_event data in use with this waitable
 *
 * \param w            Endpoint to explore.
 *
 * \return the event data.
 *
 * \note Function behaviour is undefined if the waitable is not a member of
 * any multiplexer set.
 */
LIBENTRY struct epoll_event* zf_waitable_event(struct zf_waitable* w);

#endif /* __ZF_MUXER_H__ */
