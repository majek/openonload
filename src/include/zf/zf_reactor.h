/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
**  \brief  TCPDirect reactor API for processing stack events.
*//*
\**************************************************************************/

#ifndef __REACTOR_H__
#define __REACTOR_H__

#ifndef __IN_ZF_TOP_H__
# error "Please include zf.h to use TCPDirect."
#endif


struct zf_stack;

/*! \brief Process events on a stack.
**
** \param st           Stack for which to process events.
**
** This function processes events on a stack and performs the necessary
** handling.  These events include transmit and receive events raised by the
** hardware, and also software events such as TCP timers.  Applications must
** call zf_reactor_perform(), zf_reactor_perform_attr() or zf_muxer_wait()
** frequently for each stack that is in use.  Please see
** \ref using_stack_poll in the User Guide for further information.
**
** By default this function has relatively high CPU overhead when no events
** are ready to be processed, because it polls repeatedly for events.  The
** amount of time spent polling is controlled by stack attribute
** reactor_spin_count.  Setting reactor_spin_count to 1 disables polling
** and minimises the cost of zf_reactor_perform(). To override
** reactor_spin_count for a single call, zf_reactor_perform_attr() can be
** used instead.
**
** \return 0  if nothing user-visible occurred as a result.
** \return >0 if something user-visible might have occurred as a result.
** \return Here, "something user-visible occurred" means that the
**         event-processing just performed has had an effect that can be seen
**         by another API call: for example, new data might have arrived on a
**         zocket, in which case that data can be retrieved by one of the
**         receive functions.  False positives are possible: a value greater
**         than zero indicates to the application that it should process its
**         zockets, but it does not guarantee that this will yield anything
**         new.  Finer-grained advertisement of interesting events can be
**         achieved using the multiplexer.
**
** \see zf_reactor_perform_attr() zf_muxer_wait()
*/
ZF_LIBENTRY ZF_HOT int
zf_reactor_perform(struct zf_stack* st);

/*! \brief Process events on a stack, with overridden attributes.
**
** \param st           Stack for which to process events.
** \param attr         Overridden properties for event processing. Only
**                     reactor_spin_count is currently supported.
**
** This function processes events on a stack and performs the necessary
** handling.  These events include transmit and receive events raised by the
** hardware, and also software events such as TCP timers.  Applications must
** call zf_reactor_perform(), zf_reactor_perform_attr() or zf_muxer_wait()
** frequently for each stack that is in use.  Please see
** \ref using_stack_poll in the User Guide for further information.
**
** This function differs from zf_reactor_perform() in that the
** reactor_spin_count stack attribute will be overriden using the provided
** attributes. In all other respects it is identical to zf_reactor_perform().
**
** reactor_spin_count is the only supported override at this time.
** Other attributes may be added in future versions so callers need to take
** care with the setting of other attributes to avoid unintended side effects
** when run against future versions.
**
** This function polls repeatedly for events.  The
** amount of time spent polling is controlled by the attribute
** reactor_spin_count.  Setting reactor_spin_count to 1 disables polling
** and minimises the cost of zf_reactor_perform_attr().
**
** \return 0  if nothing user-visible occurred as a result.
** \return >0 if something user-visible might have occurred as a result.
** \return Here, "something user-visible occurred" means that the
**         event-processing just performed has had an effect that can be seen
**         by another API call: for example, new data might have arrived on a
**         zocket, in which case that data can be retrieved by one of the
**         receive functions.  False positives are possible: a value greater
**         than zero indicates to the application that it should process its
**         zockets, but it does not guarantee that this will yield anything
**         new.  Finer-grained advertisement of interesting events can be
**         achieved using the multiplexer.
**
** \see zf_reactor_perform() zf_muxer_wait()
*/
ZF_LIBENTRY ZF_HOT int
zf_reactor_perform_attr(struct zf_stack* st, const struct zf_attr* attr);

/*! \brief Determine whether a stack has work pending.
**
** \param st           Stack to check for pending work.
**
** This function returns non-zero if the stack has work pending, and
** therefore the application should call zf_reactor_perform(),
** zf_reactor_perform_attr() or zf_muxer_wait().
**
** This function can be called concurrently with other calls on a stack,
** and so can be used to avoid taking a serialisation lock (and therefore
** avoid inducing lock contention) when there isn't any work to do.
**
** \return 0  if there is nothing to do.
** \return >0 if there is some work pending.
**
** \see zf_reactor_perform() zf_reactor_perform_attr() zf_muxer_wait()
*/
ZF_LIBENTRY ZF_HOT int
zf_stack_has_pending_work(const struct zf_stack* st);


/*! \brief Determine whether a stack has events pending, but don't check
** TCP-specific non-event-based work.
**
** \param st           Stack to check for pending work.
**
** This function is a cut-down version of zf_stack_has_pending_work().
** It returns non-zero if the stack has events pending, and therefore
** the application should call zf_reactor_perform(),
** zf_reactor_perform_attr() or zf_muxer_wait().
**
** This differs from zf_stack_has_pending_work() in that it never
** tries to check whether there is non-event-based work (such as
** processing TCP timers) pending.  If the calling application knows
** there is no TCP work (e.g. it is using only UDP zockets) this
** function may be a few cycles cheaper.
*/
ZF_LIBENTRY ZF_HOT int
zf_stack_has_pending_events(const struct zf_stack* st);


#endif /* __REACTOR_H__ */
/** @} */
