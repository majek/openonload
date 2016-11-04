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
** call this function or zf_muxer_wait() frequently for each stack that is in
** use.  Please see \ref using_stack_poll in the User Guide for further
** information.
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
** \see zf_muxer_wait()
*/
ZF_LIBENTRY ZF_HOT int
zf_reactor_perform(struct zf_stack* st);


/*! \brief Determine whether a stack has work pending.
**
** \param st           Stack to check for pending work.
**
** This function returns non-zero if the stack has work pending, and
** therefore the application should call zf_reactor_perform() or
** zf_muxer_wait().
**
** This function can be called concurrently with other calls on a stack,
** and so can be used to avoid taking a serialisation lock (and therefore
** avoid inducing lock contention) when there isn't any work to do.
**
** \return 0  if there is nothing to do.
** \return >0 if there is some work pending.
**
** \see zf_reactor_perform() zf_muxer_wait()
*/
ZF_LIBENTRY ZF_HOT int
zf_stack_has_pending_work(const struct zf_stack* st);


#endif /* __REACTOR_H__ */
/** @} */
