/*
** Copyright 2005-2012  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author  djr
**  \brief  Misc resources.
**   \date  2004/07/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_etherfabric */
#ifndef __ETHERFABRIC_TOOLS_H__
#define __ETHERFABRIC_TOOLS_H__

#ifdef __cplusplus
extern "C" {
#endif

struct ef_vi;


  /*! Prime the event queue timer.
  **
  ** The timer is primed with the specified timeout value, ready to run
  ** when the next event arrives.  If the timer is already running, it will
  ** be stopped and the timeout value updated accordingly.  When the
  ** timer-value reaches zero, a timeout-event will be delivered.
  **
  ** The timeout is "jiggled" slightly to try to make it unlikely that lots
  ** of timers will go off in the same tick (bug1317).
  **
  ** \param q Pointer to ef_vi structure for the event queue
  ** \param v Initial value for timer (specified in us)
  ** \return Nothing
  */
extern void ef_eventq_timer_prime(struct ef_vi* q, unsigned v);

  /*! Start an event queue timer running.
  **
  ** The timer is primed with the specified timeout value, and starts running
  ** immediately.
  **
  ** The timeout is "jiggled" slightly to try to make it unlikely that lots
  ** of timers will go off in the same tick (bug1317).
  **
  ** \param q Pointer to ef_vi structure for the event queue
  ** \param v Initial value for timer (specified in us)
  */
extern void ef_eventq_timer_run(struct ef_vi* q, unsigned v);

  /*! Stop the event-queue timer.
  **
  ** The timer will not start running when the next event is delivered to
  ** the queue; and if the timer is currently running, it will be stopped,
  ** and no timeout-event will be delivered.
  **
  ** \param q Pointer to ef_vi structure for the event queue
  ** \return Nothing
  */
extern void ef_eventq_timer_clear(struct ef_vi* q);

  /*! Prime the event-queue timer for immediate expiration.
  **
  ** The timer is primed, and will expire when the next event is delivered
  ** to the event queue.  If the timer is already running, it is stopped.
  **
  ** \param q Pointer to ef_vi structure for the event queue
  ** \return Nothing
  */
extern void ef_eventq_timer_zero(struct ef_vi* q);

#ifdef __cplusplus
}
#endif

#endif  /* __ETHERFABRIC_TOOLS_H__ */
/*! \cidoxg_end */
