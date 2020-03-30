/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  al
**  \brief  Decls & defs for event select support.
**   \date  2005/10/10
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */

#ifndef __CI_INTERNAL_EVENT_SELECT_H__
#define __CI_INTERNAL_EVENT_SELECT_H__

#include <ci/internal/ip.h>


/* ***************************
 * Inline functions
 */

/* Get current "accept" event state for a TCP connection */
ci_inline unsigned ci_tcp_state_get_accept_event_mask(ci_netif* ni,
                                                      ci_tcp_socket_listen* tsl)
{
  /* Is the accept queue non-empty?
  **
  ** Dave says this is "safe" to check this without the netif lock using
  ** what's the worst that can happen rationale.  We potentially say a
  ** listening socket that is being closed/shutdown has something in its
  ** queue when it doesn't and an application that is doing this stuff
  ** in a multi-threaded way should then cope with subsequent errors from
  ** accept.
  */
  return ci_tcp_acceptq_n(tsl) ? CI_EV_ACCEPT : CI_EV_NONE;
}

/* Get current "read" event state for a TCP connection */
ci_inline unsigned ci_tcp_state_get_read_event_mask(ci_netif* ni,
                                                    ci_tcp_state* ts)
{
  unsigned mask = CI_EV_NONE;

  /* Are we in the closed state? */
  if (ts->s.b.state == CI_TCP_CLOSED) {
    mask = CI_EV_CLOSED;
  } else {
    /* Any urgent data on recv queue? */
    if (!(tcp_urg_data(ts) & (CI_TCP_URG_IS_HERE | CI_TCP_URG_NOT_DEL))) {
      /* No.  Check for 'any' data (ignoring shutdown) */
      if (tcp_rcv_usr(ts))
	mask = CI_EV_READ;
      
    } else {
      /*
       * Yes.  We have a urgent data - don't need to check if
       * we're OOBINLINE - can't be, otherwise
       *  CI_TCP_URG_IS_HERE wouldn't be set
       */
      ci_uint32 bytes = tcp_rcv_usr(ts);
      if (tcp_urg_data(ts) & CI_TCP_URG_IS_HERE)
	mask = CI_EV_OOB;
      
      /* Any additional data? */
      if (tcp_rcv_usr(ts) > 1)
	mask |= CI_EV_READ;
    }
  }
  
  /* Windows actually behaves like this. the FD_CLOSE is posted as soon as the
  ** connection is considered closed irrespective of whether it is graceful or
  ** abortive.
  **
  ** FD_READ and FD_CLOSE can be posted at the same time, and further FD_READ
  ** events can be posted after FD_CLOSE.
  */

  /* Are we closed/shutdown for reading? */
  if (ts->s.rx_errno & CI_SHUT_RD)
    mask |= CI_EV_CLOSE;

  return mask;
}

/* Get current "write" event state for a TCP connection */
ci_inline unsigned ci_tcp_state_get_write_event_mask(ci_netif* ni,
                                                     ci_tcp_state* ts)
{
  unsigned mask = CI_EV_NONE;

  /* Are we connected? */
  if (ts->s.b.state & CI_TCP_STATE_SYNCHRONISED) {
    /* Any write space? (ignoring shutdown) */
    if (ci_tcp_tx_advertise_space(ni, ts))
      mask = (CI_EV_CONNECT | CI_EV_WRITE);
    else
      mask = CI_EV_CONNECT;
  }
  
  if ((ts->tcpflags & CI_TCPT_FLAG_WAS_ESTAB) && ts->s.tx_errno)
    mask |= CI_EV_WRITE;

  return mask;
}

/* Get current event state for a UDP connection */
ci_inline unsigned ci_udp_state_get_current_event_mask(ci_netif* ni,
                                                       ci_udp_state* us)
{
  unsigned mask = CI_EV_NONE;
  if( us->s.so.sndbuf > (int)(us->tx_count) )   mask |= CI_EV_WRITE;
  if( (us->s.evsel_latest & FD_READ) || ci_udp_recv_q_not_empty(us) )
    mask |= CI_EV_READ;

  /* Note: UDP sockets don't appear to have the same FD_CLOSE semantic
   * as TCP (in other words you don't get FD_CLOSE when SHUT_RD). */
  return mask;
}

/* Get current event state for a socket */
ci_inline unsigned ci_sock_cmn_get_current_event_mask(ci_netif* ni,
                                                      ci_sock_cmn* s)
{
  unsigned v;
  if (s->b.state == CI_TCP_LISTEN)
    v = ci_tcp_state_get_accept_event_mask(ni, SOCK_TO_TCP_LISTEN(s));
  else if (s->b.state == CI_TCP_STATE_UDP)
    v = ci_udp_state_get_current_event_mask(ni, SOCK_TO_UDP(s));
  else
    v = (ci_tcp_state_get_read_event_mask(ni, SOCK_TO_TCP(s)) |
            ci_tcp_state_get_write_event_mask(ni, SOCK_TO_TCP(s)));
  /* OR-in the current flags from the backing socket */
  return v | (unsigned)s->evsel_latest;
}

#ifndef __KERNEL__

/* Re-arm event trigger mechanism */
ci_inline void ciul_event_trigger_arm(citp_socket* ep, ci_fd_t fd,
                                      unsigned const trigger_idx,
                                      unsigned arm_events)
{
  ci_netif * ni;
  ci_sock_cmn * s;
  ci_atomic_t * armed_event_mask;

  ci_assert( ep );

  ni = ep->netif;
  s = ep->s;

  ci_assert( ni );
  ci_assert( s );

  /* Leave if no events to arm */
  if (!arm_events) return;

  /* Re-arm event select wakeup mask */
  armed_event_mask = &s->trigger_armed_mask[trigger_idx];
  ci_atomic_or(armed_event_mask, arm_events);

  /* \FIXME TODO: Make callers check this first so we don't need to do it in
  **              all cases.
  */
  /* Any current "trigger" events? */
  if ( ci_sock_cmn_get_current_event_mask(ni, s) &
       ci_atomic_read(armed_event_mask) ) {
    /* Yes, fire the trigger */
    ci_atomic_set(armed_event_mask, CI_EV_NONE);
    ci_tcp_helper_fire_event_trigger(ni, fd, SC_SP(ep->s), trigger_idx);
  }
  else {
    /* Set [wake_needed] so stack knows to "wake" us up. */
    if (arm_events & CI_EV_RX_WAKE)
      ci_bit_set(&s->b.wake_request, CI_SB_FLAG_WAKE_RX_B);
    if (arm_events & CI_EV_TX_WAKE)
      ci_bit_set(&s->b.wake_request, CI_SB_FLAG_WAKE_TX_B);

    /* Check current "trigger" events again */
    if ( ci_sock_cmn_get_current_event_mask(ni, s) &
         ci_atomic_read(armed_event_mask) ) {
      /* Found some, fire the trigger and leave */
      ci_atomic_set(armed_event_mask, CI_EV_NONE);
      ci_tcp_helper_fire_event_trigger(ni, fd, SC_SP(ep->s), trigger_idx);
    }
  }

  /* Although we don't actually sleep we will be notified by the wake
  ** mechanism when an armed event occurs.
  */
}

/* Re-arm event select mechanism after a accept to watch for ACCEPT events. */
ci_inline void citp_evsel_arm_accept(citp_socket* ep, ci_fd_t fd)
{
  ci_assert( ep );
  if (ep->s->evsel_mask & CI_EV_ACCEPT) {
    ep->s->evsel_armed_mask |= CI_EV_ACCEPT;
    ciul_event_trigger_arm(ep, fd, CI_SOCK_TRIGGER_EVENT_SELECT_IDX,
                           ep->s->evsel_armed_mask);
  }
}

/* Re-arm event select mechanism after a read to watch for READ events */
ci_inline void citp_evsel_arm_read(citp_socket* ep, ci_fd_t fd)
{
  ci_assert( ep );
  
  if (ep->s->evsel_mask & CI_EV_READ) {
    ep->s->evsel_armed_mask |= CI_EV_READ;
    ciul_event_trigger_arm(ep, fd, CI_SOCK_TRIGGER_EVENT_SELECT_IDX,
                           ep->s->evsel_armed_mask);
  }
}

/* Re-arm event select mechanism after a read to watch for OOB events */
ci_inline void citp_evsel_arm_oob(citp_socket* ep, ci_fd_t fd)
{
  ci_assert( ep );
  
  if (ep->s->evsel_mask & CI_EV_OOB) {
    ep->s->evsel_armed_mask |= CI_EV_OOB;
    ciul_event_trigger_arm(ep, fd, CI_SOCK_TRIGGER_EVENT_SELECT_IDX,
                           ep->s->evsel_armed_mask);
  }
}

/* Re-arm event select mechanism after a write to watch for WRITE events.
** Only call when send() returns WSAEWOULDBLOCK.
*/
ci_inline void citp_evsel_arm_write(citp_socket* ep, ci_fd_t fd)
{
  ci_assert( ep );
  if (ep->s->evsel_mask & CI_EV_WRITE) {
    ep->s->evsel_armed_mask |= CI_EV_WRITE;
    ciul_event_trigger_arm(ep, fd, CI_SOCK_TRIGGER_EVENT_SELECT_IDX,
                           ep->s->evsel_armed_mask);
  }
}

#endif	/* !__KERNEL__ */

#ifdef __KERNEL__

ci_inline void ci_event_trigger_wakeup(tcp_helper_resource_t* thr,
                                       tcp_helper_endpoint_t* ep)
{
  ci_sock_cmn * s;
  unsigned events;
  unsigned index = 0;
  unsigned armed_mask;
  ci_irqlock_state_t lock_state;

  ci_assert( IS_VALID_SOCK_P(&thr->netif, ep->id) );

  s = SP_TO_SOCK(&thr->netif, ep->id);

  /* Set the user's event if the current event state matches any of the event
  ** trigger masks.
  */
  events = ci_sock_cmn_get_current_event_mask(&thr->netif, s);
  for (index = 0; index < CI_SOCK_NUM_EVENT_TRIGGERS; index++) {
    if ( events & oo_atomic_read(&s->trigger_armed_mask[index]) ) {
      ci_irqlock_lock(&ep->event_lock, &lock_state);

      /* De-arm the "reported" events */
      oo_atomic_set(&s->trigger_armed_mask[index], CI_EV_NONE);

      /* Trigger user's event */
      if (ep->trigger_event[index])
        KeSetEvent(ep->trigger_event[index], EVENT_INCREMENT, FALSE);

      ci_irqlock_unlock(&ep->event_lock, &lock_state);
    }
  }
  
  /* Any remaining armed events? */
#if CI_SOCK_NUM_EVENT_TRIGGERS == 2
  armed_mask = oo_atomic_read(&s->trigger_armed_mask[0]) |
               oo_atomic_read(&s->trigger_armed_mask[1]);
#elif CI_SOCK_NUM_EVENT_TRIGGERS == 3
  armed_mask = oo_atomic_read(&s->trigger_armed_mask[0]) |
               oo_atomic_read(&s->trigger_armed_mask[1]) |
               oo_atomic_read(&s->trigger_armed_mask[2]);
#else
#error Fix the re-arm test to match the correct number of triggers
#endif
  if (!armed_mask) return;

  /* Still have armed events, ensure stack notifies us again */
  if (armed_mask & CI_EV_RX_WAKE)
    ci_bit_set(&s->b.wake_request, CI_SB_FLAG_WAKE_RX_B);
  if (armed_mask & CI_EV_TX_WAKE)
    ci_bit_set(&s->b.wake_request, CI_SB_FLAG_WAKE_TX_B);

  /* Re-check the current events as a race-breaker. */
  events = ci_sock_cmn_get_current_event_mask(&thr->netif, s);
  for (index = 0; index < CI_SOCK_NUM_EVENT_TRIGGERS; index++) {
    if ( events & oo_atomic_read(&s->trigger_armed_mask[index]) ) {
      ci_irqlock_lock(&ep->event_lock, &lock_state);

      /* De-arm the "reported" events */
      oo_atomic_set(&s->trigger_armed_mask[index], CI_EV_NONE);

      /* Trigger user's event */
      if (ep->trigger_event[index])
        KeSetEvent(ep->trigger_event[index], EVENT_INCREMENT, FALSE);

      ci_irqlock_unlock(&ep->event_lock, &lock_state);
    }
  } 
}

#endif  /* __KERNEL__ */

#endif  /* __CI_INTERNAL_EVENT_SELECT_H__ */
/*! \cidoxg_end */
