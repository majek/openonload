/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
*//*! \file tips.h
** <L5_PRIVATE L5_HEADER >
** \author  kjm
**  \brief  API for accessing TCP stack
**   \date  2008/08/11
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/


#ifndef __CI_INTERNAL_TIPSONLOAD_H__
#define __CI_INTERNAL_TIPSONLOAD_H__

#include "ci/internal/ip.h"

#include "onload/tcp_helper.h"
#include "onload/tcp_helper_fns.h"

/* Define this to see where code is looking inside these types.  This
 * won't produce a usable bit of code, but will show up where there
 * are problems with type abstraction */
#define TIPS_OPAQUE 0

#if TIPS_OPAQUE

typedef struct tips_stack {
  ci_netif _ni;
} tips_stack;

typedef struct tips_tcp_socket {
  ci_tcp_state _ts;
} tips_tcp_socket;

typedef struct tips_socket {
  citp_socket _ep;

  /* These just let TIPS_OPAQUE compile */
  tips_stack *netif;
  tips_tcp_socket *s;
} tips_socket;

#define TIPS_STACK_TO_NETIF(x) (&((x)->_ni))
#define TIPS_TCP_SOCKET_TO_TCP(x) (&((x)->_ts))
#define TIPS_SOCKET_TO_CITP_SOCKET(x) (&((x)->_ep))

#define TIPS_SOCKET_STACK(x) (x)->netif
#define TIPS_SOCKET_TCP_SOCKET(x) (x)->s

#else

typedef ci_netif tips_stack;
typedef ci_tcp_state tips_tcp_socket;

/* An implementation of tips_socket must provide at least the
 * following structure, or ensure everything uses TIPS_SOCKET_STACK
 * and TIPS_SOCKET_TCP_SOCKET macros to access them in another place:
 * 
 * struct tips_socket {
 *   tips_stack *netif;
 *   tips_tcp_socket *s;
 * }
 */

typedef citp_socket tips_socket;

#define TIPS_STACK_TO_NETIF(x) ((ci_netif *)(x))
#define TIPS_TCP_SOCKET_TO_TCP(x) ((ci_tcp_state *)(x))
#define TIPS_SOCKET_TO_CITP_SOCKET(x) ((citp_socket *)(x))

#define TIPS_SOCKET_STACK(x) (x)->netif
#define TIPS_SOCKET_TCP_SOCKET(x) SOCK_TO_TCP((x)->s);

#endif

ci_inline int tips_stack_ctor(tips_stack **ni, const ci_netif_config_opts *opts,
                              unsigned flags)
{
  return ci_netif_ctor(ni, opts, flags);
}

ci_inline int tips_stack_dtor(tips_stack *ni)
{
  return ci_netif_dtor(TIPS_STACK_TO_NETIF(ni));
}


ci_inline int tips_rx_callback_set(tips_stack *stack, 
                                   void (*fn)(void *arg, int why))
{
  ci_netif *ni = TIPS_STACK_TO_NETIF(stack);
  tcp_helper_resource_t *trs = netif2tcp_helper_resource(ni);
  return efab_tcp_helper_sock_callback_set(trs, fn);
}

ci_inline int tips_rx_callback_arm(tips_stack *stack, tips_tcp_socket *ts, 
                                   void *arg)
{
  ci_netif *ni = TIPS_STACK_TO_NETIF(stack);
  tcp_helper_resource_t *trs = netif2tcp_helper_resource(ni);
  oo_sp sock_id = S_SP(TIPS_TCP_SOCKET_TO_TCP(ts));
  return efab_tcp_helper_sock_callback_arm(trs, sock_id, arg);
}

ci_inline int tips_rx_callback_disarm(tips_stack *stack, tips_tcp_socket *ts)
{
  ci_netif *ni = TIPS_STACK_TO_NETIF(stack);
  tcp_helper_resource_t *trs = netif2tcp_helper_resource(ni);
  oo_sp sock_id = S_SP(TIPS_TCP_SOCKET_TO_TCP(ts));
  return efab_tcp_helper_sock_callback_disarm(trs, sock_id);
}


ci_inline int tips_ep_ctor(tips_socket *ep, tips_stack *ni, 
                           ci_fixed_descriptor_t os_sock_fd)
{
  int rc = ci_tcp_ep_ctor(TIPS_SOCKET_TO_CITP_SOCKET(ep), 
                          TIPS_STACK_TO_NETIF(ni), os_sock_fd);
  /* Do this here as it saves having to add something to the API to
   * allow domain to be set */
  if (rc >= 0)
    TIPS_SOCKET_TO_CITP_SOCKET(ep)->s->domain = AF_INET;
  return rc;
}

ci_inline int tips_connect(tips_socket *ep, const struct sockaddr* serv_addr, 
                           socklen_t addrlen, ci_fd_t fd, int flags)
{
  return ci_tcp_connect(TIPS_SOCKET_TO_CITP_SOCKET(ep), serv_addr, 
                        addrlen, fd, flags);
}

ci_inline int tips_close(tips_socket *ep)
{
  return ci_tcp_close(TIPS_SOCKET_TO_CITP_SOCKET(ep)->netif, 
                      SOCK_TO_TCP(TIPS_SOCKET_TO_CITP_SOCKET(ep)->s));
}

ci_inline int tips_abort(tips_socket *ep)
{
  return ci_tcp_abort(TIPS_SOCKET_TO_CITP_SOCKET(ep));
}

ci_inline void tips_destroy(tips_socket *ep)
{
  ci_netif *ni = TIPS_SOCKET_TO_CITP_SOCKET(ep)->netif;
  tcp_helper_resource_t *trs = netif2tcp_helper_resource(ni);
  unsigned ep_id = SC_ID(TIPS_SOCKET_TO_CITP_SOCKET(ep)->s);

  return efab_tcp_helper_close_endpoint(trs, ep_id);
}

typedef ci_tcp_recvmsg_args tips_recvmsg_args;

ci_inline void tips_recvmsg_args_init(ci_tcp_recvmsg_args *a,
                                      tips_stack *ni, tips_tcp_socket *ts,
                                      struct msghdr *msg, int flags,
                                      ci_addr_spc_t addr_spc)
{
  return ci_tcp_recvmsg_args_init(a, TIPS_STACK_TO_NETIF(ni), 
                                  TIPS_TCP_SOCKET_TO_TCP(ts), 
                                  msg, flags, addr_spc);
}

ci_inline int tips_recvmsg(const tips_recvmsg_args *a)
{
  return ci_tcp_recvmsg(a);
}

ci_inline int tips_recvmsg_get(const tips_recvmsg_args* a, ci_iovec_ptr* piov)
{
  return ci_tcp_recvmsg_get(a, piov);
}

ci_inline int tips_async_tx(tips_stack *ni, tips_tcp_socket *ts, 
                            struct ci_mem_desc *desc_array, int array_length, 
                            int total_entries, int *flags)
{
  return ci_async_tcp_iscsi_tx(TIPS_STACK_TO_NETIF(ni), 
                               TIPS_TCP_SOCKET_TO_TCP(ts), desc_array,
                               array_length, total_entries, flags);
}

/* Following may not be necessary on lwIP as most cases will use the
 * tips_async_tx call */
ci_inline int tips_sendmsg(tips_stack *ni, tips_tcp_socket* ts,
                           const struct msghdr* msg, 
                           int flags, ci_addr_spc_t addr_spc)
{
  return ci_tcp_sendmsg(TIPS_STACK_TO_NETIF(ni), TIPS_TCP_SOCKET_TO_TCP(ts),
                        msg, flags, addr_spc);
}


ci_inline int tips_stack_lock(tips_stack *ni)
{
  return ci_netif_lock(TIPS_STACK_TO_NETIF(ni));
}

ci_inline void tips_stack_unlock(tips_stack *ni)
{
  return ci_netif_unlock(TIPS_STACK_TO_NETIF(ni));
}

ci_inline int tips_stack_trylock(tips_stack *ni)
{
  return ci_netif_trylock(TIPS_STACK_TO_NETIF(ni));
}

ci_inline int tips_stack_is_locked(tips_stack *ni)
{
  return ci_netif_is_locked(TIPS_STACK_TO_NETIF(ni));
}


ci_inline struct oo_timeval *tips_socket_get_rcvtimeo(tips_socket *ep)
{
  return &TIPS_SOCKET_TO_CITP_SOCKET(ep)->s->so.rcvtimeo;
}

ci_inline struct oo_timeval *tips_socket_get_sndtimeo(tips_socket *ep)
{
  return &TIPS_SOCKET_TO_CITP_SOCKET(ep)->s->so.sndtimeo;
}

ci_inline int tips_socket_set_rcvtimeo(tips_socket *ep, ci_uint32 timeout)
{
  ci_bit_set(&TIPS_SOCKET_TO_CITP_SOCKET(ep)->s->s_aflags,
             CI_SOCK_AFLAG_RCVTIMEO_BIT);
  TIPS_SOCKET_TO_CITP_SOCKET(ep)->s->so.rcvtimeo.tv_sec = 
    (ci_int32)(timeout / 1000);
  TIPS_SOCKET_TO_CITP_SOCKET(ep)->s->so.rcvtimeo.tv_usec = 
    (ci_int32)((timeout % 1000) * 1000);
  return 0;
}

ci_inline int tips_socket_set_sndtimeo(tips_socket *ep, ci_uint32 timeout)
{
  ci_bit_set(&TIPS_SOCKET_TO_CITP_SOCKET(ep)->s->s_aflags,
             CI_SOCK_AFLAG_SNDTIMEO_BIT);
  TIPS_SOCKET_TO_CITP_SOCKET(ep)->s->so.sndtimeo.tv_sec = 
    (ci_int32)(timeout / 1000);
  TIPS_SOCKET_TO_CITP_SOCKET(ep)->s->so.sndtimeo.tv_usec =
    (ci_int32)((timeout % 1000) * 1000);
  return 0;
}

ci_inline int tips_socket_set_localport(tips_socket *ep, ci_uint16 localPort)
{
  S_TCP_HDR(TIPS_SOCKET_TO_CITP_SOCKET(ep)->s)->tcp_source_be16 =
    CI_BSWAP_16(localPort);
  TIPS_SOCKET_TO_CITP_SOCKET(ep)->s->s_flags |= CI_SOCK_FLAG_BOUND;
  return 0;
}


ci_inline ci_uint32 tips_tcp_rcv_usr(tips_tcp_socket *ts, tips_stack *ni)
{
  return tcp_rcv_usr(TIPS_TCP_SOCKET_TO_TCP(ts));
}

ci_inline ci_uint32 tips_tcp_eff_mss(tips_tcp_socket *ts)
{
  return tcp_eff_mss(TIPS_TCP_SOCKET_TO_TCP(ts));
}

ci_inline ci_uint16 tips_tcp_adv_mss(tips_tcp_socket *ts)
{
  return TIPS_TCP_SOCKET_TO_TCP(ts)->c.amss;
}

ci_inline ci_int32 tips_get_tcp_rcvlowat(tips_tcp_socket *ts)
{
  return TIPS_TCP_SOCKET_TO_TCP(ts)->s.so.rcvlowat;
}

ci_inline int tips_set_tcp_rcvlowat(tips_tcp_socket *ts, ci_int32 rcvlowat)
{
  TIPS_TCP_SOCKET_TO_TCP(ts)->s.so.rcvlowat = rcvlowat;
  return 0;
}

ci_inline ci_uint32 tips_tcp_state(tips_tcp_socket *ts)
{
  return TIPS_TCP_SOCKET_TO_TCP(ts)->s.b.state;
}



struct tips_stack_stats {
  unsigned n_fails;
#ifndef NDEBUG
  unsigned n_allocs;
  unsigned n_frees;
#endif
};

ci_inline int tips_stack_get_stats(tips_stack *ni, struct tips_stack_stats *out)
{
  out->n_fails = (unsigned int)
    oo_atomic_read(&TIPS_STACK_TO_NETIF(ni)->state->aop_alloc_failures);
#ifndef NDEBUG
  out->n_allocs = (unsigned int)TIPS_STACK_TO_NETIF(ni)->state->aop_allocs;
  out->n_frees = (unsigned int)TIPS_STACK_TO_NETIF(ni)->state->aop_frees;
#endif
  return 0;
}



ci_inline int tips_stack_id(tips_stack *ni)
{
  /* May want to do this the other way around.  ie. define NI_ID to
   * return tips_stack_id() when compiling for tips and then the
   * onload and lwIP versions can be defined there.  Has the advantage
   * that we wouldn't have to change existing users of NI_ID if
   * tips_stack type is more opaque */
  return NI_ID(TIPS_STACK_TO_NETIF(ni));
}

#endif /* __CI_INTERNAL_TIPSONLOAD_H__ */
