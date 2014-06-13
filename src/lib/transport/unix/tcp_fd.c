/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
** <L5_PRIVATE L5_SOURCE>
** \author  djr/ctk
**  \brief  Sockets interface to user level TCP
**   \date
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_unix */

#define _GNU_SOURCE /* for recvmmsg */

#include "internal.h"
#include "ul_poll.h"
#include "ul_select.h"
#include <netinet/in.h>
#include <ci/internal/transport_config_opt.h>
#include <ci/internal/transport_common.h>
#include <ci/internal/ip.h>
#include <onload/ul.h>
#include <onload/tcp_poll.h>
#include <onload/ul/tcp_helper.h>
#include <onload/osfile.h>


#define LPF      "citp_tcp_"

int sock_cloexec_broken = 0;

static int
citp_tcp_socket(int domain, int type, int protocol)
{
  citp_fdinfo* fdi;
  citp_sock_fdi* epi;
  int fd, rc;
  ci_netif* ni;

  Log_VSS(ci_log(LPF "socket(%d, %d, %d)", domain, type, protocol));

  epi = CI_ALLOC_OBJ(citp_sock_fdi);
  if( ! epi ) {
    Log_E(ci_log(LPF "socket: failed to allocate epi"));
    errno = ENOMEM;
    goto fail1;
  }
  fdi = &epi->fdinfo;
  citp_fdinfo_init(fdi, &citp_tcp_protocol_impl);

  rc = citp_netif_alloc_and_init(&fd, &ni);
  if( rc != 0 ) {
    if( rc == CI_SOCKET_HANDOVER ) {
      /* This implies EF_DONT_ACCELERATE is set, so we handover
       * regardless of CITP_OPTS.no_fail */
      CI_FREE_OBJ(fdi);
      return rc;
    }
    goto fail2;
  }

  /* Protect the fdtable entry until we're done initialising. */
  if( fdtable_strict() )  CITP_FDTABLE_LOCK();
  if((fd = ci_tcp_ep_ctor( &epi->sock, ni, domain, type)) < 0) {
    Log_U(ci_log(LPF "socket: tcp_ep_ctor failed"));
    errno = -fd;
    goto fail3;
  }

  citp_fdtable_new_fd_set(fd, fdip_busy, fdtable_strict());
  if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();

  CI_DEBUG(epi->sock.s->pid = getpid());

  /* We're ready.  Unleash us onto the world! */
  ci_assert(epi->sock.s->b.sb_aflags & CI_SB_AFLAG_NOT_READY);
  ci_atomic32_and(&epi->sock.s->b.sb_aflags, ~CI_SB_AFLAG_NOT_READY);
  citp_fdtable_insert(fdi, fd, 0);

  Log_VSS(ci_log(LPF "socket(%d, %d, %d) = "EF_FMT, domain,
              type, protocol, NI_ID(ni), SC_FMT(epi->sock.s), fd));
  return fd;

 fail3:
  if( CITP_OPTS.no_fail && errno != ELIBACC )
    CITP_STATS_NETIF(++ni->state->stats.tcp_handover_socket);
  citp_netif_release_ref(ni, 0);
 fail2:
  CI_FREE_OBJ(epi);
 fail1:
  /* BUG1408: Fail gracefully. We let the OS have a go at this so long as it's
   * not been caused by a driver/library mis-match */
  if( CITP_OPTS.no_fail && errno != ELIBACC ) {
    Log_U(ci_log("%s: failed (errno:%d) - PASSING TO OS", __FUNCTION__, errno));
    return CI_SOCKET_HANDOVER;
  }
  return -1;
}


static citp_fdinfo* citp_tcp_dup(citp_fdinfo* orig_fdi)
{
  citp_socket* orig_sock = fdi_to_socket(orig_fdi);
  citp_sock_fdi* sock_fdi = CI_ALLOC_OBJ(citp_sock_fdi);
  if( sock_fdi ) {
    citp_fdinfo_init(&sock_fdi->fdinfo, &citp_tcp_protocol_impl);
    sock_fdi->sock = *orig_sock;
    citp_netif_add_ref(orig_sock->netif);
    return &sock_fdi->fdinfo;
  }
  return 0;
}

ci_inline ci_uint64 linger_hash(ci_sock_cmn* s)
{
  return (ci_uint64)(sock_lport_be16(s) << 16) |
         (ci_uint64)sock_rport_be16(s) |
         ((ci_uint64)sock_raddr_be32(s) << 32);
}

static void citp_tcp_dtor(citp_fdinfo* fdinfo, int fdt_locked)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  ci_sock_cmn* s = epi->sock.s;

  /* Check for SO_LINGER: if !CI_SB_AFLAG_IN_SO_LINGER or hash mismatch,
   * then close worked perferctly and we have nothing to wait for. */
  if( epi->sock.so_linger_hash != 0 &&
      linger_hash(s) == epi->sock.so_linger_hash &&
      s->b.sb_aflags & CI_SB_AFLAG_IN_SO_LINGER &&
      (s->b.state & CI_TCP_STATE_TCP) && s->b.state != CI_TCP_LISTEN ) {
    ci_tcp_linger(epi->sock.netif, SOCK_TO_TCP(s));
  }
  citp_netif_release_ref(epi->sock.netif, fdt_locked);
}


#if CI_CFG_FD_CACHING
static void citp_tcp_cached_dtor(citp_fdinfo* fdi, int fdt_locked)
{
  /* ?? FIXME: We're not holding the netif lock, so we can't touch this.
  ** Is it better to manipulate this count when kernel fd is closed? */
  ++fdi_to_socket(fdi)->netif->state->epcache_n;

  citp_tcp_dtor(fdi, fdt_locked);
}
#endif


static void tcp_handover(citp_sock_fdi* sock_fdi)
{
  /* The O_NONBLOCK flag is not propagated to the O/S socket, so we have to
  ** fix it up when we handover.
  */
  ci_sock_cmn* s = sock_fdi->sock.s;
  int nonb_switch = -1;

  if( s->b.state == CI_TCP_LISTEN ) {
    /* O/S socket is already has O_NONBLOCK.  Turn it off? */
    if( ! (s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK) )
      nonb_switch = 0;
  }
  else if( s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK )
    nonb_switch = 1;

  citp_fdinfo_handover(&sock_fdi->fdinfo, nonb_switch);
}


static int citp_tcp_bind(citp_fdinfo* fdinfo, const struct sockaddr* sa,
                         socklen_t sa_len)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  int rc;

#if !CI_CFG_FAKE_IPV6
  Log_VSS(const struct sockaddr_in* sai = (const struct sockaddr_in*) sa;
          ci_log(LPF "bind("EF_FMT", %s:%d, %d)", EF_PRI_ARGS(epi, fdinfo->fd),
              (sai != NULL) ? ip_addr_str(sai->sin_addr.s_addr) : "(null)",
              (sai != NULL) ? CI_BSWAP_BE16(sai->sin_port) : 0, sa_len));
#endif

  ci_netif_lock_fdi(epi);
  rc = ci_tcp_bind(&epi->sock, sa, sa_len, fdinfo->fd);
  ci_netif_unlock_fdi(epi);
  if( rc == CI_SOCKET_HANDOVER ) {
    int fd = fdinfo->fd;
    CITP_STATS_NETIF(++epi->sock.netif->state->stats.tcp_handover_bind);
    tcp_handover(epi);
    return ci_sys_bind(fd, sa, sa_len);
  }
  citp_fdinfo_release_ref(fdinfo, 0);
  return rc;
}


static int citp_tcp_listen(citp_fdinfo* fdinfo, int backlog)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  int rc;
  int fcntl_result;

  Log_VSS(ci_log(LPF "listen("EF_FMT", %d)", EF_PRI_ARGS(epi,fdinfo->fd),
              backlog));

  ci_netif_lock_fdi(epi);
  rc = ci_tcp_listen(&(epi->sock), fdinfo->fd, backlog);
  ci_netif_unlock_fdi(epi);

  if( rc == CI_SOCKET_HANDOVER ||
      ((rc < 0) && (errno == ENOMEM || errno == EBUSY || errno == ENOBUFS)) ) {
    /* ENOMEM or EBUSY means we are out of some sort of resource, so hand
     * this socket over to the OS.  We need to listen on the OS socket
     * first (that's the very last thing that ci_tcp_listen() does, so it
     * won't have happened yet).
     */
    rc = ci_tcp_helper_listen_os_sock(fdinfo->fd, backlog);
    CITP_STATS_NETIF(++epi->sock.netif->state->stats.tcp_handover_listen);
    tcp_handover(epi);
    return rc;
  }

  /* When doing accept(), we should not block on OS socket */
  if (apply_fcntl_to_os_sock(epi, fdinfo->fd, F_GETFL, 0,
                             &fcntl_result) >= 0) {
    CI_TRY(apply_fcntl_to_os_sock(epi, fdinfo->fd, F_SETFL,
                                  fcntl_result | O_NONBLOCK, &fcntl_result));
  } else {
    Log_U(ci_log(LPF "No OS sock found under listening socket"));
  }

  citp_fdinfo_release_ref( fdinfo, 0 );
  return rc;
}


static int citp_tcp_accept_os(citp_sock_fdi* epi, int fd,
                              struct sockaddr* sa, socklen_t* p_sa_len,
                              int flags)
{
  int rc;

  rc = oo_os_sock_accept(epi->sock.netif, SC_SP(epi->sock.s),
                         sa, p_sa_len, flags);
  Log_VSS(ci_log(LPF "accept("EF_FMT", sa, %d) = SYSTEM FD %d",
                 EF_PRI_ARGS(epi,fd), p_sa_len ? *p_sa_len:-1, rc));
  if( rc >= 0 )
    citp_fdtable_passthru(rc, 0);
  else
    CI_SET_ERROR(rc, -rc);
  return rc;
}


static int citp_tcp_accept_complete(ci_netif* ni,
                                    struct sockaddr* sa, socklen_t* p_sa_len,
                                    ci_tcp_socket_listen* listener,
                                    ci_tcp_state* ts, int newfd)
{
  CITP_STATS_NETIF(++ni->state->stats.ul_accepts);

  if( sa ) {
    ci_addr_to_user(sa, p_sa_len, ts->s.domain, 
                    TS_TCP(ts)->tcp_dest_be16, ts->s.pkt.ip.ip_daddr_be32);
  }

  Log_VSS(ci_log(LPF "%d ACCEPTING %d %s:%u rcv=%08x-%08x snd=%08x-%08x-%08x "
             "enq=%08x", S_FMT(listener), S_FMT(ts),
             ip_addr_str(ts->s.pkt.ip.ip_daddr_be32),
             (unsigned) CI_BSWAP_BE16(TS_TCP(ts)->tcp_dest_be16),
             tcp_rcv_nxt(ts), tcp_rcv_wnd_right_edge_sent(ts),
             tcp_snd_una(ts), tcp_snd_nxt(ts), ts->snd_max,
             tcp_enq_nxt(ts)));

  /* Considered safe to take inode/uid from listening socket */
  ts->s.ino = listener->s.ino;
  ts->s.uid = listener->s.uid;
  CI_DEBUG(ts->s.pid = getpid());

  return newfd;
}


static int citp_tcp_accept_alien(ci_netif* ni, ci_tcp_socket_listen* listener,
                                 struct sockaddr* sa, socklen_t* p_sa_len,
                                 int flags, citp_waitable* w)
{
  struct oo_alien_ep *aep = &CI_CONTAINER(citp_waitable_obj,
                                          waitable, w)->alien;
  ci_netif *ani;
  oo_sp sp = aep->sock_id;
  ci_uint32 stack_id = aep->stack_id;
  int locked = fdtable_strict();
  citp_sock_fdi* newepi;
  citp_fdinfo* newfdi;
  citp_waitable *neww;
  ci_tcp_state* ts;
  int newfd, rc;

  ci_netif_lock(ni);
  citp_waitable_obj_free(ni, w);
  ci_netif_unlock(ni);

  rc = citp_netif_by_id(stack_id, &ani);
  if( rc != 0 ) {
    struct oo_op_tcp_drop_from_acceptq op;
    /* free the zombie:
     * ci_tcp_send_rst(stack_id, sp)
     * ci_tcp_drop(stack_id, sp) */
    op.stack_id = stack_id;
    op.sock_id = sp;
    ci_sys_ioctl(ci_netif_get_driver_handle(ni),
                 OO_IOC_TCP_DROP_FROM_ACCEPTQ, &op);
    CI_SET_ERROR(rc, -rc);
    return -1;
  }
  ci_assert(ani);

  newfd = ci_tcp_helper_sock_attach(ci_netif_get_driver_handle(ani),
                                    sp, AF_UNSPEC, flags);
  if( newfd < 0 ) {
    if( locked )  CITP_FDTABLE_UNLOCK();
    return -1;
  }
  citp_fdtable_new_fd_set(newfd, fdip_busy, locked);
  if( locked )  CITP_FDTABLE_UNLOCK();
  Log_EP(ci_log("%s: %d:%d accepted fd=%d %d:%d", __FUNCTION__,
                ni->state->stack_id, S_ID(listener), newfd,
                ani->state->stack_id, OO_SP_TO_INT(sp)));

  /* Check that this ts looks in the way we expect;
   * there is no guarantee that it is the same stack it used to be. */
  neww = SP_TO_WAITABLE(ani, sp);
  if( !(neww->state & CI_TCP_STATE_TCP) || neww->state == CI_TCP_LISTEN ) {
    errno = EINVAL;
    goto fail;
  }

  ts = SP_TO_TCP(ani, sp);
  if( sock_lport_be16(&ts->s) != sock_lport_be16(&listener->s) ||
      (sock_laddr_be32(&listener->s) != INADDR_ANY &&
       (sock_laddr_be32(&listener->s) !=  sock_laddr_be32(&ts->s)) )) {
    errno = EINVAL;
    goto fail;
  }

  ci_assert(!(ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN));
  ci_assert(!(ts->s.b.sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ));

  newepi = CI_ALLOC_OBJ(citp_sock_fdi);
  if( newepi == 0 ) {
    errno = ENOMEM;
    goto fail;
  }
  newfdi = &newepi->fdinfo;
  citp_fdinfo_init(newfdi, &citp_tcp_protocol_impl);
#if CI_CFG_FD_CACHING
  newfdi->can_cache = 0;
#endif
  newepi->sock.s = &ts->s;
  newepi->sock.netif = ani;

  /* get new file descriptor into table */
  ci_assert(newepi->sock.s->b.sb_aflags & CI_SB_AFLAG_NOT_READY);
  ci_atomic32_and(&newepi->sock.s->b.sb_aflags, ~CI_SB_AFLAG_NOT_READY);
  citp_fdtable_insert(newfdi, newfd, 0);
  return citp_tcp_accept_complete(ni, sa, p_sa_len, listener, ts, newfd);

fail:
    Log_E (ci_log(LPF "failed to get accepted socket from alien stack [%d]:"
                  " errno=%d", NI_ID(ani), errno));
  ef_onload_driver_close(newfd);
  citp_netif_release_ref(ani, 0);
  return -1;
}


#if CI_CFG_FD_CACHING

/* Accept a socket that is cached.  Returns -1 on error, -2 if socket turns
 * out not to be cached.  >= 0 indicates success and return value is the
 * new fd.
 */
static int citp_tcp_accept_cached(citp_fdinfo* fdinfo, ci_netif* ni,
                                  struct sockaddr* sa, socklen_t* p_sa_len,
                                  ci_tcp_socket_listen* listener,
                                  ci_tcp_state* ts, int* newfd_out)
{
  volatile citp_fdinfo_p* p_fdip;
  citp_fdinfo_p fdip;
  citp_fdinfo* newfdi;
  int newfd, rc;

  newfd = ts->cached_on_fd;

  /* If newfd is not -1, it means that we get it off the cache.  Need to
   * check the cached_on_pid to ensure it was cached for our process.
   */
  if( ts->cached_on_pid != getpid() ) {
    /* Cached on another pid -- bring it across to this process */
    Log_EP(ci_log("%s: need xfer from %d:%d", __FUNCTION__,
                  ts->cached_on_pid, ts->cached_on_fd));
    rc = ci_tcp_helper_xfer_cached(fdinfo->fd, S_SP(ts),
                                   ts->cached_on_pid, newfd);
    if( rc == -ESRCH ) {
      /* This means that the cached_on_pid process no longer exists.  This
       * means it's currently being cleaned up, and all the cached EPs will
       * shortly be destroyed.  So, we can't use the cached EP for this
       * connection.
       */
      Log_EP(ci_log("%s: not found: assuming uncached", __FUNCTION__));
      *newfd_out = ts->cached_on_fd = -1;
      return -1;
    }
    else if( rc < 0 ) {
      return rc;
    }
    else {
      if( fdtable_strict() )  CITP_FDTABLE_LOCK();
      *newfd_out = rc;
      ts->cached_on_pid = getpid();
      citp_fdtable_new_fd_set(newfd, fdip_busy, fdtable_strict());
      Log_EP(ci_log("%s: accepted fd=%d (cached)", __FUNCTION__, newfd));
      if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
    }
  }

  /* We're reusing a cached socket, we don't attach; merely change its
  ** state.
  */
  ci_atomic32_and(&ts->s.b.sb_aflags,
                  ~(CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ));
  ts->cached_on_fd = -1;

  /* There is probably a race here with the cached fd being closed by
  ** another thread in this process.  Wants to reorg to sort nicely.
  */
  Log_EP(ci_log("%s: fd=%d from cache", __FUNCTION__, newfd));

  ci_assert_ge(newfd, 0);

  p_fdip = &citp_fdtable.table[newfd].fdip;
  fdip = *p_fdip;
 fdip_again:
  if( fdip_is_busy(fdip) )  fdip = citp_fdtable_busy_wait(newfd, 0);
  if( fdip_cas_fail(p_fdip, fdip, fdip_busy) )  goto fdip_again;

  ci_assert(fdip_is_normal(fdip));
  newfdi = fdip_to_fdi(fdip);
  ci_assert(newfdi != &citp_the_closed_fd);
  ci_assert(newfdi->fd == newfd);
  ci_assert(newfdi->is_cached);
  ci_assert(newfdi->can_cache);
  ci_assert(newfdi->is_special);

  /* This fd is no longer cached */
  newfdi->is_special = newfdi->is_cached = 0;
  /* Put back the protocol ops to the TCP ones */
  ci_assert (newfdi->protocol == &citp_tcp_cached_protocol_impl);
  newfdi->protocol = &citp_tcp_protocol_impl;
  citp_fdtable_busy_clear(newfd, fdip, 0);

  return citp_tcp_accept_complete(ni, sa, p_sa_len, listener, ts, newfd);
}

#endif


static int citp_tcp_accept_ul(citp_fdinfo* fdinfo, ci_netif* ni,
			      ci_tcp_socket_listen* listener,
			      struct sockaddr* sa, socklen_t* p_sa_len,
                              int flags)
{
  citp_sock_fdi* newepi;
  citp_fdinfo* newfdi;
  ci_tcp_state* ts;
  citp_waitable* w;
  int newfd;

  Log_VSS(ci_log(LPF "accept(%d:%d, sa, %d)", fdinfo->fd,
                 S_FMT(listener), p_sa_len ? *p_sa_len : -1));

  /* Pop the socket off the accept queue. */
  ci_assert(ci_sock_is_locked(ni, &listener->s.b));
  ci_assert(ci_tcp_acceptq_not_empty(listener));
  w = ci_tcp_acceptq_get(ni, listener);
  ci_sock_unlock(ni, &listener->s.b);

  if( w->state == CI_TCP_STATE_ALIEN )
    return citp_tcp_accept_alien(ni, listener, sa, p_sa_len, flags, w);

  ci_assert(w->state & CI_TCP_STATE_TCP);
  ci_assert(w->state != CI_TCP_LISTEN);
  ts = &CI_CONTAINER(citp_waitable_obj, waitable, w)->tcp;
  newfd = -1;

#if CI_CFG_FD_CACHING
  if( ci_tcp_is_cached(ts) ) {
    int rc = citp_tcp_accept_cached(fdinfo, ni, sa, p_sa_len,
                                    listener, ts, &newfd);
    if( rc != -2 )
      return rc;
  }
#endif

  if( newfd < 0 ) {
    /* Need to create new fd */
    if( fdtable_strict() )  CITP_FDTABLE_LOCK();
    newfd = ci_tcp_helper_sock_attach(ci_netif_get_driver_handle(ni),
                                      S_SP(ts), AF_UNSPEC, flags);
    if( newfd < 0 ) {
      Log_E(ci_log(LPF "%s: ci_tcp_helper_sock_attach %d",
                   __FUNCTION__, newfd));
      if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
      ci_sock_lock(ni, &listener->s.b);
      ci_assert(ts->s.b.sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ);
      ci_tcp_acceptq_put_back(ni, listener, &ts->s.b);
      CITP_STATS_TCP_LISTEN(++listener->stats.n_accept_no_fd);
      ci_sock_unlock(ni, &listener->s.b);
      return -1;
    }
    citp_fdtable_new_fd_set(newfd, fdip_busy, fdtable_strict());
    Log_EP(ci_log("%s: accepted fd=%d (not cached)", __FUNCTION__, newfd));
    if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
  }

  /* ts didn't come from cache, or it was for another process.  Either way,
   * we need to create the u/l state for the fd (i.e. fdinfo).
   */
  ci_assert(!(ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN));
  ci_assert(!(ts->s.b.sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ));

  newepi = CI_ALLOC_OBJ(citp_sock_fdi);
  if( newepi == 0 ) {
    Log_E (ci_log(LPF "accept: newepi malloc failed"));
    ef_onload_driver_close(newfd);
    return -1;
  }
  newfdi = &newepi->fdinfo;
  citp_fdinfo_init(newfdi, &citp_tcp_protocol_impl);
#if CI_CFG_FD_CACHING
  newfdi->can_cache = 1;
#endif
  newepi->sock.s = &ts->s;
  newepi->sock.netif = ni;
  citp_netif_add_ref(ni);

  /* get new file descriptor into table */
  ci_assert(newepi->sock.s->b.sb_aflags & CI_SB_AFLAG_NOT_READY);
  ci_atomic32_and(&newepi->sock.s->b.sb_aflags, ~CI_SB_AFLAG_NOT_READY);
  citp_fdtable_insert(newfdi, newfd, 0);

  return citp_tcp_accept_complete(ni, sa, p_sa_len, listener, ts, newfd);
}


static int citp_tcp_accept(citp_fdinfo* fdinfo,
                           struct sockaddr* sa, socklen_t* p_sa_len,
                           int flags,
                           citp_lib_context_t* lib_context)
{
  ci_tcp_socket_listen* listener;
  citp_sock_fdi* epi;
  ci_netif* ni;
  int have_polled = 0;
  ci_uint64 start_frc = 0 /* for effing stoopid compilers */;
  int rc = 0;
  ci_uint64 max_spin;
  int spin_limit_by_so = 0;
  int timeout;
  unsigned tcp_accept_spin = oo_per_thread_get()->spinstate &
    (1 << ONLOAD_SPIN_TCP_ACCEPT);

  /* check parameters:
   * NULL sockaddr*: Linux and Solaris will still wait for connection;
   * NULL socklen_t*: Linux will wait, Sun gives an error right away;
   * both NULL's are ok. */
  
  epi = fdi_to_sock_fdi(fdinfo);
  ni = epi->sock.netif;

  /* Prepare to spin if necessary */
  max_spin = ni->state->spin_cycles;
  if( epi->sock.s->so.rcvtimeo_msec && tcp_accept_spin ) {
    ci_uint64 max_so_spin = (ci_uint64)epi->sock.s->so.rcvtimeo_msec *
        IPTIMER_STATE(ni)->khz;
    if( max_so_spin <= max_spin ) {
      max_spin = max_so_spin;
      spin_limit_by_so = 1;
    }
  }

check_ul_accept_q:
  if( epi->sock.s->b.state != CI_TCP_LISTEN ) {
    CI_SET_ERROR(rc, EINVAL);
    return rc;
  }
  listener = SOCK_TO_TCP_LISTEN(epi->sock.s);

  if( ci_tcp_acceptq_n(listener) ) {
      ci_sock_lock(ni, &listener->s.b);
      if( ci_tcp_acceptq_not_empty(listener) ) {
          if( CI_UNLIKELY(p_sa_len == NULL && sa != NULL) ) {
              ci_sock_unlock(ni, &listener->s.b);
              CI_SET_ERROR(rc, EFAULT);
              return rc;
          }
          rc = citp_tcp_accept_ul(fdinfo, ni, listener, sa, p_sa_len, flags);
          if( rc < 0 && errno != EMFILE ) {
            CITP_STATS_TCP_LISTEN(++listener->stats.n_accept_loop2_closed);
            ci_log("%s: failed to accept connection: errno=%d",
                   __FUNCTION__, errno);
            ci_log("See limitations of EF_TCP_SERVER_LOOPBACK=2 mode");
            rc = 0;
            goto check_ul_accept_q;
          }
          return rc;
      }
      ci_sock_unlock(ni, &listener->s.b);
  }

  /* User-level accept queue is empty.  Are we up-to-date? */

  if( ! have_polled ) {
    have_polled = 1;
    ci_frc64(&start_frc);
    if( ci_netif_may_poll(ni) && ci_netif_need_poll_frc(ni, start_frc) &&
        ci_netif_trylock(ni) ) {
      int any_evs = ci_netif_poll(ni);
      ci_netif_unlock(ni);
      if( any_evs )  goto check_ul_accept_q;
    }
  }

  /* What about the O/S socket? */
  if( 1 ) {
    if( listener->s.os_sock_status & OO_OS_STATUS_RX ) {
      rc = citp_tcp_accept_os(epi, fdinfo->fd, sa, p_sa_len, flags);
      if( rc >= 0 ) {
	CITP_STATS_TCP_LISTEN(++listener->stats.n_accept_os);
	goto unlock_out;
      }
      if( errno != EAGAIN )  goto unlock_out;
    }
  }

  if( listener->s.b.sb_aflags & (CI_SB_AFLAG_O_NONBLOCK |
                                 CI_SB_AFLAG_O_NDELAY) ) {
    CITP_STATS_NETIF(++ni->state->stats.accept_eagain);
    errno = EAGAIN;
    rc = -1;
    goto unlock_out;
  }

  /* We need to block (optionally spinning first). */

  timeout = listener->s.so.rcvtimeo_msec;
  if( tcp_accept_spin ) {
    ci_uint64 now_frc;
    ci_frc64(&now_frc);
    if( now_frc - start_frc < max_spin ) {
      if( ci_netif_may_poll(ni) && ci_netif_need_poll_frc(ni, now_frc) ) {
	if( ci_netif_trylock(ni) ) {
	  ci_netif_poll(ni);
          ci_netif_unlock(ni);
	}
      }
      else if( ! ni->state->is_spinner )
        ni->state->is_spinner = 1;
      if(CI_UNLIKELY( lib_context->thread->sig.run_pending )) {
        if( listener->s.so.rcvtimeo_msec ) {
          ni->state->is_spinner = 0;
          errno = EINTR;
          return -1;
        }

        /* run any pending signals: */
        citp_exit_lib(lib_context, FALSE);
        citp_reenter_lib(lib_context);

        if( !lib_context->thread->sig.need_restart ) {
          ni->state->is_spinner = 0;
          errno = EINTR;
          return -1;
        }
      }
      goto check_ul_accept_q;
    }

    if( spin_limit_by_so ) {
      errno = EAGAIN;
      return -1;
    }
    if( timeout )
      timeout -= (now_frc - start_frc) / IPTIMER_STATE(ni)->khz;
  }

  {
    struct pollfd pfd;
    pfd.fd = fdinfo->fd;
    pfd.events = POLLIN;

    if( timeout == 0 )
      timeout = -1;

    /* If poll() is interrupted by a signal with the SA_RESTART flag set, it
     * returns EINTR anyway.  However, accept() is supposed to restart.  So, if
     * we detect that a signal with SA_RESTART has fired (by the magic of the
     * signal interception code), we do the restart manually.
     *
     * See also ci_udp_recvmsg().
     */
   restart_select:
    citp_exit_lib(lib_context, FALSE);
    lib_context->thread->sig.need_restart = 1;
    rc = ci_sys_poll(&pfd, 1, timeout);
    citp_reenter_lib(lib_context);

    /* Check if we've been shut down */
    if( listener->s.b.state != CI_TCP_LISTEN ) {
      CI_SET_ERROR(rc, EINVAL);
      return rc;
    }

    if( rc > 0 ) {
      goto check_ul_accept_q;
    }
    else if( rc == 0 ) {
      errno = EAGAIN;
      rc = -1;
    }
    else if( errno == EINTR && lib_context->thread->sig.need_restart &&
             timeout == -1 ) {
      goto restart_select;
    }
  }

 unlock_out:
  ni->state->is_spinner = 0;
  return rc;
}

/* Re-probe fdinfo after endpoint was moved.
 * refcounts is the number of reference counf of fdinfo taken by this code
 * path. */
static citp_fdinfo *citp_reprobe_moved(citp_fdinfo* fdinfo, int from_fast_lookup)
{
  volatile citp_fdinfo_p *p_fdip;
  citp_fdinfo_p fdip;
  int fd = fdinfo->fd;

  CITP_FDTABLE_LOCK();

  p_fdip = &citp_fdtable.table[fd].fdip;
  do {
    fdip = *p_fdip;
    ci_assert(fdip_is_normal(fdip));

    if( fdip_to_fdi(fdip) != fdinfo ) {
      fdinfo = fdip_to_fdi(fdip);
      if( from_fast_lookup )
        citp_fdinfo_ref_fast(fdinfo);
      else
        citp_fdinfo_ref(fdinfo);
      CITP_FDTABLE_UNLOCK();
      return fdinfo;
    }
  } while( fdip_cas_fail(p_fdip, fdip, fdip_unknown) );

  fdinfo->on_ref_count_zero = FDI_ON_RCZ_MOVED;
  /* One refcount from the caller */
  if( from_fast_lookup )
    citp_fdinfo_release_ref_fast(fdinfo);
  else
    citp_fdinfo_release_ref(fdinfo, 1);
  /* One refcount from fdtable */
  citp_fdinfo_release_ref(fdinfo, 1);
  
  /* re-probe new fd */
  fdinfo = citp_fdtable_probe_locked(fd, CI_TRUE);
  CITP_FDTABLE_UNLOCK();
  if( fdinfo == NULL )
    return NULL;

  if( from_fast_lookup ) {
    citp_fdinfo_release_ref(fdinfo, 0);
    citp_fdinfo_ref_fast(fdinfo);
  }

  return fdinfo;
}

static int citp_tcp_connect(citp_fdinfo* fdinfo,
                            const struct sockaddr* sa, socklen_t sa_len,
                            citp_lib_context_t* lib_context)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  int rc;
  int moved = 0;

#if !CI_CFG_FAKE_IPV6
  Log_VSS(const struct sockaddr_in* sai = (const struct sockaddr_in*) sa;
          ci_log(LPF "connect("EF_FMT", %s:%d, %d)",
              EF_PRI_ARGS(epi,fdinfo->fd),
              (sai != NULL) ? ip_addr_str(sai->sin_addr.s_addr) : "(null)",
              (sai != NULL) ? CI_BSWAP_BE16(sai->sin_port) : 0, sa_len));
#endif

  rc = ci_tcp_connect( &epi->sock, sa, sa_len, fdinfo->fd, &moved);

  if( moved ) {
    fdinfo = citp_reprobe_moved(fdinfo, CI_FALSE);
    if( fdinfo == NULL ) {
      /* Most probably, it is EMFILE, but we can't know for sure.
       * And we can't handover since there is no fdinfo now. */
      errno = EMFILE;
      return -1;
    }

    /* Possibly we also should handover.  To do it properly, we need
     * current epi value. */
    epi = fdi_to_sock_fdi(fdinfo);
  }

  if (rc == CI_SOCKET_HANDOVER
      || ((rc < 0) &&
          (errno == ENOMEM || errno == EBUSY || errno == ENOBUFS))) {
    /* Try to connect the OS socket. OS connect also syncs non-blocking
     * state between UL/OS sockets. */
    citp_exit_lib(lib_context, FALSE);
    rc = ci_tcp_helper_connect_os_sock(fdinfo->fd, sa, sa_len);
    citp_reenter_lib(lib_context);
    /* Do handover to OS in the case of success only */
    if( rc == 0 ||
        /* \todo If non-blocking OS connect fails, we may want to connect
         *       via L5 NIC. It will work, but not using UL stack. */
        (((epi->sock.s->b.sb_aflags & (CI_SB_AFLAG_O_NONBLOCK |
                                       CI_SB_AFLAG_O_NDELAY))
          || epi->sock.s->so.sndtimeo_msec) &&
         (errno == EINPROGRESS)) ) {
      int saved_errno = errno;
      CITP_STATS_NETIF(++epi->sock.netif->state->stats.tcp_handover_connect);
      tcp_handover(epi);
      errno = saved_errno;
      return rc;
    }
    else {
      /* binding information may get modified by connection failure */
      int saved_errno = errno;  /* may get trampled in the next calls */
      ci_fd_t fd = ci_get_os_sock_fd( &epi->sock, fdinfo->fd );

      if( fd >= 0 ) {
        union ci_sockaddr_u sa_u;
        socklen_t sa_len = sizeof(sa_u);

        if( ci_sys_getsockname(fd, &sa_u.sa, &sa_len) == 0 ) {
          if( sa_len >= sizeof(struct sockaddr_in) &&
              sa_u.sa.sa_family == AF_INET ) {
            sock_lport_be16(epi->sock.s) = sa_u.sin.sin_port;
#if CI_CFG_FAKE_IPV6
          } else if( sa_len >= sizeof(struct sockaddr_in6) && 
                     sa_u.sa.sa_family == AF_INET6 ) {
            sock_lport_be16(epi->sock.s) = sa_u.sin6.sin6_port;
#endif
          } else {
            Log_U(ci_log("%s: sockaddr from getsockname() len:%d, fam:%d",
              __FUNCTION__, sa_len, sa_u.sa.sa_family));
          }
        }
        ci_rel_os_sock_fd(fd);
      }

      errno = saved_errno;
      epi->sock.s->tx_errno = EPIPE;

      epi->sock.s->rx_errno = ENOTCONN;
    }
  }
  citp_fdinfo_release_ref( fdinfo, 0 );
  return rc;
}


#if CI_CFG_FD_CACHING

static void citp_tcp_cached_protocol_impl_init(void)
{
  citp_tcp_cached_protocol_impl.ops = citp_closed_protocol_impl.ops;
  citp_tcp_cached_protocol_impl.ops.dtor = citp_tcp_cached_dtor;
}


static ci_boolean_t can_cache_fd(ci_netif* ni, int fd)
{
  return (oo_resource_op(ci_netif_get_driver_handle(ni),
                         OO_IOC_TCP_CAN_CACHE_FD, &fd) == 0);
}


static int citp_tcp_close_cached(citp_fdinfo* fdinfo)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  ci_sock_cmn* s = epi->sock.s;
  ci_netif* ni = epi->sock.netif;
  ci_tcp_state* ts = SOCK_TO_TCP(s);
  int ni_locked;

  ci_assert(ts->cached_on_fd == -1);

  if( (ni_locked = ci_netif_trylock(ni)) && ni->state->epcache_n > 0 ) {
    unsigned laddr = sock_laddr_be32(s);
    unsigned lport = sock_lport_be16(s);
    int rc = ci_netif_filter_lookup(ni, laddr, lport, 0,0, sock_protocol(s));
    if( rc >= 0 ) {
      ci_tcp_socket_listen* tlo =
        SP_TO_TCP_LISTEN(ni, CI_NETIF_FILTER_ID_TO_SOCK_ID(ni, rc));

      /* Check reference-counts.  We may only cache an FD if no-one else is
      ** using it -- i.e. ref count in of file object in kernel is exactly
      ** 1.
      */
#define DANGEROUS_CACHING  0
      if( DANGEROUS_CACHING || can_cache_fd(ni, fdinfo->fd) ) {
        ni->state->epcache_n--;

        /* Setting the TCP-state's 'fd' field means that this tcp-state
         * will be cached, associated with this fd.
         */
        ts->cached_on_fd = fdinfo->fd;
        ts->cached_on_pid = getpid();
        Log_EP(ci_log ("Pushing fd %d (pid %u) on to pending list",
                       fdinfo->fd, (unsigned) getpid()));
        ci_ni_dllist_push (ni, &tlo->epcache_pending, &ts->epcache_link);

        /* Now close the connection */
/*XXX missing errorcheck? */
        ci_tcp_close(ni, ts, 1);

        fdinfo->is_special = fdinfo->is_cached = 1;

        /* Swizzle the ops of this fd to be the closed ops.  i.e. any
         * operations on it will return EBADF
         */
        ci_assert (fdinfo->protocol == &citp_tcp_protocol_impl);
        if( citp_tcp_cached_protocol_impl.ops.dtor == 0 )
          citp_tcp_cached_protocol_impl_init();
        fdinfo->protocol = &citp_tcp_cached_protocol_impl;

        /* And we're done; unlock and out... */
        ci_netif_unlock_fdi(epi);
        return 1;  /* Indicate to caller fd is cached */
      }

      /* We are not able to cache the FD.  This probably means someone else
       * is using it (i.e. its ref-count in the kernel was > 1).  Oh well.
       * Return 0, telling our caller that it's closed at UL, but not
       * cached
       */
      Log_EP(log("FD %d not cached - kernel ref-count non-zero", fdinfo->fd));
    }
    else
      Log_EP(ci_log("FD %d not cached - no listening socket", fdinfo->fd));
  }
  else
    Log_EP(log("FD %d not cached - cache full / locked (%d)",
               fdinfo->fd, ni_locked));

  if( ni_locked )
    ci_netif_unlock(ni);

  return 0;
}

#endif


/* Close a user-level file-descriptor.
 * If this function returns 0, the fd is closed.
 * A return of 1 means the fd is closed in user-space, but it's tcp EP is
 * cached (the fd will only be reused on a subsequent accept).
 * The usual "-ve error code for failure" applies
 */
static int citp_tcp_close(citp_fdinfo* fdinfo, int may_cache)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  ci_sock_cmn* s = epi->sock.s;
  int rc = 0;

  /* SO_LINGER is handled in-kernel */
  if( s->b.state != CI_TCP_LISTEN && (s->s_flags & CI_SOCK_FLAG_LINGER) ) {
    epi->sock.so_linger_hash = linger_hash(s);
    may_cache = 0;
  }
  else
    epi->sock.so_linger_hash = 0;

#if CI_CFG_FD_CACHING
  /* Note: if this is a listening socket, we don't need to uncache any
   * cached EPs that belong to this listening socket here.  Instead we
   * leave this to __ci_tcp_listen_shutdown, which will uncache everything
   * there (this way we're consistent with a close due to application
   * exit). The user-level state will be cleared up lazily - when the
   * kernel gives us an fd for which we have an fdinfo that is cached, we
   * unpick user-level state there.
   */
  if( may_cache && fdinfo->can_cache &&
      epi->sock.netif->state->epcache_n > 0 &&
      ((s->b.state == CI_TCP_ESTABLISHED) ||
       (s->b.state == CI_TCP_CLOSE_WAIT)) ) {
    rc = citp_tcp_close_cached(fdinfo);
  }
  else
    Log_EP(log("FD %d not cached - not in suitable state - state 0x%x",
               fdinfo->fd, s->b.state));
#endif

  Log_VSS(ci_log(LPF "close("EF_FMT")", EF_PRI_ARGS(epi, fdinfo->fd)));
  return rc;
}


static int citp_tcp_shutdown(citp_fdinfo* fdinfo, int how)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  int rc;

  Log_VSS(ci_log(LPF "shutdown("EF_FMT", %d)", EF_PRI_ARGS(epi,fdinfo->fd), how));
  rc = ci_tcp_shutdown(&(epi->sock), how, fdinfo->fd);
  return rc;
}


static int citp_tcp_getsockname(citp_fdinfo* fdinfo,
                                struct sockaddr* sa, socklen_t* p_sa_len)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);

  Log_VSC(ci_log(LPF "getsockname("EF_FMT")", EF_PRI_ARGS(epi,fdinfo->fd)));
  __citp_getsockname(epi->sock.s, sa, p_sa_len);
  return 0;
}


static int citp_tcp_getpeername(citp_fdinfo* fdinfo,
                                struct sockaddr* sa, socklen_t* p_sa_len)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  int rc;

  Log_VSC(ci_log(LPF "getpeername("EF_FMT")", EF_PRI_ARGS(epi,fdinfo->fd)));
  ci_netif_lock_fdi(epi);
  rc = ci_tcp_getpeername(&epi->sock, sa, p_sa_len);
  ci_netif_unlock_fdi(epi);
  return rc;
}


static int citp_tcp_getsockopt(citp_fdinfo* fdinfo, int level,
                               int optname, void* optval, socklen_t* optlen)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  int rc;

  Log_VSC(ci_log(LPF "getsockopt("EF_FMT", %d, %d)",
              EF_PRI_ARGS(epi,fdinfo->fd), level, optname));

  ci_netif_lock_count(epi->sock.netif, getsockopt_ni_lock_contends);
  rc = ci_tcp_getsockopt(&epi->sock, fdinfo->fd,
                         level, optname, optval, optlen);
  ci_netif_unlock_fdi(epi);
  return rc;
}


static int citp_tcp_setsockopt(citp_fdinfo* fdinfo, int level,
                       int optname, const void* optval, socklen_t optlen)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  int rc;

  Log_VSC(ci_log(LPF "setsockopt("EF_FMT", %d, %d)",
              EF_PRI_ARGS(epi,fdinfo->fd), level, optname));

  rc = ci_tcp_setsockopt(&epi->sock, fdinfo->fd,
			 level, optname, optval, optlen);

  if( rc == CI_SOCKET_HANDOVER ) {
    CITP_STATS_NETIF(++epi->sock.netif->state->stats.tcp_handover_setsockopt);
    /* Here is the only point where we try to handover listening socket.
     * Do not do it!  For already-listening socket, we have reference to
     * its OS socket from our accepted sockets.  So, we should be able to
     * shutdown OS socket when user thinks he is closing it.
     *
     * Hence, we just remove filters and wash our hands, but do not
     * handover. */
    if( epi->sock.s->b.state == CI_TCP_LISTEN ) {
      ci_tcp_helper_ep_clear_filters(
                            ci_netif_get_driver_handle(epi->sock.netif),
                            SC_SP(epi->sock.s));
      citp_fdinfo_release_ref(fdinfo, 0);
      return 0;
    }
    else if( epi->sock.s->b.state == CI_TCP_CLOSED ) {
      tcp_handover(epi);
      return 0;
    }
    else /* Can't handover connected socket */
      RET_WITH_ERRNO(EINVAL);
  }

  citp_fdinfo_release_ref(fdinfo, 0);
  return rc;
}


static int citp_tcp_recv(citp_fdinfo* fdinfo, struct msghdr* msg, int flags)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  ci_tcp_recvmsg_args a;
  int rc;

  if (epi->sock.s->b.sb_aflags & (CI_SB_AFLAG_O_NONBLOCK|CI_SB_AFLAG_O_NDELAY))
    flags |= MSG_DONTWAIT;

  Log_V(ci_log(LPF "recv("EF_FMT", len=%d, "CI_SOCKCALL_FLAGS_FMT")",
            EF_PRI_ARGS(epi,fdinfo->fd),
            ci_iovec_bytes(msg->msg_iov, msg->msg_iovlen),
            CI_SOCKCALL_FLAGS_PRI_ARG(flags)));

  if( ~epi->sock.s->b.state & CI_TCP_STATE_TCP ) {
    fdinfo = citp_reprobe_moved(fdinfo, CI_TRUE);
    if( fdinfo == NULL ) {
      if( msg->msg_namelen != 0 || msg->msg_controllen != 0 ||
          msg->msg_flags != 0 ) {
        errno = ENOTSOCK;
        return -1;
      }
      return ci_sys_readv(fdinfo->fd, msg->msg_iov, msg->msg_iovlen);
    }
    epi = fdi_to_sock_fdi(fdinfo);
  }

  if( epi->sock.s->b.state != CI_TCP_LISTEN ) {
    if (msg->msg_iovlen == 0 || msg->msg_iov == NULL)
      return 0;
    ci_tcp_recvmsg_args_init(&a, epi->sock.netif, SOCK_TO_TCP(epi->sock.s),
                             msg, flags);
    rc = ci_tcp_recvmsg(&a);
    Log_V(ci_log(LPF "recv("EF_FMT") = %d", EF_PRI_ARGS(epi, fdinfo->fd), rc));
    return rc;
  }

  CI_SET_ERROR(rc, SOCK_RX_ERRNO(epi->sock.s));
  Log_V(ci_log(LPF "recv("EF_FMT") = %d", EF_PRI_ARGS(epi, fdinfo->fd), rc));
  return rc;
}


#if CI_CFG_RECVMMSG
static int citp_tcp_recvmmsg(citp_fdinfo* fdinfo, struct mmsghdr* msg, 
                             unsigned vlen, int flags, 
                             const struct timespec *timeout)
{
  Log_E(ci_log("%s: TCP fd recvmmsg not supported by OpenOnload",
               __FUNCTION__));
  errno = ENOSYS;
  return -1;
}
#endif

#if CI_CFG_SENDMMSG
static int citp_tcp_sendmmsg(citp_fdinfo* fdinfo, struct mmsghdr* msg, 
                             unsigned vlen, int flags)
{
  Log_E(ci_log("%s: TCP fd sendmmsg not supported by OpenOnload",
               __FUNCTION__));
  errno = ENOSYS;
  return -1;
}
#endif

static int citp_tcp_send(citp_fdinfo* fdinfo, const struct msghdr* msg,
                         int flags)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  int rc;

  if( ~epi->sock.s->b.state & CI_TCP_STATE_TCP ) {
    fdinfo = citp_reprobe_moved(fdinfo, CI_TRUE);
    if( fdinfo == NULL ) {
      if( msg->msg_namelen != 0 || msg->msg_controllen != 0 ||
          msg->msg_flags != 0 ) {
        errno = ENOTSOCK;
        return -1;
      }
      return ci_sys_writev(fdinfo->fd, msg->msg_iov, msg->msg_iovlen);
    }
    epi = fdi_to_sock_fdi(fdinfo);
  }

  ci_assert(msg != NULL);

  if( epi->sock.s->b.sb_aflags & (CI_SB_AFLAG_O_NONBLOCK |
                                  CI_SB_AFLAG_O_NDELAY) ) {
    flags |= MSG_DONTWAIT;
  }

  if(CI_LIKELY( msg->msg_iov != NULL && msg->msg_iovlen > 0 &&
                (msg->msg_namelen == 0 || msg->msg_name != NULL) )) {
    Log_V(ci_log(LPF "send("EF_FMT", len=%d, "CI_SOCKCALL_FLAGS_FMT")",
                 EF_PRI_ARGS(epi,fdinfo->fd),
                 ci_iovec_bytes(msg->msg_iov, msg->msg_iovlen),
                 CI_SOCKCALL_FLAGS_PRI_ARG(flags)));
    if( epi->sock.s->b.state != CI_TCP_LISTEN ) {
      rc = ci_tcp_sendmsg(epi->sock.netif, SOCK_TO_TCP(epi->sock.s),
                          msg, flags); 
    }
    else {
      errno = epi->sock.s->tx_errno;
      rc = -1;
    }
  }
  else if( msg != NULL && msg->msg_iovlen == 0 ) {
    if( epi->sock.s->tx_errno ) {
      errno = epi->sock.s->tx_errno;
      rc = -1;
    }
    else {
      rc = 0;
    }
  }
  else {
    errno = EFAULT;
    rc = -1;
  }

  if( rc == -1 && errno == EPIPE && ! (flags & MSG_NOSIGNAL) ) {
    ci_sys_ioctl(ci_netif_get_driver_handle(epi->sock.netif), 
                 OO_IOC_KILL_SELF_SIGPIPE, NULL);
  }
  Log_V(log(LPF "send("EF_FMT") = %d", EF_PRI_ARGS(epi,fdinfo->fd),rc));
  return rc;
}


static int citp_tcp_fcntl(citp_fdinfo* fdinfo, int cmd, long arg)
{
  return citp_sock_fcntl(fdi_to_sock_fdi(fdinfo), fdinfo->fd, cmd, arg);
}


static int citp_tcp_ioctl(citp_fdinfo* fdinfo, int request, void* arg)
{
  citp_sock_fdi *epi = fdi_to_sock_fdi(fdinfo);
  int rc;

  Log_VSC(ci_log(LPF "ioctl("EF_FMT", %d, %#lx)",
              EF_PRI_ARGS(epi,fdinfo->fd),
              request, (long) arg));
  rc = ci_tcp_ioctl(&epi->sock, fdinfo->fd, request, arg);
  Log_VSC(ci_log(LPF "ioctl: "EF_FMT" rc=%d", EF_PRI_ARGS(epi,fdinfo->fd),rc));
  if( rc < -1 )
    CI_SET_ERROR(rc, -rc);
  return rc;
}


#if CI_CFG_USERSPACE_SELECT

/* ATTENTION! This function should be kept is sync with 
 * ci_tcp_poll_events_listen() and ci_tcp_poll_events_nolisten() */
static int citp_tcp_select(citp_fdinfo* fdi, int* n, int rd, int wr, int ex,
                           struct oo_ul_select_state*__restrict__ ss)
{
  citp_sock_fdi *epi = fdi_to_sock_fdi(fdi);
  ci_sock_cmn* s = epi->sock.s;
  ci_netif* ni = epi->sock.netif;

  citp_poll_if_needed(ni, ss->now_frc, ss->ul_select_spin);

  /* Fast path: CI_TCP_LISTEN or
   * CI_TCP_ESTABLISHED || CI_TCP_CLOSE_WAIT.
   * Everything else goes via ci_tcp_poll_events_nolisten() */
  if( ( s->b.state & (CI_TCP_STATE_SYNCHRONISED | CI_TCP_STATE_CAN_FIN)) ==
        (CI_TCP_STATE_SYNCHRONISED | CI_TCP_STATE_CAN_FIN) ) {
    if( rd && ci_tcp_recv_not_blocked(SOCK_TO_TCP(s)) ) {
        FD_SET(fdi->fd, ss->rdu);
        ++*n;
    }
    if( wr && ci_tcp_tx_advertise_space(ni, SOCK_TO_TCP(s)) ) {
        FD_SET(fdi->fd, ss->wru);
        ++*n;
    }
    if( ex && tcp_urg_data(SOCK_TO_TCP(s)) & CI_TCP_URG_IS_HERE ) {
      FD_SET(fdi->fd, ss->exu);
      ++*n;
    }
  }
  else if( s->b.state == CI_TCP_LISTEN ) {
    if( rd && ci_tcp_poll_events_listen(ni, SOCK_TO_TCP_LISTEN(s)) ) {
      FD_SET(fdi->fd, ss->rdu);
      ++*n;
    }
  }
  else {
    /* slow path: instead of copying ci_tcp_poll_events_nolisten(), just
     * call it. */
    unsigned mask = ci_tcp_poll_events_nolisten(ni, SOCK_TO_TCP(s));
    if( rd && (mask & SELECT_RD_SET) ) {
      FD_SET(fdi->fd, ss->rdu);
      ++*n;
    }
    if( wr && (mask & SELECT_WR_SET) ) {
      FD_SET(fdi->fd, ss->wru);
      ++*n;
    }
    if( ex && (mask & SELECT_EX_SET) ) {
      FD_SET(fdi->fd, ss->exu);
      ++*n;
    }
  }

  return 1;
}


static int citp_tcp_poll(citp_fdinfo*__restrict__ fdi,
                         struct pollfd*__restrict__ pfd,
                         struct oo_ul_poll_state*__restrict__ ps)
{
  citp_sock_fdi *epi = fdi_to_sock_fdi(fdi);
  ci_sock_cmn* s = epi->sock.s;
  ci_netif* ni = epi->sock.netif;
  unsigned mask;

  if( s->b.state != CI_TCP_LISTEN )
    mask = ci_tcp_poll_events_nolisten(ni, SOCK_TO_TCP(s));
  else
    mask = ci_tcp_poll_events_listen(ni, SOCK_TO_TCP_LISTEN(s));
  pfd->revents = mask & (pfd->events | POLLERR | POLLHUP);
  if( pfd->revents == 0 )
    if( citp_poll_if_needed(ni, ps->this_poll_frc, ps->ul_poll_spin) ) {
      if( s->b.state != CI_TCP_LISTEN )
        mask = ci_tcp_poll_events_nolisten(ni, SOCK_TO_TCP(s));
      else
        mask = ci_tcp_poll_events_listen(ni, SOCK_TO_TCP_LISTEN(s));
      pfd->revents = mask & (pfd->events | POLLERR | POLLHUP);
    }

  return 1;
}

#endif /*CI_CFG_USERSPACE_SELECT*/


#if CI_CFG_USERSPACE_EPOLL
#include "ul_epoll.h"
/* More-or-less copy of citp_tcp_poll */
static void citp_tcp_epoll(citp_fdinfo*__restrict__ fdi,
                           struct citp_epoll_member*__restrict__ eitem,
                           struct oo_ul_epoll_state*__restrict__ eps)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdi);
  ci_sock_cmn* s = epi->sock.s;
  ci_netif* ni = epi->sock.netif;
  ci_uint64 sleep_seq;
  ci_uint32 mask;

  /* Try to return a result without polling if we can. */
  sleep_seq = s->b.sleep_seq.all;
  if( s->b.state != CI_TCP_LISTEN )
    mask = ci_tcp_poll_events_nolisten(ni, SOCK_TO_TCP(s));
  else
    mask = ci_tcp_poll_events_listen(ni, SOCK_TO_TCP_LISTEN(s));
  if( ! citp_ul_epoll_set_ul_events(eps, eitem, mask, sleep_seq) )
    if( citp_poll_if_needed(ni, eps->this_poll_frc, eps->ul_epoll_spin) ) {
      sleep_seq = s->b.sleep_seq.all;
      if( s->b.state != CI_TCP_LISTEN )
        mask = ci_tcp_poll_events_nolisten(ni, SOCK_TO_TCP(s));
      else
        mask = ci_tcp_poll_events_listen(ni, SOCK_TO_TCP_LISTEN(s));
      citp_ul_epoll_set_ul_events(eps, eitem, mask, sleep_seq);
    }
}
#endif /*CI_CFG_USERSPACE_EPOLL*/


#if CI_CFG_SENDFILE
/*!
 * TCP post hook of the sendfile() system call.  Checks whether the send
 * queue needs to be advanced to push out enqueued data.
 *
 * \param out_fdinfo   output file descriptor information
 */
static void citp_tcp_sendfile_post_hook(citp_fdinfo* out_fdinfo)
{
 citp_socket* ep = fdi_to_socket(out_fdinfo);

  if( ep->s->b.state & CI_TCP_STATE_TCP_CONN ) {
    ci_tcp_state* ts = SOCK_TO_TCP(ep->s);
    /* Do the basic check first: avoid locking unless we really need to. */
    if( ts->tcpflags & CI_TCPT_FLAG_ADVANCE_NEEDED ) {
      ci_ip_pkt_queue* sendq = &ts->send;
      ci_netif* ni = ep->netif;
      Log_V(ci_log(LPF "sendfile_post_hook(0x%lx)", (unsigned long)out_fdinfo));
      ci_netif_lock(ni);
      CHECK_TEP(ep);
      ts->tcpflags &=~ CI_TCPT_FLAG_ADVANCE_NEEDED;
      if(CI_LIKELY( ts->s.tx_errno == 0 && ! ci_ip_queue_is_empty(sendq) ))
        ci_tcp_tx_advance(ts, ni);
      ci_netif_unlock(ni);
    }
  }
}
#endif


static int citp_tcp_zc_send(citp_fdinfo* fdi, struct onload_zc_mmsg* msg, 
                            int flags)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdi);
  ci_netif* ni = epi->sock.netif;
  ci_tcp_state *ts = SOCK_TO_TCP(epi->sock.s);
  int rc = 0;

  if( epi->sock.s->b.state != CI_TCP_LISTEN ) {
    if( flags & ~ONLOAD_ZC_SEND_FLAGS_MASK ) {
      msg->rc = -EINVAL;
      rc = 1;
    }
    
    if( epi->sock.s->b.sb_aflags & (CI_SB_AFLAG_O_NONBLOCK | 
                                    CI_SB_AFLAG_O_NDELAY) ) 
      flags |= MSG_DONTWAIT;

    rc = ci_tcp_zc_send(ni, ts, msg, flags);
  }
  else {
    msg->rc = -epi->sock.s->tx_errno;
    rc = 1;
  }

  ci_assert_equal(rc, 1);
  if( msg->rc == -EPIPE && ! (flags & MSG_NOSIGNAL) ) {
    ci_sys_ioctl(ci_netif_get_driver_handle(epi->sock.netif), 
                 OO_IOC_KILL_SELF_SIGPIPE, NULL);
  }
  return rc;
}


static int citp_tcp_zc_recv(citp_fdinfo* fdi, struct onload_zc_recv_args* args)
{
  return -EOPNOTSUPP;
}


static int citp_tcp_recvmsg_kernel(citp_fdinfo* fdi, struct msghdr *msg, 
                                   int flags)
{
  return -EOPNOTSUPP;
}


static int citp_tcp_zc_recv_filter(citp_fdinfo* fdi, 
                                   onload_zc_recv_filter_callback filter,
                                   void* cb_arg, int flags)
{
#if CI_CFG_ZC_RECV_FILTER
  return -EOPNOTSUPP;
#else
  return -ENOSYS;
#endif
}


int citp_tcp_tmpl_alloc(citp_fdinfo* fdi, struct iovec* initial_msg,
                        int mlen, struct oo_msg_template** omt_pp,
                        unsigned flags)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdi);
  ci_tcp_state* ts = SOCK_TO_TCP(epi->sock.s);
  ci_netif* ni = epi->sock.netif;

  ci_assert(ts->s.b.state != CI_TCP_LISTEN);
  return ci_tcp_tmpl_alloc(ni, ts, omt_pp, initial_msg, mlen, flags);
}


int citp_tcp_tmpl_update(citp_fdinfo* fdi, struct oo_msg_template* omt,
                         struct onload_template_msg_update_iovec* updates,
                         int ulen, unsigned flags)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdi);
  ci_tcp_state* ts = SOCK_TO_TCP(epi->sock.s);
  ci_netif* ni = epi->sock.netif;

  ci_assert(ts->s.b.state != CI_TCP_LISTEN);
  return ci_tcp_tmpl_update(ni, ts, omt, updates, ulen, flags);
}


int citp_tcp_tmpl_abort(citp_fdinfo* fdi, struct oo_msg_template* omt)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdi);
  ci_tcp_state* ts = SOCK_TO_TCP(epi->sock.s);
  ci_netif* ni = epi->sock.netif;

  ci_assert(ts->s.b.state != CI_TCP_LISTEN);
  return ci_tcp_tmpl_abort(ni, ts, omt);
}


citp_protocol_impl citp_tcp_protocol_impl = {
  .type        = CITP_TCP_SOCKET,
  .ops         = {
    .socket             = citp_tcp_socket,
    .dtor               = citp_tcp_dtor,
    .dup                = citp_tcp_dup,
    .bind               = citp_tcp_bind,
    .listen             = citp_tcp_listen,
    .accept             = citp_tcp_accept,
    .connect            = citp_tcp_connect,
    .close              = citp_tcp_close,
    .shutdown           = citp_tcp_shutdown,
    .getsockname        = citp_tcp_getsockname,
    .getpeername        = citp_tcp_getpeername,
    .getsockopt         = citp_tcp_getsockopt,
    .setsockopt         = citp_tcp_setsockopt,
    .recv               = citp_tcp_recv,
#if CI_CFG_RECVMMSG
    .recvmmsg           = citp_tcp_recvmmsg,
#endif
    .send               = citp_tcp_send,
#if CI_CFG_SENDMMSG
    .sendmmsg           = citp_tcp_sendmmsg,
#endif
    .fcntl              = citp_tcp_fcntl,
    .ioctl              = citp_tcp_ioctl,
#if CI_CFG_USERSPACE_SELECT
    .select             = citp_tcp_select,
    .poll               = citp_tcp_poll,
#if CI_CFG_USERSPACE_EPOLL
    .epoll              = citp_tcp_epoll,
#endif
#endif
#if CI_CFG_SENDFILE
    .sendfile_post_hook = citp_tcp_sendfile_post_hook,
#endif
    .zc_send            = citp_tcp_zc_send,
    .zc_recv            = citp_tcp_zc_recv,
    .zc_recv_filter     = citp_tcp_zc_recv_filter,
    .recvmsg_kernel     = citp_tcp_recvmsg_kernel,
    .tmpl_alloc         = citp_tcp_tmpl_alloc,
    .tmpl_update        = citp_tcp_tmpl_update,
    .tmpl_abort         = citp_tcp_tmpl_abort,
  }
};

citp_protocol_impl citp_tcp_cached_protocol_impl = {
  .type        = -1,
  /* ops are initialised when this is first used. */
};

/*! \cidoxg_end */
