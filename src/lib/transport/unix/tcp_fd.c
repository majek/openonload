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
#include <onload/extensions.h>


#define LPF      "citp_tcp_"

int sock_cloexec_broken = 0;

#if CI_CFG_FD_CACHING
int ci_tcp_close(ci_netif* netif, ci_tcp_state* ts);
#endif


#ifndef __ci_driver__
#if CI_CFG_FD_CACHING
#ifdef O_CLOEXEC
#define CI_CACHE_FIXUP_FLAGS (O_NONBLOCK | O_CLOEXEC)
#else
#define CI_CACHE_FIXUP_FLAGS (O_NONBLOCK)
#endif

static int
citp_tcp_cached_fixup_flags(ci_netif* ni, ci_tcp_state* ts, int fd, int flags)
{
  int current_flags = 0;
  int new_flags;
  int rc = 0;

  /* Socket caching is only supported on linux, where these are identical */
  CI_BUILD_ASSERT(O_NONBLOCK == O_NDELAY);

  if( !!(flags & O_NONBLOCK) != 
      !!(ts->s.b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK) ) {
    /* Get current flags */
    current_flags = ci_sys_fcntl(fd, F_GETFL);

    if( current_flags >= 0 ) {
      /* Add or remove O_NONBLOCK flag */
      new_flags = flags & O_NONBLOCK ? (current_flags | O_NONBLOCK) :
                                       (current_flags & ~O_NONBLOCK);

      /* Set new value */
      rc = ci_sys_fcntl(fd, F_SETFL, new_flags);

      /* Flip the value of the onload flag */
      if( rc == 0 )
        ci_atomic32_merge(&ts->s.b.sb_aflags, ~ts->s.b.sb_aflags,
                          CI_SB_AFLAG_O_NONBLOCK | CI_SB_AFLAG_O_NDELAY);
      else
        NI_LOG(ni, RESOURCE_WARNINGS, "%s: Failed to modify O_NONBLOCK setting"
               " of cached socket to new value", __FUNCTION__);
    }
    else {
      NI_LOG(ni, RESOURCE_WARNINGS, "%s: Failed to modify O_NONBLOCK setting "
             "of cached socket to new value", __FUNCTION__);
    }
  }

#ifdef O_CLOEXEC
  if( !!(flags & O_CLOEXEC) != 
      !!(ts->s.b.sb_aflags & CI_SB_AFLAG_O_CLOEXEC) ) {
    /* Set new value */
    rc = ci_sys_fcntl(fd, F_SETFD, (flags & O_CLOEXEC) ? FD_CLOEXEC : 0);

    /* Flip the value of the onload flag */
    if( rc == 0 )
      ci_atomic32_merge(&ts->s.b.sb_aflags, ~ts->s.b.sb_aflags,
                        CI_SB_AFLAG_O_CLOEXEC);
    else
      NI_LOG(ni, RESOURCE_WARNINGS, "%s: Failed to modify O_CLOEXEC setting of"
             " cached socket to new value", __FUNCTION__);
  }
#endif

  return rc;
}
#endif


/* When initialising an endpoint, either from scratch or from an accept queue,
 * we need to get hold of an fd.  Given a TCP state, this function gets an fd
 * for it and associates them with one another.  If the TCP state was taken
 * from the cache, then it might have an fd already available; otherwise, we go
 * into the kernel to get one.  In either case, the fd will be marked as busy
 * on return from this function.
 *     [listener] serves only to identify whether the socket for which we need
 * an fd is passive-open.  It should be NULL otherwise.
 *     This function may take the fdtable lock, and so the caller must not
 * hold the stack lock.
 */
static ci_fd_t citp_tcp_ep_acquire_fd(ci_netif* netif, ci_tcp_state* ts,
                                      ci_tcp_socket_listen* listener,
                                      int domain, int type, int flags)
{
  ci_fd_t fd;
#if CI_CFG_FD_CACHING
  int from_cache;
#endif

  /* As well as protecting the explicit fdtable operations that follow, the
   * fdtable lock prevents a probe of the new fd until we've finished setting
   * it up. */
  if( fdtable_strict() )  CITP_FDTABLE_LOCK();

#if CI_CFG_FD_CACHING
  from_cache = ci_tcp_is_cached(ts);

  /* It is possible that someone is concurrently trying to dup2/3 onto the
   * cached fd we're using.  We need to ensure that the NO_FD flag does not
   * change once we've decided we don't need an fd, so mark the fdtable entry
   * as busy.
   *
   * This is similar to the case with non-cached fds between return from the
   * accept ioctl, and setting the entry in the fdtable when not using
   * EF_FDTABLE_STRICT=1, so if we're requiring that apps that might be doing
   * this set that option anyway in the non-caching case, we may want to
   * consider only doing this check if fdtable_strict()...
   */
  if( (from_cache != 0) &&
      !(ts->s.b.sb_aflags & CI_SB_AFLAG_IN_CACHE_NO_FD) ) {
    int prev = citp_fdtable_new_fd_set(ts->cached_on_fd, fdip_busy,
                                       fdtable_strict());

    /* Now we're in one of two states:
     * - there was dup2/3 in progress onto our fd, but it's now completed
     * - there was no dup2/3 in progress, and one can't happen until we
     *   clear the busy state of the fd
     * This means that we can safely use the CI_SB_AFLAG_IN_CACHE_NO_FD flag.
     */
    if( ts->s.b.sb_aflags & CI_SB_AFLAG_IN_CACHE_NO_FD )
      citp_fdtable_busy_clear(ts->cached_on_fd, prev, fdtable_strict());
  }

  if( (from_cache == 0) || (ts->s.b.sb_aflags & CI_SB_AFLAG_IN_CACHE_NO_FD) ) {
#endif
    /* Need to create new fd */
    ci_fd_t stack_fd = ci_netif_get_driver_handle(netif);
    oo_sp sp = S_SP(ts);
    fd = ( listener != NULL ) ?
      ci_tcp_helper_tcp_accept_sock_attach(stack_fd, sp, flags) :
      ci_tcp_helper_sock_attach(stack_fd, sp, domain, type);
    if( fd < 0 ) {
      if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
      return fd;
    }

    citp_fdtable_new_fd_set(fd, fdip_busy, fdtable_strict());
#if CI_CFG_FD_CACHING
  }
  else {
    /* Caching is unsupported but not disabled after fork(), so it is possible
     * to hit this assertion, but we definitely want to catch it as it will
     * definitely break things.  For the active-open cache, we do an explicit
     * pid check and so in that case we should not trigger this assertion. */
    ci_assert_equal(ts->cached_on_pid, getpid());

    fd = ts->cached_on_fd;

   /* It's possible that the cached socket has different flags from those
    * requested - if so we need to sort that out.
    */
    citp_tcp_cached_fixup_flags(netif, ts, fd, flags);

   /* We're reusing a cached socket.  We don't attach, but need to set the
    * flags that would be set on attach.  We also clear the cached_on_fd
    * state.
    *
    * This state must be consistent before we add the entry to the fdtable.
    */
    ci_atomic32_and(&ts->s.b.sb_aflags,
                    ~(CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ |
                      CI_SB_AFLAG_IN_CACHE | CI_SB_AFLAG_IN_PASSIVE_CACHE));
    ts->cached_on_fd = -1;
    ts->cached_on_pid = -1;
  }
#endif

  if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();

  /* By this point, [ts] should have had its cache bit cleared. */
  ci_assert(! ci_tcp_is_cached(ts));

  return fd;
}


/* Called where some initialisation is needed, but not a full construction. */
ci_fd_t ci_tcp_ep_ctor(citp_socket* ep, ci_netif* netif, int domain, int type)
{
  ci_tcp_state* ts;
  ci_fd_t fd;

  ci_assert(ep);
  ci_assert(netif);

  ci_netif_lock(netif);
  ts = ci_tcp_get_state_buf_from_cache(netif);
  if( ts == NULL )
    ts = ci_tcp_get_state_buf(netif);
#if ! CI_CFG_FD_CACHING
  else
    ci_assert(0);
#endif

  ci_netif_unlock(netif);

  if( ts == NULL ) {
    LOG_E(ci_log("%s: [%d] out of socket buffers", __FUNCTION__,NI_ID(netif)));
    return -ENOMEM;
  }

  fd = citp_tcp_ep_acquire_fd(netif, ts, NULL, domain, type,
                              type
#if CI_CFG_FD_CACHING
                              & CI_CACHE_FIXUP_FLAGS
#endif
                              );
  if( fd < 0 ) {
    if( fd == -EAFNOSUPPORT )
      LOG_U(ci_log("%s: citp_tcp_ep_acquire_fd (domain=%d, type=%d) failed %d",
                   __FUNCTION__, domain, type, fd));
    else
      LOG_E(ci_log("%s: citp_tcp_ep_acquire_fd (domain=%d, type=%d) failed %d",
                   __FUNCTION__, domain, type, fd));
    return fd;
  }

  /* The fd is marked busy, so we still have the unique reference to [ts]. */

  ci_assert(~ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN);
  /* Apply default sockbuf sizes now we've updated them from the kernel
   ** defaults. */
  ts->s.so.sndbuf = NI_OPTS(netif).tcp_sndbuf_def;
  ts->s.so.rcvbuf = NI_OPTS(netif).tcp_rcvbuf_def;
  ep->netif = netif;
  ep->s = &ts->s;

#ifndef NDEBUG
  /* We hold the only reference to [ep] and its fd is marked busy, so its
   * validity is not contingent on the netif lock, but CHECK_TEP also validates
   * the netif itself.*/
  ci_netif_lock(netif);
  CHECK_TEP(ep);
  ci_netif_unlock(netif);
#endif

  return fd;
}
#endif


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
#if CI_CFG_FD_CACHING
  fdi->can_cache = 1;
#endif

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

  if((fd = ci_tcp_ep_ctor( &epi->sock, ni, domain, type)) < 0) {
    Log_U(ci_log(LPF "socket: tcp_ep_ctor failed"));
    errno = -fd;
    goto fail3;
  }

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


citp_fdinfo* citp_tcp_dup(citp_fdinfo* orig_fdi)
{
  citp_socket* orig_sock = fdi_to_socket(orig_fdi);
  citp_sock_fdi* sock_fdi = CI_ALLOC_OBJ(citp_sock_fdi);
  if( sock_fdi ) {
    citp_fdinfo_init(&sock_fdi->fdinfo, orig_fdi->protocol);
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
  citp_netif_release_ref(epi->sock.netif, fdt_locked);
}


static void tcp_handover(citp_sock_fdi* sock_fdi)
{
  /* The O_NONBLOCK flag is not propagated to the O/S socket, so we have to
  ** fix it up when we handover.
  */
  ci_sock_cmn* s = sock_fdi->sock.s;
  int nonb_switch = -1;

  ci_assert_flags(s->b.sb_aflags, CI_SB_AFLAG_OS_BACKED);

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
  citp_socket* ep = &epi->sock;
  ci_sock_cmn* s = ep->s;
  int rc;

#if !CI_CFG_FAKE_IPV6
  Log_VSS(const struct sockaddr_in* sai = (const struct sockaddr_in*) sa;
          ci_log(LPF "bind("EF_FMT", %s:%d, %d)", EF_PRI_ARGS(epi, fdinfo->fd),
              (sai != NULL) ? ip_addr_str(sai->sin_addr.s_addr) : "(null)",
              (sai != NULL) ? CI_BSWAP_BE16(sai->sin_port) : 0, sa_len));
#endif

  ci_netif_lock_fdi(epi);
  rc = ci_tcp_bind(ep, sa, sa_len, fdinfo->fd);
  ci_netif_unlock_fdi(epi);
  if( rc == CI_SOCKET_HANDOVER ) {
    int fd = fdinfo->fd;

    /* ci_tcp_bind must give us an OS socket if we should have one */
    ci_assert_flags(s->b.sb_aflags, CI_SB_AFLAG_OS_BACKED);

    CITP_STATS_NETIF(++epi->sock.netif->state->stats.tcp_handover_bind);
    tcp_handover(epi);
    fdinfo = citp_fdtable_lookup(fd);
    if( fdinfo == NULL )
      return ci_sys_bind(fd, sa, sa_len);
    else {
      ci_assert_equal( fdinfo->protocol->type, CITP_PASSTHROUGH_FD);
      return citp_passthrough_bind(fdinfo, sa, sa_len);
    }
  }

  if( rc == 0 )
    if( (s->s_flags & CI_SOCK_FLAG_REUSEPORT) != 0 )
      /* If the following fails, we are not undoing the bind() done
       * above as that is non-trivial.  We are still leaving the socket
       * in a working state albeit bound without reuseport set.
       */
      if( (rc = ci_tcp_reuseport_bind(s, fdinfo->fd)) == 0 ) {
        /* The socket has moved so need to reprobe the fd.  This will also
         * map the the new stack into user space of the executing process.
         */
        fdinfo = citp_fdtable_lookup(fdinfo->fd);
        fdinfo = citp_reprobe_moved(fdinfo, CI_FALSE, CI_FALSE);
        epi = fdi_to_sock_fdi(fdinfo);
        ep = &epi->sock;
        ci_netif_cluster_prefault(ep->netif);
      }

  citp_fdinfo_release_ref(fdinfo, 0);
  return rc;
}


static int citp_tcp_listen(citp_fdinfo* fdinfo, int backlog)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  int rc;

  Log_VSS(ci_log(LPF "listen("EF_FMT", %d)", EF_PRI_ARGS(epi,fdinfo->fd),
              backlog));

  if( epi->sock.s->s_flags & CI_SOCK_FLAG_TPROXY ) {
    /* We do not support IP_TRANSPARENT on listening sockets.  If this has
     * already been bound then we're past the point where we should have
     * created the OS socket, otherwise we can just handover.
     *
     * Note that this only applies if EF_SCALABLE_FILTERS is set.  If not,
     * then we hand over sockets as soon as IP_TRANSPARENT is applied.
     */
    NI_LOG(epi->sock.netif, USAGE_WARNINGS, "Listening sockets using socket "
           "option IP_TRANSPARENT cannot be accelerated");
    if( epi->sock.s->s_flags & CI_SOCK_FLAG_CONNECT_MUST_BIND ) {
      rc = CI_SOCKET_HANDOVER;
    }
    else {
      rc = EINVAL;
    }
  }
  else {
    rc = ci_tcp_listen(&(epi->sock), fdinfo->fd, backlog);
  }

  if( rc == CI_SOCKET_HANDOVER ||
      ( (rc < 0) && CITP_OPTS.no_fail &&
        (errno == ENOMEM || errno == EBUSY || errno == ENOBUFS) ) ) {
    /* ENOMEM or EBUSY means we are out of some sort of resource, so hand
     * this socket over to the OS.  We need to listen on the OS socket
     * first (that's the very last thing that ci_tcp_listen() does, so it
     * won't have happened yet).
     */
    ci_netif_lock_fdi(epi);
    rc = ci_tcp_helper_listen_os_sock(fdinfo->fd, backlog);
    ci_netif_unlock_fdi(epi);
    CITP_STATS_NETIF(++epi->sock.netif->state->stats.tcp_handover_listen);
    tcp_handover(epi);
    return rc;
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
  ci_netif *ani;
  oo_sp sp = w->moved_to_sock_id;
  ci_uint32 stack_id = w->moved_to_stack_id;
  citp_sock_fdi* newepi;
  citp_fdinfo* newfdi;
  citp_waitable *neww;
  ci_tcp_state* ts;
  int newfd, rc;

  ci_netif_lock(ni);
  citp_waitable_obj_free(ni, w);
  ci_netif_unlock(ni);

  if( fdtable_strict() )  CITP_FDTABLE_LOCK();

  rc = citp_netif_by_id(stack_id, &ani, fdtable_strict());
  if( rc != 0 ) {
    struct oo_op_tcp_drop_from_acceptq op;
    /* free the zombie:
     * ci_tcp_send_rst(stack_id, sp)
     * ci_tcp_drop(stack_id, sp) */
    if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
    op.stack_id = stack_id;
    op.sock_id = sp;
    ci_sys_ioctl(ci_netif_get_driver_handle(ni),
                 OO_IOC_TCP_DROP_FROM_ACCEPTQ, &op);
    CI_SET_ERROR(rc, -rc);
    return -1;
  }
  ci_assert(ani);

  newfd = ci_tcp_helper_tcp_accept_sock_attach(ci_netif_get_driver_handle(ani),
                                               sp, flags);
  if( newfd < 0 ) {
    if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
    return -1;
  }
  citp_fdtable_new_fd_set(newfd, fdip_busy, fdtable_strict());
  if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
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
#if CI_CFG_FD_CACHING
  int from_cache;
#endif

  Log_VSS(ci_log(LPF "accept(%d:%d, sa, %d)", fdinfo->fd,
                 S_FMT(listener), p_sa_len ? *p_sa_len : -1));

  /* Pop the socket off the accept queue. */
  ci_assert(ci_sock_is_locked(ni, &listener->s.b));
  ci_assert(ci_tcp_acceptq_not_empty(listener));
  w = ci_tcp_acceptq_get(ni, listener);

  if( w->sb_aflags & CI_SB_AFLAG_MOVED_AWAY ) {
    ci_sock_unlock(ni, &listener->s.b);
    return citp_tcp_accept_alien(ni, listener, sa, p_sa_len, flags, w);
  }

  ci_assert(w->state & CI_TCP_STATE_TCP);
  ci_assert(w->state != CI_TCP_LISTEN);
  ts = &CI_CONTAINER(citp_waitable_obj, waitable, w)->tcp;
#if CI_CFG_FD_CACHING
  from_cache = ci_tcp_is_cached(ts);
  ci_ni_dllist_remove_safe(ni, &ts->epcache_fd_link);
#endif
  ci_sock_unlock(ni, &listener->s.b);

  newfd = citp_tcp_ep_acquire_fd(ni, ts, listener, ts->s.domain, SOCK_STREAM,
                                 flags);
  if( newfd < 0 ) {
    Log_E(ci_log(LPF "%s: citp_tcp_ep_acquire_fd failed: %d",
                 __FUNCTION__, newfd));
    ci_sock_lock(ni, &listener->s.b);
    ci_assert(ts->s.b.sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ);
    ci_tcp_acceptq_put_back(ni, listener, &ts->s.b);
    CITP_STATS_TCP_LISTEN(++listener->stats.n_accept_no_fd);
    ci_sock_unlock(ni, &listener->s.b);
    return -1;
  }

  Log_EP(ci_log("%s: accepted fd=%d", __FUNCTION__, newfd));

  /* Whether [ts] came from the cache or not, we need to create the u/l state
   * for the fd (i.e. fdinfo).
   */
  ci_assert(!(ts->s.b.sb_aflags & CI_SB_AFLAG_ORPHAN));
  ci_assert(!(ts->s.b.sb_aflags & CI_SB_AFLAG_TCP_IN_ACCEPTQ));

  newepi = CI_ALLOC_OBJ(citp_sock_fdi);
  if( newepi == 0 ) {
    Log_E (ci_log(LPF "accept: newepi malloc failed"));
    citp_fdtable_busy_clear(newfd, fdip_unknown, 0);
    ci_tcp_helper_close_no_trampoline(newfd);
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

#if CI_CFG_FD_CACHING
  if( from_cache ) {
    ci_atomic32_inc(&ni->state->passive_cache_avail_stack);
    ci_atomic32_inc(&listener->cache_avail_sock);
    ci_assert_le(ni->state->passive_cache_avail_stack,
                 ni->state->opts.sock_cache_max);
    ci_assert_le(listener->cache_avail_sock,
                 ni->state->opts.per_sock_cache_max);
  }
#endif

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
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
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
  
  ni = epi->sock.netif;

  /* Prepare to spin if necessary */
  max_spin = epi->sock.s->b.spin_cycles;
  if( epi->sock.s->so.rcvtimeo_msec && tcp_accept_spin ) {
    ci_uint64 max_so_spin = (ci_uint64)epi->sock.s->so.rcvtimeo_msec *
        IPTIMER_STATE(ni)->khz;
    if( max_so_spin <= max_spin ) {
      max_spin = max_so_spin;
      spin_limit_by_so = 1;
    }
  }

check_ul_accept_q:
  /* Are we still listening or we've been shut down? */
  if( epi->sock.s->b.state != CI_TCP_LISTEN ) {
    CI_SET_ERROR(rc, EINVAL);
    return rc;
  }
  listener = SOCK_TO_TCP_LISTEN(epi->sock.s);

  /* Do we have a error to report? */
  if( (rc = ci_get_so_error(&listener->s)) != 0 ) {
    CI_SET_ERROR(rc, rc);
    return -1;
  }

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
#if CI_CFG_SPIN_STATS
      ni->state->stats.spin_tcp_accept++;
#endif
      if( ci_netif_may_poll(ni) && ci_netif_need_poll_frc(ni, now_frc) ) {
	if( ci_netif_trylock(ni) ) {
	  ci_netif_poll(ni);
          ci_netif_unlock(ni);
	}
      }
      else if( ! ni->state->is_spinner )
        ni->state->is_spinner = 1;
      if(CI_UNLIKELY( lib_context->thread->sig.aflags &
                      OO_SIGNAL_FLAG_HAVE_PENDING )) {
        if( listener->s.so.rcvtimeo_msec ) {
          ni->state->is_spinner = 0;
          errno = EINTR;
          return -1;
        }

        /* run any pending signals: */
        citp_exit_lib(lib_context, FALSE);
        citp_reenter_lib(lib_context);

        if( ~lib_context->thread->sig.aflags & OO_SIGNAL_FLAG_NEED_RESTART ) {
          ni->state->is_spinner = 0;
          errno = EINTR;
          return -1;
        }

        if( oo_atomic_read(&fdinfo->ref_count) == 1 ) {
          ni->state->is_spinner = 0;
          errno = EBADF;
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
    rc = ci_sys_poll(&pfd, 1, timeout);
    citp_reenter_lib(lib_context);

    if( rc > 0 )
      goto check_ul_accept_q;
    else if( rc == 0 ) {
      errno = EAGAIN;
      rc = -1;
    }
    else if( errno == EINTR &&
             (lib_context->thread->sig.aflags & OO_SIGNAL_FLAG_NEED_RESTART) &&
             timeout == -1 ) {
      /* Before restarting because of SA_RESTART, let's check the fd was
       * not closed.  One refcount is ours - so we exit if it is the last
       * one. */
      if( oo_atomic_read(&fdinfo->ref_count) == 1 ) {
        errno = EBADF;
        return -1;
      }
      goto restart_select;
    }
  }

 unlock_out:
  ni->state->is_spinner = 0;
  return rc;
}

static int citp_tcp_connect(citp_fdinfo* fdinfo,
                            const struct sockaddr* sa, socklen_t sa_len,
                            citp_lib_context_t* lib_context)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  ci_sock_cmn* s = epi->sock.s;
  int rc;
  int moved = 0;

#if !CI_CFG_FAKE_IPV6
  Log_VSS(const struct sockaddr_in* sai = (const struct sockaddr_in*) sa;
          ci_log(LPF "connect("EF_FMT", %s:%d, %d)",
              EF_PRI_ARGS(epi,fdinfo->fd),
              (sai != NULL) ? ip_addr_str(sai->sin_addr.s_addr) : "(null)",
              (sai != NULL) ? CI_BSWAP_BE16(sai->sin_port) : 0, sa_len));
#endif


  /* We do not support implicit bind of sockets with IP_TRANSPARENT set.
   * These sockets are expected to be used in one of 2 ways:
   * - active connects using a specific local address and port
   * - listeners with wild ip or port
   * If this is an active connect it must specify a port.  We don't maintain
   * an OS socket, so can't get the port number that way.  If we need to create
   * an OS socket to get the port we'll have to handover.
   */
  if( (s->s_flags & CI_SOCK_FLAG_TPROXY) &&
      (s->s_flags & CI_SOCK_FLAG_CONNECT_MUST_BIND) ) {
    NI_LOG(epi->sock.netif, USAGE_WARNINGS, "Sockets using socket option "
           "IP_TRANSPARENT must explicitly bind to a port to be accelerated");
    rc = CI_SOCKET_HANDOVER;
  }
  else {
    rc = ci_tcp_connect( &epi->sock, sa, sa_len, fdinfo->fd, &moved);
  }

  if( moved ) {
    fdinfo = citp_reprobe_moved(fdinfo, CI_FALSE, CI_FALSE);
    if( fdinfo == NULL ) {
      /* Most probably, it is EMFILE, but we can't know for sure.
       * And we can't handover since there is no fdinfo now. */
      errno = EMFILE;
      return -1;
    }

    /* Possibly we also should handover.  To do it properly, we need
     * current epi value. */
    epi = fdi_to_sock_fdi(fdinfo);
    s = epi->sock.s;
  }

  if (rc == CI_SOCKET_HANDOVER
      || ((rc < 0) && CITP_OPTS.no_fail &&
          (errno == ENOMEM || errno == EBUSY || errno == ENOBUFS))) {
    /* We try to connect the OS socket if we have one, or it's valid to create
     * one.  That means non-tproxy sockets, or tproxy sockets that have not
     * been bound (ie they wouldn't have an os socket even if they weren't
     * tproxy.
     */
    if( !(s->s_flags & CI_SOCK_FLAG_TPROXY) ||
         (s->s_flags & CI_SOCK_FLAG_CONNECT_MUST_BIND) ) {
      rc = 0;
      ci_netif_lock_fdi(epi);
      if( ~epi->sock.s->b.sb_aflags & CI_SB_AFLAG_OS_BACKED ) {
        rc = ci_tcp_helper_os_sock_create_and_set(epi->sock.netif, fdinfo->fd,
                                                  epi->sock.s,
                                                  -1, 0, NULL, 0);
      }
      ci_netif_unlock_fdi(epi);
      if( rc < 0 ) {
        /* Too bad, but we can't do anything.  Return to the user. */
        citp_fdinfo_release_ref( fdinfo, 0 );
        RET_WITH_ERRNO(-rc);
      }

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
        ci_fd_t fd = ci_get_os_sock_fd(fdinfo->fd );

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
    else {
      NI_LOG(epi->sock.netif, USAGE_WARNINGS, "Sockets using socket option "
             "IP_TRANSPARENT cannot be handed over after bind");
    }
  }
  citp_fdinfo_release_ref( fdinfo, 0 );
  return rc;
}


#if CI_CFG_FD_CACHING
static void citp_tcp_close_cached(citp_fdinfo* fdinfo,
                                  ci_socket_cache_t* cache, int active)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  ci_sock_cmn* s = epi->sock.s;
  ci_netif* netif = epi->sock.netif;
  ci_tcp_state* ts = SOCK_TO_TCP(s);

  ci_assert(!ci_tcp_is_cached(ts));

  /* We've decided to cache.  There are two lots of things to do.  Firstly,
   * set up the state needed to cache:
   * - decrement the remaining number of cache spaces
   * - what we're cached on
   * - setting the NOT_READY flag, to avoid incorrect re-probe
   * - pushing onto the cache or pending list
   *
   * Then we need to ensure that the rest of the socket state closely
   * matches what it would be if we weren't caching it.  This means doing
   * similar things to what we would do in citp_waitable_all_fds_gone:
   * - purge the deferred socket list in case this is on it
   * - remove the post_poll link
   * - perform the appropriate tcp protocol options via ci_tcp_close
   * We don't go via citp_waitable_all_fds_gone as we must not set the
   * ORPHAN flag - we remain attached to our fd.
   */
  ci_atomic32_dec((volatile ci_uint32*)CI_NETIF_PTR(netif,
                                                    cache->avail_stack));
  ci_assert_ge(cache->avail_stack, 0);
  ci_assert_lt(*(ci_uint32*)CI_NETIF_PTR(netif, cache->avail_stack),
               netif->state->opts.sock_cache_max);

  ts->cached_on_fd = fdinfo->fd;
  ts->cached_on_pid = getpid();

  ci_assert(!(s->b.sb_aflags & CI_SB_AFLAG_NOT_READY));
  ci_atomic32_or(&s->b.sb_aflags, CI_SB_AFLAG_NOT_READY | CI_SB_AFLAG_IN_CACHE
                                 | (active ? 0 : CI_SB_AFLAG_IN_PASSIVE_CACHE));

  /* If this socket was previously accepted from cache it may already be on
   * the connected list, so it needs removing before pushing to the pending
   * list.
   */
  ci_ni_dllist_remove_safe(netif, &ts->epcache_link);
  ci_ni_dllist_push(netif, &cache->pending, &ts->epcache_link);

  /* If the listening socket is going away we might not be able to push it on
   * to the list of fd-owning-states (and there's no point in doing so anyway).
   * In that case, we'll just call close the fd now, and all the previous stat:
   * will be tidied up eventually by uncache_ep().
   */
  ci_assert(ci_ni_dllist_is_self_linked(netif, &ts->epcache_fd_link));
  if( ! ci_ni_dllist_concurrent_push(netif, &cache->fd_states,
                                     &ts->epcache_fd_link) )
    ci_sys_close(ts->cached_on_fd);

  /* We're more of a kidnapped child than an orphan, but we still need to
   * do the state tidy up that's needed for a socket who's parent isn't
   * there any more...
   *
   * NB. This socket cannot now be added to the deferred list, because
   * no-one has a reference to it.
   */                                 
  ci_netif_purge_deferred_socket_list(netif);

  /* We also need to remove the socket from the post-poll list.  It may
   * have been left there because the stack believes a wakeup is needed.
   */
  ci_ni_dllist_remove_safe(netif, &s->b.post_poll_link);
  ci_ni_dllist_remove_safe(netif, &s->b.ready_link);
  s->b.ready_list_id = 0;

  ci_tcp_all_fds_gone_common(netif, ts);

  /* Now need to trigger the next transition.  If the socket is not closed
   * yet then we just go via ci_tcp_close, which will handle whatever state
   * we're in appropriately.
   *
   * If we're already closed there's nothing else we're waiting for - we can
   * free to cache straightaway.
   */
  if( ts->s.b.state != CI_TCP_CLOSED ) {
    ci_tcp_close(netif, ts);
  }
  else {
    /* Only active cached sockets can go directly to the cached list - we
     * can only cache passive sockets that still have their hw filter ref.
     */
    ci_assert(active);
    ci_tcp_state_free_to_cache(netif, ts);
  }
  ci_assert(ci_tcp_is_cached(ts));
}


static void citp_tcp_close_passive_cached(ci_netif* netif, citp_fdinfo* fdinfo,
                                          ci_tcp_socket_listen* tls)
{
  ci_atomic32_dec(&tls->cache_avail_sock);
  ci_assert_ge(tls->cache_avail_sock, 0);
  ci_assert_lt(tls->cache_avail_sock, netif->state->opts.per_sock_cache_max);

  citp_tcp_close_cached(fdinfo, &tls->epcache, 0);
}


static void citp_tcp_close_active_cached(ci_netif* netif, citp_fdinfo* fdinfo)
{
  citp_tcp_close_cached(fdinfo, &netif->state->active_cache, 1);
}


#endif


#if CI_CFG_FD_CACHING
/* Check whether a socket's local port is in the list of permitted ports for
 * caching.
 */
static int citp_tcp_cache_port_eligible(ci_sock_cmn* s) {
  struct ci_port_list *sock_cache_port;

  if( CITP_OPTS.sock_cache_ports == 0 )
    return 1;

  CI_DLLIST_FOR_EACH2(struct ci_port_list, sock_cache_port, link,
                      (ci_dllist*)(ci_uintptr_t)CITP_OPTS.sock_cache_ports)
    if( sock_cache_port->port == sock_lport_be16(s) )
      return 1;

  return 0;
}


/* Decide whether to cache a file descriptor.
 * If this function returns 0, the fd is closed.
 * A return of 1 means the fd is closed in user-space, but it's tcp EP is
 * cached (the fd will only be reused on a subsequent accept).
 * The usual "-ve error code for failure" applies
 */
static int citp_tcp_cache(citp_fdinfo* fdinfo)
{
  int rc = 0;
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdinfo);
  ci_sock_cmn* s = epi->sock.s;
  ci_tcp_state* ts;
  ci_netif* netif = epi->sock.netif;
  ci_tcp_socket_listen* tls;

  Log_VSS(ci_log(LPF "cache("EF_FMT")", EF_PRI_ARGS(epi, fdinfo->fd)));

  /* We don't cache OS-backed sockets as managing the backing socket would
   * require going into the kernel.  This stops us from caching listening
   * sockets.
   */
  if( s->b.sb_aflags & CI_SB_AFLAG_OS_BACKED ) {
    Log_EP(ci_log("FD %d not cached - has backing socket", fdinfo->fd));
    return 0;
  }

  /* All listening sockets have OS-backed socket. Hence, our socket is
   * a connected socket. */
  ts = SOCK_TO_TCP(s);

  /* SO_LINGER handled in the kernel. */
  if( s->s_flags & CI_SOCK_FLAG_LINGER ) {
    Log_EP(ci_log("FD %d not cached - SO_LINGER set", fdinfo->fd));
    return 0;
  }
  
  /* Loopback sockets lack hw filter - shouldn't cache. */
  if( OO_SP_NOT_NULL(ts->local_peer) &&
      ts->tcpflags & CI_TCPT_FLAG_PASSIVE_OPENED) {
    Log_EP(ci_log("FD %d not cached - accelerated loopback", fdinfo->fd));
    return 0;
  }

  /* We'd need to go into the kernel to sort out the async queue for sockets
   * using O_ASYNC, so caching isn't worthwhile given they're an unusual case
   * anyway.  Similarly, we'd have to remove the O_APPEND flag.
   */
  if( s->b.sb_aflags & (CI_SB_AFLAG_O_ASYNC | CI_SB_AFLAG_O_APPEND) ) {
    Log_EP(ci_log("FD %d not cached - invalid flags set 0x%x", fdinfo->fd,
           s->b.sb_aflags & (CI_SB_AFLAG_O_ASYNC | CI_SB_AFLAG_O_APPEND)));
    return 0;
  }

  /* We may not be cacheable, for example if we've been duped, or added to
   * a ul_epoll=2 set.
   */
  if( !fdinfo->can_cache ) {
    Log_EP(ci_log("FD %d not cached - fdinfo not cacheable", fdinfo->fd));
    return 0;
  }

  /* Caching can be configured to be restricted to specific local ports. Make
   * the appropriate check.
   */
  if( ! citp_tcp_cache_port_eligible(s) ) {
    Log_EP(ci_log("FD %d not cached - ineligible port", fdinfo->fd));
    return 0;
  }

  /* The rest of the state checks need the netif lock, to ensure we make the
   * right decision.
   */
  if( ! ci_netif_trylock(netif) ) {
    Log_EP(ci_log("FD %d not cached - couldn't lock stack", fdinfo->fd));
    CITP_STATS_NETIF(++netif->state->stats.sockcache_contention);
    return 0;
  }

  /* We need to decide whether this socket should go on the passive- or
   * active-open cache, as the remaining work is different in each case. */
  if( ts->tcpflags & CI_TCPT_FLAG_PASSIVE_OPENED ) {
    rc = ci_netif_listener_lookup(netif, sock_laddr_be32(s),
                                  sock_lport_be16(s));
    if( rc < 0 ) {
      /* If the listener has been closed, we can't cache this socket. */
      rc = 0;
      goto unlock_out;
    }

    /* This is a passive-open socket whose listener is still open, so check
     * that we satisfy the additional restrictions placed on the passive cache.
     */

    /* We limit the maximum number of sockets cached in a stack. */
    if( netif->state->passive_cache_avail_stack == 0 ) {
      Log_EP(ci_log("FD %d not cached - passive stack limit reached",
                    fdinfo->fd));
      CITP_STATS_NETIF(++netif->state->stats.passive_sockcache_stacklim);
      goto unlock_out;
    }

    /* The tcp state needs to still have its filters, or we'd have to go into
     * kernel anyway.
     */
    if( !(s->b.state & CI_TCP_STATE_TCP_CONN) ) {
      Log_EP(ci_log("FD %d not cached - not in suitable state (0x%x)",
                    fdinfo->fd, s->b.state));
      goto unlock_out;
    }

    if( s->s_flags & CI_SOCK_FLAG_FILTER ) {
      Log_EP(ci_log("FD %d not cached - full match hw filter is installed",
                    fdinfo->fd));
      goto unlock_out;
    }

    tls = SP_TO_TCP_LISTEN(netif, CI_NETIF_FILTER_ID_TO_SOCK_ID(netif, rc));

    if( tls->cache_avail_sock == 0 ) {
      Log_EP(ci_log("FD %d not cached - per-socket limit reached", fdinfo->fd));
      CITP_STATS_NETIF(++netif->state->stats.sockcache_socklim);
      goto unlock_out;
    }

    /* Woohoo!  Cache this sucker! */
    citp_tcp_close_passive_cached(netif, fdinfo, tls);
    Log_EP(ci_log("FD %d cached on passive-open cache", fdinfo->fd));
  }
  else {
    /* This socket goes on the active-open cache, so we're good to go.
     * Currently the only such sockets are either closed and unbound or have
     * IP_TRANSPARENT set. */
    ci_assert(s->s_flags & CI_SOCK_FLAG_TPROXY ||
              (s->b.state == CI_TCP_CLOSED &&
               ! (s->s_flags & CI_SOCK_FLAG_BOUND)));

    /* We limit the maximum number of sockets cached in a stack. */
    if( netif->state->active_cache_avail_stack == 0 ) {
      Log_EP(ci_log("FD %d not cached - active stack limit reached",
                    fdinfo->fd));
      CITP_STATS_NETIF(++netif->state->stats.active_sockcache_stacklim);
      goto unlock_out;
    }

    citp_tcp_close_active_cached(netif, fdinfo);
    Log_EP(ci_log("FD %d cached on active-open cache", fdinfo->fd));
  }

  rc = 1;
  CITP_STATS_NETIF(++netif->state->stats.sockcache_cached);

 unlock_out:
  ci_netif_unlock_fdi(epi);
  return rc;
}
#endif


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
      /* Do not support listening tproxy sockets at the moment - that means
       * we can be sure that something in the listening state does have an
       * os socket backing it.
       */
      ci_assert_nflags(epi->sock.s->s_flags, CI_SOCK_FLAG_TPROXY);
      ci_assert_flags(epi->sock.s->b.sb_aflags, CI_SB_AFLAG_OS_BACKED);

      ci_netif_lock_fdi(epi);
      ci_tcp_helper_ep_clear_filters(
                            ci_netif_get_driver_handle(epi->sock.netif),
                            SC_SP(epi->sock.s), 0);
      ci_netif_unlock_fdi(epi);
      citp_fdinfo_release_ref(fdinfo, 0);
      return 0;
    }
    else if( epi->sock.s->b.state == CI_TCP_CLOSED ) {
      ci_netif_lock_fdi(epi);
      if( (epi->sock.s->b.sb_aflags & CI_SB_AFLAG_OS_BACKED) == 0 ) {
        /* Non os-backed TCP sockets are one of three things:
         * 1 passively accepted
         * 2 pre bind, connect and listen
         * 3 tproxy bound sockets
         * For sockets in state 2 we can create the OS socket now and sync the
         * option we were trying to set, so that we can just handover.
         * I'm not convinced we can get here at all for sockets in state 1 -
         * perhaps if we concurrently close whilst setting the socket option.
         * In that case it's valid to fail.
         * For tproxy bound sockets we can't handover, so we fail.
         */
        if( (SOCK_TO_TCP(epi->sock.s)->tcpflags &
             CI_TCPT_FLAG_PASSIVE_OPENED) ) {
          ci_netif_unlock_fdi(epi);
          RET_WITH_ERRNO(EINVAL);
        }
        else if( (epi->sock.s->s_flags & CI_SOCK_FLAG_TPROXY) &&
                 (epi->sock.s->s_flags & CI_SOCK_FLAG_PORT_BOUND) ) {
          ci_netif_unlock_fdi(epi);
          NI_LOG(epi->sock.netif, USAGE_WARNINGS, "Sockets that have been "
                 "bound with IP_TRANSPARENT set cannot be handed over, and "
                 "socket option %d %d requires handover", level, optname);
          RET_WITH_ERRNO(EINVAL);
        }

        rc = ci_tcp_helper_os_sock_create_and_set(epi->sock.netif, fdinfo->fd,
                                                  epi->sock.s, level, optname,
                                                  optval, optlen);
        if( rc < 0 ) {
          ci_netif_unlock_fdi(epi);
          RET_WITH_ERRNO(errno);
        }
      }
      ci_netif_unlock_fdi(epi);

      ci_assert_flags(epi->sock.s->b.sb_aflags, CI_SB_AFLAG_OS_BACKED);
      tcp_handover(epi);
      return 0;
    }
    else /* Can't handover connected socket */
      RET_WITH_ERRNO(EINVAL);
  }

  if( rc == 0 &&
      (epi->sock.s->s_flags & CI_SOCK_FLAG_PORT_BOUND) != 0 &&
      (epi->sock.s->s_flags & CI_SOCK_FLAG_FILTER) == 0 &&
      ci_opt_is_setting_reuseport(level, optname, optval, optlen) != 0 )
    /* If the following fails, we are not undoing the bind() done
     * before as that is non-trivial.  We are still leaving the socket
     * in a working state albeit bound without reuseport set.
     */
    if( (rc = ci_tcp_reuseport_bind(epi->sock.s, fdinfo->fd)) == 0 ) {
      /* The socket has moved so need to reprobe the fd.  This will also
       * map the the new stack into user space of the executing process.
       */
      fdinfo = citp_fdtable_lookup(fdinfo->fd);
      fdinfo = citp_reprobe_moved(fdinfo, CI_FALSE, CI_FALSE);
      epi = fdi_to_sock_fdi(fdinfo);
      ci_netif_cluster_prefault(epi->sock.netif);
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

  if( (flags & (MSG_WAITALL | ONLOAD_MSG_ONEPKT)) ==
      (MSG_WAITALL | ONLOAD_MSG_ONEPKT) ) {
    Log_E(ci_log("WAITALL and ONEPKT is not a valid flag combination"));
    errno = EINVAL;
    return -1;
  };

  Log_V(ci_log(LPF "recv("EF_FMT", len=%d, "CI_SOCKCALL_FLAGS_FMT")",
            EF_PRI_ARGS(epi,fdinfo->fd),
            ci_iovec_bytes(msg->msg_iov, msg->msg_iovlen),
            CI_SOCKCALL_FLAGS_PRI_ARG(flags)));

  if( epi->sock.s->b.state != CI_TCP_LISTEN ) {
    if (msg->msg_iovlen == 0 || msg->msg_iov == NULL) {
      msg->msg_flags = 0;
      return 0;
    }
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
                             ci_recvmmsg_timespec* timeout)
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
                          msg->msg_iov, msg->msg_iovlen, flags); 
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

#if CI_CFG_SPIN_STATS
  if( CI_UNLIKELY(! ss->stat_incremented) ) {
    ni->state->stats.spin_select++;
    ss->stat_incremented = 1;
  }
#endif

  citp_poll_if_needed(ni, ss->now_frc, ss->ul_select_spin);

  /* Fast path: CI_TCP_LISTEN or
   * CI_TCP_ESTABLISHED || CI_TCP_CLOSE_WAIT.
   * Everything else goes via ci_tcp_poll_events_nolisten() */
  if( (s->b.state & CI_TCP_STATE_SYNCHRONISED) && s->tx_errno == 0 ) {
    ci_tcp_state* ts = SOCK_TO_TCP(s);
    if( rd && ( ci_tcp_recv_not_blocked(ts) ||
                ci_udp_recv_q_not_empty(&ts->timestamp_q) ) ) {
        FD_SET(fdi->fd, ss->rdu);
        ++*n;
    }
    if( wr && ( ci_tcp_tx_advertise_space(ni, ts) ||
                ci_udp_recv_q_not_empty(&ts->timestamp_q) ) ) {
        FD_SET(fdi->fd, ss->wru);
        ++*n;
    }
    if( ex && ci_tcp_poll_events_nolisten_haspri(ni, ts) ) {
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
     * call it.  And avoid races by calling ci_tcp_poll_events(). */
    unsigned mask = ci_tcp_poll_events(ni, s);
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

#if CI_CFG_SPIN_STATS
  ni->state->stats.spin_poll++;
#endif

  mask = ci_tcp_poll_events(ni, s);
  pfd->revents = mask & (pfd->events | POLLERR | POLLHUP);
  if( pfd->revents == 0 )
    if( citp_poll_if_needed(ni, ps->this_poll_frc, ps->ul_poll_spin) ) {
      mask = ci_tcp_poll_events(ni, s);
      pfd->revents = mask & (pfd->events | POLLERR | POLLHUP);
    }

  return 1;
}

#endif /*CI_CFG_USERSPACE_SELECT*/


#if CI_CFG_USERSPACE_EPOLL
#include "ul_epoll.h"
/* More-or-less copy of citp_tcp_poll */
static int citp_tcp_epoll(citp_fdinfo*__restrict__ fdi,
                          struct citp_epoll_member*__restrict__ eitem,
                          struct oo_ul_epoll_state*__restrict__ eps,
                          int* stored_event)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdi);
  ci_sock_cmn* s = epi->sock.s;
  ci_netif* ni = epi->sock.netif;
  ci_uint64 sleep_seq;
  ci_uint32 mask;
  int seq_mismatch = 0;

#if CI_CFG_SPIN_STATS
  if( CI_UNLIKELY(! eps->stat_incremented) ) {
    ni->state->stats.spin_epoll++;
    eps->stat_incremented = 1;
  }
#endif

  /* Try to return a result without polling if we can. */
  sleep_seq = s->b.sleep_seq.all;
  mask = ci_tcp_poll_events(ni, s);
  *stored_event = citp_ul_epoll_set_ul_events(eps, eitem, mask, sleep_seq,
                                              &s->b.sleep_seq.all,
                                              &seq_mismatch);
  /* Try a poll if we don't already have events.  If this is an ordered wait
   * (ie we have ordering_info) another netif poll will be too late, so don't
   * bother.
   */
  if( (*stored_event == 0) && !eps->ordering_info ) {
    if( citp_poll_if_needed(ni, eps->this_poll_frc, eps->ul_epoll_spin) ) {
      sleep_seq = s->b.sleep_seq.all;
      mask = ci_tcp_poll_events(ni, s);
      seq_mismatch = 0;
      *stored_event = citp_ul_epoll_set_ul_events(eps, eitem, mask, sleep_seq,
                                                  &s->b.sleep_seq.all,
                                                  &seq_mismatch);
    }
  }

  /* We shouldn't have stored an event if there was a mismatch */
  ci_assert( !(seq_mismatch == 1 && *stored_event == 1) );
  return seq_mismatch;
}
#endif /*CI_CFG_USERSPACE_EPOLL*/


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


int citp_tcp_tmpl_alloc(citp_fdinfo* fdi, const struct iovec* initial_msg,
                        int mlen, struct oo_msg_template** omt_pp,
                        unsigned flags)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdi);
  ci_tcp_state* ts = SOCK_TO_TCP(epi->sock.s);
  ci_netif* ni = epi->sock.netif;

  ci_assert(ts->s.b.state != CI_TCP_LISTEN);
  return ci_tcp_tmpl_alloc(ni, ts, omt_pp, initial_msg, mlen, flags);
}


int
citp_tcp_tmpl_update(citp_fdinfo* fdi, struct oo_msg_template* omt,
                     const struct onload_template_msg_update_iovec* updates,
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


#if CI_CFG_USERSPACE_EPOLL
int citp_tcp_ordered_data(citp_fdinfo* fdi, struct timespec* limit,
                          struct timespec* next_out, int* bytes_out)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdi);
  ci_sock_cmn* s = epi->sock.s;
  ci_tcp_state* ts;
  ci_ip_pkt_fmt* pkt;

  *bytes_out = 0;
  next_out->tv_sec = 0;

  if( s->b.state != CI_TCP_LISTEN ) {
    ts = SOCK_TO_TCP(s);
    
    if( OO_SP_NOT_NULL(ts->local_peer) )
      return 0;

    ci_sock_lock(epi->sock.netif, &ts->s.b);
    if( tcp_rcv_usr(ts) <= 0 || OO_PP_IS_NULL(ts->recv1_extract)) {
      ci_sock_unlock(epi->sock.netif, &ts->s.b);
      return 0;
    }

    pkt = PKT_CHK_NNL(epi->sock.netif, ts->recv1_extract);
    if( oo_offbuf_is_empty(&pkt->buf) ) {
      if( OO_PP_IS_NULL(pkt->next) )  {
        ci_sock_unlock(epi->sock.netif, &ts->s.b);
        return 0;  /* recv1 is empty. */
      }
      pkt = PKT_CHK_NNL(epi->sock.netif, pkt->next);
      ci_assert(oo_offbuf_not_empty(&pkt->buf));
    }

    do {
      if( citp_oo_timespec_compare(&pkt->pf.tcp_rx.rx_hw_stamp, limit) < 1 ) {
        *bytes_out += oo_offbuf_left(&pkt->buf);
      }
      else {
        next_out->tv_sec = pkt->pf.tcp_rx.rx_hw_stamp.tv_sec;
        next_out->tv_nsec = pkt->pf.tcp_rx.rx_hw_stamp.tv_nsec;
        break;
      }
      if( ! OO_PP_IS_NULL(pkt->next) )
        pkt = PKT_CHK_NNL(epi->sock.netif, pkt->next);
      else
        break;
    }
    while( 1 );

    ci_sock_unlock(epi->sock.netif, &ts->s.b);
  }

  return 1;
}
#endif

int citp_sock_is_spinning(citp_fdinfo* fdi)
{
  return !!fdi_to_sock_fdi(fdi)->sock.s->b.spin_cycles;
}



enum onload_delegated_send_rc
citp_tcp_ds_prepare(citp_fdinfo* fdi, int size, unsigned flags,
                    struct onload_delegated_send* out)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdi);
  ci_netif* ni = epi->sock.netif;
  ci_sock_cmn* s = epi->sock.s;
  ci_tcp_state* ts;
  enum onload_delegated_send_rc rc;

  /* Basic checks */
  if( s->tx_errno != 0 ||
      (s->timestamping_flags & ONLOAD_SOF_TIMESTAMPING_STREAM) )
    return ONLOAD_DELEGATED_SEND_RC_BAD_SOCKET;
  ts = SOCK_TO_TCP(epi->sock.s);
  if( ts->s.pkt.flags & CI_IP_CACHE_IS_LOCALROUTE )
    return ONLOAD_DELEGATED_SEND_RC_BAD_SOCKET;

  /* We lock the stack at this point to ensure that the prequeue has been
   * flushed, and also to prevent various sequence numbers changing under our
   * feet. */
  ci_netif_lock(ni);
  if( ci_tcp_sendq_not_empty(ts) ) {
    rc = ONLOAD_DELEGATED_SEND_RC_SENDQ_BUSY;
    goto unlock_out;
  }

  /* Calculate the windows */
  out->mss = tcp_eff_mss(ts);
  out->send_wnd = SEQ_SUB(ts->snd_max, tcp_snd_nxt(ts));
  out->cong_wnd = ts->cwnd + ts->cwnd_extra - ci_tcp_inflight(ts);
  out->user_size = size;
  if( out->cong_wnd < out->mss ) {
    ci_assert( ci_ip_queue_not_empty(&ts->retrans) );
    out->cong_wnd = 0;
    rc = ONLOAD_DELEGATED_SEND_RC_NOWIN;
    goto unlock_out;
  }
  if( out->send_wnd <= 0 ) {
    out->send_wnd = 0;
    rc = ONLOAD_DELEGATED_SEND_RC_NOWIN;
    goto unlock_out;
  }


  rc = ci_tcp_ds_fill_headers(ni, ts, flags, out->headers, &out->headers_len,
                              &out->ip_tcp_hdr_len,
                              &out->tcp_seq_offset, &out->ip_len_offset);
  if( rc != ONLOAD_DELEGATED_SEND_RC_OK )
    goto unlock_out;

  /* Tell TCP state to be ready for ACKs from future */
  ts->snd_delegated = CI_MIN(size, out->send_wnd);

 unlock_out:
  ci_netif_unlock(ni);
  return rc;
}

int citp_tcp_ds_complete(citp_fdinfo* fdi, const ci_iovec *iov, int iovlen,
                         int flags)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdi);
  ci_netif* ni = epi->sock.netif;
  ci_sock_cmn* s = epi->sock.s;
  int rc;

  if( (~s->b.state & CI_TCP_STATE_TCP) || s->b.state == CI_TCP_LISTEN ) {
    errno = EINVAL;
    return -1;
  }

  rc = ci_tcp_ds_done(ni, SOCK_TO_TCP(epi->sock.s), iov, iovlen, flags);

  if( rc == -1 && errno == EPIPE && ! (flags & MSG_NOSIGNAL) ) {
    ci_sys_ioctl(ci_netif_get_driver_handle(epi->sock.netif),
                 OO_IOC_KILL_SELF_SIGPIPE, NULL);
  }
  return rc;
}

int citp_tcp_ds_cancel(citp_fdinfo* fdi)
{
  citp_sock_fdi* epi = fdi_to_sock_fdi(fdi);
  ci_sock_cmn* s = epi->sock.s;

  if( (~s->b.state & CI_TCP_STATE_TCP) || s->b.state == CI_TCP_LISTEN ) {
    errno = ENOTTY;
    return -1;
  }

  SOCK_TO_TCP(epi->sock.s)->snd_delegated = 0;
  return 0;
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
    .zc_send            = citp_tcp_zc_send,
    .zc_recv            = citp_tcp_zc_recv,
    .recvmsg_kernel     = citp_tcp_recvmsg_kernel,
    .tmpl_alloc         = citp_tcp_tmpl_alloc,
    .tmpl_update        = citp_tcp_tmpl_update,
    .tmpl_abort         = citp_tcp_tmpl_abort,
#if CI_CFG_USERSPACE_EPOLL
    .ordered_data       = citp_tcp_ordered_data,
#endif
    .is_spinning        = citp_sock_is_spinning,
#if CI_CFG_FD_CACHING
    .cache              = citp_tcp_cache,
#endif
    .dsend_prepare      = citp_tcp_ds_prepare,
    .dsend_complete     = citp_tcp_ds_complete,
    .dsend_cancel       = citp_tcp_ds_cancel,
  }
};

/*! \cidoxg_end */
