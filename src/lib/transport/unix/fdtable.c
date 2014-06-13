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
**  \brief  Table mapping [fd]s to userlevel state.
**   \date  2003/01/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_unix */

#include "internal.h"
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <onload/ul.h>
#include <onload/dup2_lock.h>
#include <onload/ul/tcp_helper.h>
#include <onload/version.h>

#if CI_CFG_USERSPACE_PIPE
# include "ul_pipe.h"
#endif
#if CI_CFG_USERSPACE_EPOLL
# include "ul_poll.h"
# include "ul_epoll.h"
#endif

/* FIXME Yes, it is ugly. But we do not have any appropriate header */
#define CI_ID_POOL_ID_NONE ((unsigned)(-1))

#define DEBUGPREINIT(x)

# define citp_fdinfo_free	CI_FREE_OBJ


citp_fdtable_globals	citp_fdtable;

/* Initial seqno should differ from the seqno in special fdi, such as
 * citp_the_closed_fd */
ci_uint64 fdtable_seq_no = 1;


static void dup2_complete(citp_fdinfo* prev_newfdi,
			  citp_fdinfo_p prev_newfdip, int fdt_locked);

static void sighandler_do_nothing(int sig) { }

/*! Block until fdtable entry is neither closing nor busy, and return the
** new (non-closing-or-busy) fdip. */
static citp_fdinfo_p citp_fdtable_closing_wait(unsigned fd, int fdt_locked);


int citp_fdtable_ctor()
{
  struct rlimit rlim;
  int rc;

  Log_S(log("%s:", __FUNCTION__));

  /* How big should our fdtable be by default?  It's pretty arbitrary, but we have
   * seen a few apps that use setrlimit to set the fdtable to 4096 entries on
   * start-up (see bugs 3253 and 3373), so we choose that.  (Note: we can't grow
   * the table if the app later does setrlimit, and unused entries consume virtual
   * space only, so it's worth allocating a table of reasonable sized.)
   */
  citp_fdtable.size = 4096;

  if( getrlimit(RLIMIT_NOFILE, &rlim) == 0 ) {
    citp_fdtable.size = rlim.rlim_max;
    if( CITP_OPTS.fdtable_size != 0 &&
        CITP_OPTS.fdtable_size != rlim.rlim_max ) {
      Log_S(ci_log("Set the limits for the number of opened files "
                   "to EF_FDTABLE_SIZE=%u value.",
                   CITP_OPTS.fdtable_size));
      rlim.rlim_max = CITP_OPTS.fdtable_size;
      if( rlim.rlim_cur > rlim.rlim_max )
        rlim.rlim_cur = rlim.rlim_max;
      if( ci_sys_setrlimit(RLIMIT_NOFILE, &rlim) == 0 )
          citp_fdtable.size = rlim.rlim_max;
      else {
        /* Most probably, we've got EPERM */
        ci_assert_lt(citp_fdtable.size, CITP_OPTS.fdtable_size);
        ci_log("Can't set EF_FDTABLE_SIZE=%u; using %u",
               CITP_OPTS.fdtable_size, citp_fdtable.size);
        rlim.rlim_max = rlim.rlim_cur = citp_fdtable.size;
        CI_TRY(ci_sys_setrlimit(RLIMIT_NOFILE, &rlim));
      }
    }
  }
  else
    Log_S(ci_log("Assume EF_FDTABLE_SIZE=%u", citp_fdtable.size));

  citp_fdtable.inited_count = 0;

  citp_fdtable.table = ci_libc_malloc(sizeof (citp_fdtable_entry) *
                                      citp_fdtable.size);
  if( ! citp_fdtable.table ) {
    Log_U(log("%s: failed to allocate fdtable (0x%x)", __FUNCTION__,
              citp_fdtable.size));
    return -1;
  }

  /* The whole table is not initialised at start-of-day, but is initialised
  ** on demand.  citp_fdtable.inited_count counts the number of initialised
  ** entries.
  */

  if( (rc = CITP_LOCK_CTOR(&citp_ul_lock)) != 0 ) {
    Log_E(log("%s: CITP_LOCK_CTOR %d", __FUNCTION__, rc));
    return -1;
  }

  /* Install SIGONLOAD handler */
  {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa)); /* sa_flags and sa_mask = 0 */
    sa.sa_handler = sighandler_do_nothing;
    sigaction(SIGONLOAD, &sa, NULL);
  }

  return 0;
}


#if !defined (NDEBUG) || CI_CFG_FDTABLE_CHECKS
/* This function does some simple tests to ensure that the fdtable makes sense.
 * There are many more tests we could do; feel free to add them at your
 * leisure!
 */
void
citp_fdtable_assert_valid(void)
{
  int i;

  if( ! citp_fdtable.table )  return;

  CITP_FDTABLE_LOCK_RD();

  for( i = 0; i < citp_fdtable.inited_count; i++ ) {
    citp_fdinfo_p fdip = citp_fdtable.table[i].fdip;

    if( fdip_is_normal(fdip) ) {
      citp_fdinfo * fdi = fdip_to_fdi(fdip);

      ci_assert(fdi);
      ci_assert(fdi->protocol);
      if( ( fdi->protocol->type == CITP_TCP_SOCKET ||
            fdi->protocol->type == CITP_UDP_SOCKET )
          && fdi_to_socket(fdi)->s )
	ci_assert(! (fdi_to_socket(fdi)->s->b.sb_aflags & CI_SB_AFLAG_ORPHAN));

      if (!fdi->is_special) {
        /* Ensure the "back pointer" makes sense */
        ci_assert (fdi->fd == i);
#if CI_CFG_FD_CACHING
        ci_assert (fdi->is_cached == 0);
#endif
        /* Ensure that the reference count is in a vaguely sensible range */
        ci_assert ((oo_atomic_read (&fdi->ref_count) > 0) &&
                   (oo_atomic_read (&fdi->ref_count) < 10000));

        /* 10,000 threads is a bit mad, warn if more than 20 */
        if (oo_atomic_read (&fdi->ref_count) > 20) {
          Log_U (log ("Warning: fd %d's ref-count suspiciously large (%d)\n",
                      i, oo_atomic_read (&fdi->ref_count)));
        }
      }
#if CI_CFG_FD_CACHING
      if (fdi->is_cached) ci_assert (fdi->can_cache);
#endif
    }
  }

  CITP_FDTABLE_UNLOCK();
}
#endif


static void fdtable_swap(unsigned fd, citp_fdinfo_p from,
			 citp_fdinfo_p to, int fdt_locked)
{
  volatile citp_fdinfo_p* p_fdip;
  citp_fdinfo_p fdip;

  p_fdip = &citp_fdtable.table[fd].fdip;

 again:
  fdip = *p_fdip;
  if( fdip_is_busy(fdip) )  fdip = citp_fdtable_busy_wait(fd, fdt_locked);
  ci_assert(fdip == from);
  if( fdip_cas_fail(p_fdip, from, to) )  goto again;
}


static citp_fdinfo*
citp_fdtable_probe_restore(int fd, ci_ep_info_t * info, int print_banner)
{
  citp_protocol_impl* proto = 0;
  citp_fdinfo* fdi = 0;
  ci_netif* ni;
  int rc;
  int c_sock_fdi = 1;

  /* Must be holding the FD table writer lock */
  CITP_FDTABLE_ASSERT_LOCKED(1);
  ci_assert_nequal(info->resource_id, CI_ID_POOL_ID_NONE);

  /* Will need to review this function if the following assert fires */
  switch( info->fd_type ) {
  case CI_PRIV_TYPE_TCP_EP:  proto = &citp_tcp_protocol_impl;  break;
  case CI_PRIV_TYPE_UDP_EP:  proto = &citp_udp_protocol_impl;  break;
#if CI_CFG_USERSPACE_PIPE
  case CI_PRIV_TYPE_PIPE_READER:
    proto = &citp_pipe_read_protocol_impl;
    c_sock_fdi = 0;
    break;
  case CI_PRIV_TYPE_PIPE_WRITER:
    proto = &citp_pipe_write_protocol_impl;
    c_sock_fdi = 0;
    break;
#endif
  default:                   ci_assert(0);
  }

  /* Attempt to find the user-level netif for this endpoint */
  ni = citp_find_ul_netif(info->resource_id, 1);
  if( ! ni ) {
    ef_driver_handle netif_fd;

    /* Not found, rebuild/restore the netif for this endpoint */
    rc = citp_netif_recreate_probed(fd, &netif_fd, &ni);
    if ( rc < 0 ) {
      Log_E(log("%s: citp_netif_recreate_probed failed! (%d)",
		__FUNCTION__, rc));
      goto fail;
    }

    if( print_banner ) {
      ci_log("Importing "ONLOAD_PRODUCT" "ONLOAD_VERSION" "ONLOAD_COPYRIGHT
             " [%s]", ni->state->pretty_name);
    }
  }
  else
    citp_netif_add_ref(ni);


  if (c_sock_fdi) {
    citp_sock_fdi* sock_fdi;

    sock_fdi = CI_ALLOC_OBJ(citp_sock_fdi);
    if( ! sock_fdi ) {
      Log_E(log("%s: out of memory (sock_fdi)", __FUNCTION__));
      goto fail;
    }
    fdi = &sock_fdi->fdinfo;

    sock_fdi->sock.s = SP_TO_SOCK_CMN(ni, info->sock_id);
    sock_fdi->sock.netif = ni;
  }
#if CI_CFG_USERSPACE_PIPE
  else {
    citp_pipe_fdi* pipe_fdi;

    pipe_fdi = CI_ALLOC_OBJ(citp_pipe_fdi);
    if( ! pipe_fdi ) {
      Log_E(log("%s: out of memory (pipe_fdi)", __FUNCTION__));
      goto fail;
    }
    fdi = &pipe_fdi->fdinfo;

    pipe_fdi->pipe = SP_TO_PIPE(ni, info->sock_id);
    pipe_fdi->ni = ni;
  }
#endif

  citp_fdinfo_init(fdi, proto);

  /* We're returning a reference to the caller. */
  citp_fdinfo_ref(fdi);
  citp_fdtable_insert(fdi, fd, 1);
  return fdi;
 
 fail:
  if( ni  )  citp_netif_release_ref(ni, 1);
  return 0;
}


/* Find out what sort of thing [fd] is, and if it is a user-level socket
 * then map in the user-level state.
 */
citp_fdinfo * citp_fdtable_probe_locked(unsigned fd, int print_banner)
{
  volatile citp_fdinfo_p* p_fdip;
  citp_fdinfo_p fdip;
  citp_fdinfo* fdi = NULL;
  struct stat st;
  ci_ep_info_t info;

  /* ?? We're repeating some effort already expended in lookup() here, but
  ** this keeps it cleaner.  May optimise down the line when I understand
  ** what other code needs to call this.
  */

  p_fdip = &citp_fdtable.table[fd].fdip;
 again:
  fdip = *p_fdip;
  if( fdip_is_busy(fdip) )  fdip = citp_fdtable_busy_wait(fd, 1);
  if( ! fdip_is_unknown(fdip) && ! fdip_is_normal(fdip) )  goto exit;
  if( fdip_cas_fail(p_fdip, fdip, fdip_busy) )  goto again;

  if( fdip_is_normal(fdip) ) {
    fdi = fdip_to_fdi(fdip);
    citp_fdinfo_ref(fdi);
    citp_fdtable_busy_clear(fd, fdip, 1);
    goto exit;
  }

  if( ci_sys_fstat(fd, &st) != 0 ) {
    /* fstat() failed.  Must be a bad (closed) file descriptor, so
    ** leave this entry as unknown.  Return citp_the_closed_fd to avoid the
    ** caller passing through to an fd that is created asynchronously.
    */
    citp_fdtable_busy_clear(fd, fdip_unknown, 1);
    fdi = &citp_the_closed_fd;
    citp_fdinfo_ref(fdi);
    goto exit;
  }

  if(  st.st_dev == citp_onloadfs_dev_t() ) {
    /* Retrieve user-level endpoint info */
    if( oo_ep_info(fd, &info) < 0 ) {
      Log_V(log("%s: fd=%d type=%d unknown", __FUNCTION__,fd,info.fd_type));
      citp_fdtable_busy_clear(fd, fdip_passthru, 1);
      goto exit;
    }

    switch( info.fd_type ) {
    case CI_PRIV_TYPE_TCP_EP:
    case CI_PRIV_TYPE_UDP_EP:
#if CI_CFG_USERSPACE_PIPE
    case CI_PRIV_TYPE_PIPE_READER:
    case CI_PRIV_TYPE_PIPE_WRITER:
#endif
      Log_V(log("%s: fd=%d %s restore", __FUNCTION__, fd,
		info.fd_type == CI_PRIV_TYPE_TCP_EP ? "TCP":
#if CI_CFG_USERSPACE_PIPE
                info.fd_type == CI_PRIV_TYPE_UDP_EP ? "PIPE" :
#endif
                "UDP"));
      fdi = citp_fdtable_probe_restore(fd, &info, print_banner);
      if( fdi == NULL )
        citp_fdtable_busy_clear(fd, fdip_unknown, 1);
      goto exit;

    case CI_PRIV_TYPE_NETIF:
      /* This should never happen, because netif fds are close-on-exec.
      ** But let's leave this code here just in case my reasoning is bad.
      */
      Log_U(log("%s: fd=%d NETIF reserved", __FUNCTION__, fd));
      citp_fdtable_busy_clear(fd, fdip_reserved, 1);
      fdi = &citp_the_reserved_fd;
      citp_fdinfo_ref(fdi);
      goto exit;

    default:
      /* This can potentially happen if (a) a thread gets at an fd we've
      ** just created, but before it's been specialised.  It can also
      ** happen if (b) we're running an app that wants to access our
      ** driver!  So we should pass-through in this case.
      **
      ** In either case setting to passthru should be fine.
      */
      Log_V(log("%s: fd=%d type=%d passthru", __FUNCTION__,fd,info.fd_type));
      citp_fdtable_busy_clear(fd, fdip_passthru, 1);
      goto exit;
    }
  }
  else if( ci_major(st.st_rdev) == citp_onload_epoll_dev_major() ) {
    citp_epollb_fdi *epi = CI_ALLOC_OBJ(citp_epollb_fdi);
    if( ! epi ) {
      Log_E(log("%s: out of memory (epoll_fdi)", __FUNCTION__));
      citp_fdtable_busy_clear(fd, fdip_passthru, 1);
      goto exit;
    }
    oo_epollb_ctor(epi);
    fdi = &epi->fdinfo;
    citp_fdinfo_init(fdi, &citp_epollb_protocol_impl);
    citp_fdinfo_ref(fdi);
    citp_fdtable_insert(fdi, fd, 1);
    goto exit;
  }

#ifndef NDEBUG
  /* /dev/onload may be netif only; they are closed on fork or exec */
  if( ci_major(st.st_rdev) == citp_onload_dev_major() )
    Log_U(log("%s: %d is /dev/onload", __FUNCTION__, fd));
#endif

  /* Not one of ours, so pass-through. */
  Log_V(log("%s: fd=%u non-efab", __FUNCTION__, fd));
  citp_fdtable_busy_clear(fd, fdip_passthru, 1);

 exit:
  return fdi;

}

static citp_fdinfo *
citp_fdtable_probe(unsigned fd)
{
  citp_fdinfo* fdi;
  int saved_errno;

  ci_assert(fd < citp_fdtable.size);

  if( ! CITP_OPTS.probe )  return NULL;

  saved_errno = errno;
  CITP_FDTABLE_LOCK();
  __citp_fdtable_extend(fd);
   fdi = citp_fdtable_probe_locked(fd, CI_FALSE);
  CITP_FDTABLE_UNLOCK();
  errno = saved_errno;
  return fdi;
}


citp_fdinfo *
citp_fdtable_lookup(unsigned fd)
{
  /* Note that if we haven't yet initialised this module, then
  ** [inited_count] will be zero, and the following test will fail.  So the
  ** test for initialisation is done further down...
  **
  ** This is highly performance critial.  DO NOT add any code between here
  ** and the first [return] statement.
  */
  citp_fdinfo* fdi;

  if( fd < citp_fdtable.inited_count ) {

    volatile citp_fdinfo_p* p_fdip = &citp_fdtable.table[fd].fdip;
    citp_fdinfo_p fdip;

  again:
    /* Swap in the busy marker. */
    fdip = *p_fdip;

    if( fdip_is_normal(fdip) ) {
      if( citp_fdtable_not_mt_safe() ) {
	if( fdip_cas_succeed(p_fdip, fdip, fdip_busy) ) {
	  fdi = fdip_to_fdi(fdip);
	  ci_assert(fdi);
	  ci_assert_gt(oo_atomic_read(&fdi->ref_count), 0);
	  ci_assert(fdip_is_closing(fdip) || fdip_is_reserved(fdip) ||
		    fdi->fd == fd);
	  /* Bump the reference count. */
	  citp_fdinfo_ref(fdi);
	  /* Swap the busy marker out again. */
	  citp_fdtable_busy_clear(fd, fdip, 0);
	  return fdi;
	}
	goto again;
      }
      else {
	/* No need to use atomic ops when single-threaded.  The definition
         * of "fds_mt_safe" is that the app does not change the meaning of
         * a file descriptor in one thread when it is being used in another
         * thread.  In that case I'm hoping this should be safe, but at
         * time of writing I'm really not confident.  (FIXME).
         */
	fdi = fdip_to_fdi(fdip);
        if( ci_is_multithreaded() )
	  citp_fdinfo_ref(fdi);
        else
          ++fdi->ref_count.n;
	return fdi;
      }
    }

    /* Not normal! */
    if( fdip_is_passthru(fdip) )  return NULL;

    if( fdip_is_busy(fdip) ) {
      citp_fdtable_busy_wait(fd, 0);
      goto again;
    }

    ci_assert(fdip_is_unknown(fdip));
    goto probe;
  }

  if (citp.init_level < CITP_INIT_FDTABLE) {
    if (_citp_do_init_inprogress == 0)
      CI_TRY(citp_do_init(CITP_INIT_ALL));
    else
      CI_TRY(citp_do_init(CITP_INIT_FDTABLE)); /* get what we need */
  }

  if( fd >= citp_fdtable.size )  return NULL;

 probe:
  fdi = citp_fdtable_probe(fd);

  return fdi;
}


citp_fdinfo*
citp_fdtable_lookup_fast(citp_lib_context_t* ctx, unsigned fd)
{
  /* Note that if we haven't yet initialised this module, then
  ** [inited_count] will be zero, and the following test will fail.  So the
  ** test for initialisation is done further down...
  **
  ** This is highly performance critial.  DO NOT add any code between here
  ** and the first [return] statement.
  */
  citp_fdinfo* fdi;

  /* Try to avoid entering lib. */
  ctx->thread = NULL;

  if( fd < citp_fdtable.inited_count ) {
    volatile citp_fdinfo_p* p_fdip = &citp_fdtable.table[fd].fdip;
    citp_fdinfo_p fdip;

  again:
    fdip = *p_fdip;
    if( fdip_is_normal(fdip) ) {
      citp_enter_lib_if(ctx);
      if( citp_fdtable_is_mt_safe() ) {
	/* No need to use atomic ops or add a ref to the fdi when MT-safe.
         * The definition of "fds_mt_safe" is that the app does not change
         * the meaning of a file descriptor in one thread when it is being
         * used in another thread.
         */
	return fdip_to_fdi(fdip);
      }
      else {
        /* Swap in the busy marker. */
	if( fdip_cas_succeed(p_fdip, fdip, fdip_busy) ) {
	  fdi = fdip_to_fdi(fdip);
	  ci_assert(fdi);
	  ci_assert_gt(oo_atomic_read(&fdi->ref_count), 0);
	  ci_assert(fdip_is_closing(fdip) || fdip_is_reserved(fdip) ||
		    fdi->fd == fd);
	  /* Bump the reference count. */
	  citp_fdinfo_ref(fdi);
	  /* Swap the busy marker out again. */
	  citp_fdtable_busy_clear(fd, fdip, 0);
	  return fdi;
	}
	goto again;
      }
    }

    /* Not normal! */
    if( fdip_is_passthru(fdip) )
      return NULL;

    citp_enter_lib_if(ctx);
    if( fdip_is_busy(fdip) ) {
      citp_fdtable_busy_wait(fd, 0);
      goto again;
    }

    ci_assert(fdip_is_unknown(fdip));
    goto probe;
  }

  if( citp.init_level < CITP_INIT_FDTABLE ) {
    if( _citp_do_init_inprogress == 0 )
      CI_TRY(citp_do_init(CITP_INIT_ALL));
    else
      CI_TRY(citp_do_init(CITP_INIT_FDTABLE)); /* get what we need */
  }

  if( fd >= citp_fdtable.size )
    return NULL;

 probe:
  citp_enter_lib_if(ctx);
  fdi = citp_fdtable_probe(fd);
  if( fdi && citp_fdtable_is_mt_safe() )
    citp_fdinfo_release_ref(fdi, 0);
  return fdi;
}


/* Looks up the user-level 'FD info' for a given file descriptor.
** Returns pointer to the user-level 'FD info' for a given file
** descriptor, or NULL if the FD is not user-level.
** NOTE: The reference count of the 'FD info' is incremented, the
**       caller should ensure the reference is dropped when no
**       longer needed by calling citp_fdinfo_release_ref().
*/
citp_fdinfo* citp_fdtable_lookup_noprobe(unsigned fd)
{
  /* Need to be initialised before we can try and grab the lock at the
  ** moment.  TODO: make this more efficient by using a trylock to grab the
  ** fdtable lock, and on fail see if we need to initialise it.
  */
  if( CI_UNLIKELY(citp.init_level < CITP_INIT_FDTABLE) ) {
    if (_citp_do_init_inprogress == 0)
      CI_TRY(citp_do_init(CITP_INIT_ALL));
    else
      CI_TRY(citp_do_init(CITP_INIT_FDTABLE)); /* get what we need */

    return NULL;
  }

  if( fd < citp_fdtable.inited_count ) {

    volatile citp_fdinfo_p* p_fdip = &citp_fdtable.table[fd].fdip;
    citp_fdinfo_p fdip;

  again:
    /* Swap in the busy marker. */
    fdip = *p_fdip;
    if( fdip_is_normal(fdip) ) {
      if( fdip_cas_succeed(p_fdip, fdip, fdip_busy) ) {
	/* Bump the reference count. */
	citp_fdinfo* fdi = fdip_to_fdi(fdip);
	citp_fdinfo_ref(fdi);
	/* Swap the busy marker out again. */
	citp_fdtable_busy_clear(fd, fdip, 0);
        return fdi;
      }
      goto again;
    }
    /* Not normal! */
    else if( fdip_is_busy(fdip) ) {
      citp_fdtable_busy_wait(fd, 0);
      goto again;
    }

  }

  return NULL;
}


static void citp_fdinfo_do_handover(citp_fdinfo* fdi, int fdt_locked)
{
#ifndef NDEBUG
  /* Yuk: does for UDP too. */
  volatile citp_fdinfo_p* p_fdip;
  p_fdip = &citp_fdtable.table[fdi->fd].fdip;
  ci_assert(fdip_is_busy(*p_fdip));
#endif


  Log_V(ci_log("%s: fd=%d nonb_switch=%d", __FUNCTION__, fdi->fd,
	       fdi->on_rcz.handover_nonb_switch));

  if( fdi->epoll_fd >= 0 )
    citp_epollb_on_handover(fdi);
  CI_DEBUG_TRY(ci_tcp_helper_handover(
                ci_netif_get_driver_handle(fdi_to_sock_fdi(fdi)->sock.netif),
                fdi->fd));
  if( fdi->on_rcz.handover_nonb_switch >= 0 ) {
    int on_off = !! fdi->on_rcz.handover_nonb_switch;
    int rc = ci_sys_ioctl(fdi->fd, FIONBIO, &on_off);
    if( rc < 0 )
      Log_E(ci_log("%s: ioctl failed on_off=%d", __FUNCTION__, on_off));
  }
  citp_fdtable_busy_clear(fdi->fd, fdip_passthru, fdt_locked);
  citp_fdinfo_get_ops(fdi)->dtor(fdi, fdt_locked);
  if( fdi->epoll_fd >= 0 )
    citp_epoll_on_handover(fdi, fdt_locked);
  citp_fdinfo_free(fdi);
}


void __citp_fdinfo_ref_count_zero(citp_fdinfo* fdi, int fdt_locked)
{
  Log_V(log("%s: fd=%d on_rcz=%d", __FUNCTION__, fdi->fd,
	    fdi->on_ref_count_zero));

  citp_fdinfo_assert_valid(fdi);
  ci_assert(oo_atomic_read(&fdi->ref_count) == 0);
  ci_assert_ge(fdi->fd, 0);
  ci_assert_lt(fdi->fd, citp_fdtable.inited_count);
  ci_assert_nequal(fdi_to_fdip(fdi), citp_fdtable.table[fdi->fd].fdip);

  switch( fdi->on_ref_count_zero ) {
  case FDI_ON_RCZ_CLOSE:
    if( ! fdt_locked && fdtable_strict() )  CITP_FDTABLE_LOCK();
    fdtable_swap(fdi->fd, fdip_closing, fdip_unknown,
		 fdt_locked | fdtable_strict());
    ci_tcp_helper_close_no_trampoline(fdi->fd);
    citp_fdinfo_get_ops(fdi)->dtor(fdi, fdt_locked | fdtable_strict());
    if( ! fdt_locked && fdtable_strict() )  CITP_FDTABLE_UNLOCK();
    citp_fdinfo_free(fdi);
    break;
  case FDI_ON_RCZ_DUP2:
    dup2_complete(fdi, fdi_to_fdip(fdi), fdt_locked);
    break;
  case FDI_ON_RCZ_HANDOVER:
    citp_fdinfo_do_handover(fdi, fdt_locked);
    break;
  case FDI_ON_RCZ_UNCACHE:
  case FDI_ON_RCZ_MOVED:
    citp_fdinfo_get_ops(fdi)->dtor(fdi, fdt_locked);
    citp_fdinfo_free(fdi);
    break;
  default:
    CI_DEBUG(ci_log("%s: fd=%d on_ref_count_zero=%d", __FUNCTION__,
		    fdi->fd, fdi->on_ref_count_zero));
    ci_assert(0);
  }
}


void citp_fdinfo_assert_valid(citp_fdinfo* fdinfo)
{
  ci_assert(fdinfo);
#if CI_CFG_FD_CACHING
  ci_assert(fdinfo->is_cached || fdinfo->fd >= 0);
#else
  ci_assert(fdinfo->fd >= 0);
#endif
}


void citp_fdinfo_handover(citp_fdinfo* fdi, int nonb_switch)
{
  /* Please see comments in internal.h. */

  volatile citp_fdinfo_p* p_fdip;
  citp_fdinfo_p fdip;
  unsigned fd = fdi->fd;

  /* We're about to free some user-level state, so we need to interlock
  ** against select and poll.
  */
  CITP_FDTABLE_LOCK();

  p_fdip = &citp_fdtable.table[fd].fdip;
 again:
  fdip = *p_fdip;
  if( fdip_is_busy(fdip) )  fdip = citp_fdtable_busy_wait(fd, 1);

  if( fdip == fdi_to_fdip(fdi) ) {
    if( fdip_cas_fail(p_fdip, fdip, fdip_busy) )
      goto again;
  }
  else {
    /* [fd] must have changed meaning under our feet.  It must be closing,
    ** so do nothing except drop the ref passed in.
    */
    ci_assert(fdip_is_closing(fdip));
    ci_assert_nequal(fdi->on_ref_count_zero, FDI_ON_RCZ_NONE);
  }

  CITP_FDTABLE_UNLOCK();

  if( fdip == fdi_to_fdip(fdi) ) {
    ci_assert_equal(fdi->on_ref_count_zero, FDI_ON_RCZ_NONE);
    fdi->on_ref_count_zero = FDI_ON_RCZ_HANDOVER;
    fdi->on_rcz.handover_nonb_switch = nonb_switch;

    /* Drop the fdtable ref.  When the ref count goes to zero, the handover
    ** will be done.  We return without waiting, because the caller
    ** shouldn't do anything more with this socket anyway.
    */
    citp_fdinfo_release_ref(fdi, 0);
  }

  /* Drop the ref passed in. */
  citp_fdinfo_release_ref(fdi, 0);
}


#if CI_CFG_FD_CACHING

/* Called by citp_fdtable_new_fd_set() to clean-up user-level state when a
** new file descriptor appears where a cached fd used to be.
*/
static void citp_fdinfo_uncache(citp_fdinfo* fdi, int fdt_locked)
{
  Log_V(ci_log("%s: fd=%d locked=%d", __FUNCTION__, fdi->fd, fdt_locked));

  ci_assert(fdi);
  ci_assert(fdi->is_cached);
  CITP_FDTABLE_ASSERT_LOCKED(fdt_locked);
  ci_assert(fdi->protocol == &citp_tcp_cached_protocol_impl);
  ci_assert_ge(fdi->fd, 0);
  ci_assert_lt(fdi->fd, citp_fdtable.inited_count);
  ci_assert_nequal(citp_fdtable.table[fdi->fd].fdip, fdi_to_fdip(fdi));

  /* Free-up this fdi.  NB. It may still be being used by other threads, so
  ** we can't just free it.  Also we mustn't close the [fd] in this
  ** case. */
  ci_assert_equal(fdi->on_ref_count_zero, FDI_ON_RCZ_NONE);
  fdi->on_ref_count_zero = FDI_ON_RCZ_UNCACHE;
  citp_fdinfo_release_ref(fdi, fdt_locked);
}

#endif


/* This function is called from citp_netif_child_fork_hook() only.
 * It handles any non-standard fdip, not only cached ones: it also
 * "fixes" busy fdip.
 */
void citp_fdtable_close_cached(void)
{
  unsigned fd;

  for (fd = 0; fd < citp_fdtable.inited_count; fd++) {
    citp_fdinfo_p fdip = citp_fdtable.table[fd].fdip;

    /* Parent has forked when one of its threads had made an fdtable
     * entry busy.  Here in the child no-one will clear the busy state.
     * We can't do any better than just clearing back to the unknown
     * state. */
    if (fdip_is_busy(fdip)) {
      citp_fdtable.table[fd].fdip = fdip_unknown;
      continue;
    }

#if CI_CFG_FD_CACHING
    {
      citp_fdinfo* fdi;
      if (!fdip_is_normal(fdip))
        continue;
      fdi = fdip_to_fdi(fdip);
      if (!fdi->is_cached)
        continue;
      fdtable_swap(fd, fdip, fdip_unknown, 1);
      ci_tcp_helper_close_no_trampoline(fd);
      citp_fdinfo_free(fdi);
    }
#endif
  }
}


void
citp_fdtable_new_fd_set(unsigned fd, citp_fdinfo_p new_fdip, int fdt_locked)
{
  volatile citp_fdinfo_p* p_fdip;
  citp_fdinfo_p prev;

  if( fd >= citp_fdtable.inited_count ) {
    ci_assert_lt(fd, citp_fdtable.size);
    if( ! fdt_locked )  CITP_FDTABLE_LOCK();
    __citp_fdtable_extend(fd);
    if( ! fdt_locked )  CITP_FDTABLE_UNLOCK();
  }

  p_fdip = &citp_fdtable.table[fd].fdip;

  do {
    prev = *p_fdip;

    /* Busy?  Perhaps just closed, but not yet marked unknown.  Or perhaps it
    ** is being probed. */
    if( fdip_is_busy(prev) )
      prev = citp_fdtable_busy_wait(fd, fdt_locked);

    /* There is a close in progress, so we wait until it is resolved. */
    if( fdip_is_closing(prev) )
      prev = citp_fdtable_closing_wait(fd, fdt_locked);

    /* Reserved?  Perhaps it was a netif fd that has just been closed.  So it
    ** should be about to be unreserved. */
  } while (fdip_is_reserved(prev) || fdip_cas_fail(p_fdip, prev, new_fdip) );

  if( fdip_is_normal(prev) ) {
#if CI_CFG_FD_CACHING
    /* Lazy uncache of socket uncached in kernel. */
    citp_fdinfo* fdi = fdip_to_fdi(prev);
    ci_assert(fdi->is_cached);
    if( fdi->is_cached )
      citp_fdinfo_uncache(fdi, fdt_locked);
    else
#endif
    {
      /* We can get here is close-trampolining fails.  So for release
      ** builds we accept that the user-level state got out-of-sync, and
      ** leak [fdi] since it seems like a suitably cautious thing to do.
      */
      ci_log("%s: ERROR: Orphaned entry in user-level fd-table",
             __FUNCTION__);
    }
  }
  else
    /* We (at time of writing) only register a trampoline handler when we
    ** create a netif, so we can miss the closing of pass-through
    ** descriptors.
    */
    ci_assert(fdip_is_unknown(prev) || fdip_is_passthru(prev));
}


void citp_fdtable_insert(citp_fdinfo* fdi, unsigned fd, int fdt_locked)
{
  ci_assert(fdi);
  ci_assert(fdi->protocol);
  ci_assert(citp_fdtable.inited_count > fd);
  ci_assert_ge(oo_atomic_read(&fdi->ref_count), 1);

  fdi->fd = fd;
  CI_DEBUG(fdi->on_ref_count_zero = FDI_ON_RCZ_NONE);
#if CI_CFG_FD_CACHING
  fdi->is_cached = 0;
#endif
  fdi->is_special = 0;
  citp_fdtable_busy_clear(fd, fdi_to_fdip(fdi), fdt_locked);
}


void __citp_fdtable_busy_clear_slow(unsigned fd, citp_fdinfo_p new_fdip,
				    int fdt_locked)
{
  volatile citp_fdinfo_p* p_fdip = &citp_fdtable.table[fd].fdip;
  citp_fdinfo_p fdip, next;
  citp_fdtable_waiter* waiter;

  ci_assert(fd < citp_fdtable.inited_count);

 again:
  fdip = *p_fdip;
  ci_assert(fdip_is_busy(fdip));
  waiter = fdip_to_waiter(fdip);
  ci_assert(waiter);
  ci_assert(fdip_is_busy(waiter->next));
  if( waiter->next == fdip_busy )  next = new_fdip;
  else                             next = waiter->next;
  if( fdip_cas_fail(p_fdip, fdip, next) )  goto again;

  oo_rwlock_cond_broadcast(&waiter->cond, &citp_ul_lock, fdt_locked);

  if( next != new_fdip )  goto again;
}


citp_fdinfo_p citp_fdtable_busy_wait(unsigned fd, int fdt_locked)
{
  volatile citp_fdinfo_p* p_fdip = &citp_fdtable.table[fd].fdip;
  citp_fdtable_waiter waiter;
  int saved_errno = errno;

  Log_V(ci_log("%s: fd=%u", __FUNCTION__, fd));

  ci_assert(ci_is_multithreaded());

  oo_rwlock_cond_init(&waiter.cond);
  if( ! fdt_locked )  CITP_FDTABLE_LOCK();
 again:
  waiter.next = *p_fdip;
  if( fdip_is_busy(waiter.next) ) {
    if( fdip_cas_succeed(p_fdip, waiter.next, waiter_to_fdip(&waiter)) )
      oo_rwlock_cond_wait(&waiter.cond, &citp_ul_lock);
    goto again;
  }
  if( ! fdt_locked )  CITP_FDTABLE_UNLOCK();
  oo_rwlock_cond_destroy(&waiter.cond);

  errno = saved_errno;
  return waiter.next;
}


static citp_fdinfo_p citp_fdtable_closing_wait(unsigned fd, int fdt_locked)
{
  /* We're currently spinning in this case.  Not ideal, but implementing
  ** blocking here is slightly tricky.  (Can be done, but I want proof that
  ** it's needed first!)
  */
  volatile citp_fdinfo_p* p_fdip = &citp_fdtable.table[fd].fdip;
  citp_fdinfo_p fdip;

  Log_V(ci_log("%s: fd=%u", __FUNCTION__, fd));

 again:
  fdip = *p_fdip;
  if( fdip_is_busy(fdip)    )  fdip = citp_fdtable_busy_wait(fd, fdt_locked);
  if( fdip_is_closing(fdip) ) {
    if( fdt_locked ) {
      /* Need to drop the lock to avoid deadlock with the other thread
      ** trying to closing this fd! */
      CITP_FDTABLE_UNLOCK();
      CITP_FDTABLE_LOCK();
    }
    goto again;
  }
  return fdip;
}


void __citp_fdtable_reserve(int fd, int protect)
{
  /* Must be holding the lock. */
  CITP_FDTABLE_ASSERT_LOCKED(1);
  ci_assert ((unsigned) fd < citp_fdtable.size);

  if( protect )  citp_fdtable_new_fd_set(fd, fdip_reserved, 1);
  else           fdtable_swap(fd, fdip_reserved, fdip_unknown, 1);
}


/**********************************************************************
 * citp_ep_dup()
 */

int citp_ep_dup_dup(int oldfd, long arg_unused)
{
  return ci_sys_dup(oldfd);
}


int citp_ep_dup_fcntl_dup(int oldfd, long arg)
{
  return ci_sys_fcntl(oldfd, F_DUPFD, arg);
}

#ifdef F_DUPFD_CLOEXEC
int citp_ep_dup_fcntl_dup_cloexec(int oldfd, long arg)
{
  return ci_sys_fcntl(oldfd, F_DUPFD_CLOEXEC, arg);
}
#endif

/*
** Why do these live here?  Because they need to hack into the low-level
** dirty nastiness of the fdtable.
*/
int citp_ep_dup(unsigned oldfd, int (*syscall)(int oldfd, long arg),
		long arg)
{
  /* This implements dup(oldfd) and fcntl(oldfd, F_DUPFD, arg). */

  volatile citp_fdinfo_p* p_oldfdip;
  citp_fdinfo_p oldfdip;
  citp_fdinfo* newfdi = 0;
  int newfd;

  Log_V(log("%s(%d)", __FUNCTION__, oldfd));

  if(CI_UNLIKELY( citp.init_level < CITP_INIT_FDTABLE ))
    /* Lib not initialised, so no U/L state, and therefore system dup()
    ** will do just fine. */
    return syscall(oldfd, arg);

  if( oldfd >= citp_fdtable.inited_count ) {
    /* NB. We can't just pass through in this case because we need to worry
    ** about other threads racing with us.  So we need to be able to lock
    ** this fd while we do the dup. */
    ci_assert(oldfd < citp_fdtable.size);
    CITP_FDTABLE_LOCK();
    __citp_fdtable_extend(oldfd);
    CITP_FDTABLE_UNLOCK();
  }

  p_oldfdip = &citp_fdtable.table[oldfd].fdip;
 again:
  oldfdip = *p_oldfdip;
  if( fdip_is_busy(oldfdip) )
    oldfdip = citp_fdtable_busy_wait(oldfd, 0);
  if( fdip_is_closing(oldfdip) | fdip_is_reserved(oldfdip) ) {
    errno = EBADF;
    return -1;
  }
  if( fdip_cas_fail(p_oldfdip, oldfdip, fdip_busy) )  goto again;

  if( fdip_is_passthru(oldfdip) | fdip_is_unknown(oldfdip) ) {
    if( fdtable_strict() )  CITP_FDTABLE_LOCK();
    newfd = syscall(oldfd, arg);
    if( newfd < citp_fdtable.inited_count )
      citp_fdtable_new_fd_set(newfd, oldfdip, fdtable_strict());
    if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
    /* If outside inited_count then if someone wants it they'll probe it. */
  }
  else {
    citp_fdinfo* oldfdi = fdip_to_fdi(oldfdip);

    newfdi = citp_fdinfo_get_ops(oldfdi)->dup(oldfdi);
    if( ! newfdi ) {
      citp_fdtable_busy_clear(oldfd, oldfdip, 0);
      errno = ENOMEM;
      return -1;
    }

    if( fdtable_strict() )  CITP_FDTABLE_LOCK();
    newfd = syscall(oldfd, arg);
    if( newfd >= 0 )
      citp_fdtable_new_fd_set(newfd, fdip_busy, fdtable_strict());
    if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
    if( newfd >= 0 ) {
      citp_fdtable_insert(newfdi, newfd, 0);
      newfdi = 0;
    }
  }

  citp_fdtable_busy_clear(oldfd, oldfdip, 0);
  if( newfdi )  citp_fdinfo_free(newfdi);
  return newfd;
}


static void dup2_complete(citp_fdinfo* prev_tofdi,
			  citp_fdinfo_p prev_tofdip, int fdt_locked)
{
  volatile citp_fdinfo_p *p_fromfdip;
  unsigned fromfd = prev_tofdi->on_rcz.dup2_fd;
  unsigned tofd = prev_tofdi->fd;
  citp_fdinfo_p fromfdip;
  int rc;

#ifndef NDEBUG
  volatile citp_fdinfo_p* p_tofdip;
  p_tofdip = &citp_fdtable.table[tofd].fdip;
  ci_assert(fdip_is_busy(*p_tofdip));
#endif

  p_fromfdip = &citp_fdtable.table[fromfd].fdip;
 lock_fromfdip_again:
  fromfdip = *p_fromfdip;
  if( fdip_is_busy(fromfdip) )
    fromfdip = citp_fdtable_busy_wait(fromfd, fdt_locked);
  if( fdip_is_closing(fromfdip) | fdip_is_reserved(fromfdip) ) {
    prev_tofdi->on_rcz.dup2_result = -EBADF;
    ci_wmb();
    prev_tofdi->on_ref_count_zero = FDI_ON_RCZ_DONE;
    return;
  }
  if( fdip_cas_fail(p_fromfdip, fromfdip, fdip_busy) )
    goto lock_fromfdip_again;

  oo_rwlock_lock_write(&citp_dup2_lock);
  rc = ci_sys_dup2(fromfd, tofd);
  oo_rwlock_unlock_write(&citp_dup2_lock);
  if( rc < 0 ) {
    citp_fdtable_busy_clear(fromfd, fromfdip, fdt_locked);
    prev_tofdi->on_rcz.dup2_result = -errno;
    ci_wmb();
    prev_tofdi->on_ref_count_zero = FDI_ON_RCZ_DONE;
    return;
  }

  ci_assert(fdip_is_normal(fromfdip) | fdip_is_passthru(fromfdip) |
	    fdip_is_unknown(fromfdip));

  if( fdip_is_normal(fromfdip) ) {
    citp_fdinfo* fromfdi = fdip_to_fdi(fromfdip);
    citp_fdinfo* newfdi = citp_fdinfo_get_ops(fromfdi)->dup(fromfdi);
    if( newfdi ) {
      citp_fdinfo_init(newfdi, fdip_to_fdi(fromfdip)->protocol);
      citp_fdtable_insert(newfdi, tofd, fdt_locked);
    }
    else
      /* Out of memory.  Let's hope we have more memory when this gets
      ** probed! */
      citp_fdtable_busy_clear(tofd, fdip_unknown, fdt_locked);
  }
  else
    citp_fdtable_busy_clear(tofd, fromfdip, fdt_locked);

  citp_fdtable_busy_clear(fromfd, fromfdip, fdt_locked);
  prev_tofdi->on_rcz.dup2_result = tofd;
  ci_wmb();
  prev_tofdi->on_ref_count_zero = FDI_ON_RCZ_DONE;
}

pthread_mutex_t citp_dup_lock = PTHREAD_MUTEX_INITIALIZER;

int citp_ep_dup2(unsigned fromfd, unsigned tofd)
{
  volatile citp_fdinfo_p* p_tofdip;
  citp_fdinfo_p tofdip;
  unsigned max;

  Log_V(log("%s(%d, %d)", __FUNCTION__, fromfd, tofd));

  if( fromfd == tofd )
    /* Nothing to do here.  Moreover, we'd better not even try, since when
    ** we try to add "tofd" the fdtable we'll be surprised to see
    ** something already there! */
    return 0;

  /* Hack: if [tofd] is the fd we're using for logging, we'd better choose
  ** a different one!
  */
  if( tofd == citp.log_fd )  citp_log_change_fd();

  if(CI_UNLIKELY( citp.init_level < CITP_INIT_FDTABLE ))
    /* Lib not initialised, so no U/L state, and therefore system dup2()
    ** will do just fine. */
    return ci_sys_dup2(fromfd, tofd);

  max = CI_MAX(fromfd, tofd);
  if( max >= citp_fdtable.inited_count ) {
    ci_assert(max < citp_fdtable.size);
    CITP_FDTABLE_LOCK();
    __citp_fdtable_extend(max);
    CITP_FDTABLE_UNLOCK();
  }

  /* Bug1151: Concurrent threads doing dup2(x,y) and dup2(y,x) can deadlock
  ** against one another.  So we take out a fat lock to prevent concurrent
  ** dup2()s.
  */
  /* Lock tofd.  We need to interlock against select and poll etc, so we
  ** also grab the exclusive lock.  Also grab the bug1151 lock.
  */
  pthread_mutex_lock(&citp_dup_lock);
  CITP_FDTABLE_LOCK();
  p_tofdip = &citp_fdtable.table[tofd].fdip;
 lock_tofdip_again:
  tofdip = *p_tofdip;
  if( fdip_is_busy(tofdip) )
    tofdip = citp_fdtable_busy_wait(tofd, 1);
  if( fdip_is_closing(tofdip) )
    tofdip = citp_fdtable_closing_wait(tofd, 1);
  if( fdip_is_reserved(tofdip) ) {
    /* ?? FIXME: we can't cope with this at the moment */
    CITP_FDTABLE_UNLOCK();
    Log_U(log("%s(%d, %d): target is reserved", __FUNCTION__, fromfd, tofd));
    errno = EBUSY;
    tofd = -1;
    goto out;
  }
  if( fdip_cas_fail(p_tofdip, tofdip, fdip_busy) )
    goto lock_tofdip_again;
  CITP_FDTABLE_UNLOCK();
  ci_assert(fdip_is_normal(tofdip) | fdip_is_passthru(tofdip) |
 	    fdip_is_unknown(tofdip));

  if( fdip_is_normal(tofdip) ) {
    /* We're duping onto a user-level socket. */
    citp_fdinfo* tofdi = fdip_to_fdi(tofdip);
    ci_verify(citp_fdinfo_get_ops(tofdi)->close(tofdi, 0) != 1);
    ci_assert_equal(tofdi->on_ref_count_zero, FDI_ON_RCZ_NONE);
    tofdi->on_ref_count_zero = FDI_ON_RCZ_DUP2;
    tofdi->on_rcz.dup2_fd = fromfd;
    citp_fdinfo_release_ref(tofdi, 0);
    {
      int i = 0;
      /* We need to free this fdi.  If someone is using it right now,
       * we are in trouble.  So, we spin for a while and interrupt the
       * user.  See bug 28123. */
      while( tofdi->on_ref_count_zero != FDI_ON_RCZ_DONE ) {
        if( ci_is_multithreaded() && i % 10000 == 9999 ) {
          pthread_t pth = tofdi->thread_id;
          if( pth !=  pthread_self() && pth != PTHREAD_NULL ) {
            pthread_kill(pth, SIGONLOAD);
            sleep(1);
          }
        }
        ci_spinloop_pause();
        i++;
      }
    }
    if( tofdi->on_rcz.dup2_result < 0 ) {
      errno = -tofdi->on_rcz.dup2_result;
      /* Need to re-insert [tofdi] into the table. */
      ci_assert_equal(oo_atomic_read(&tofdi->ref_count), 0);
      oo_atomic_set(&tofdi->ref_count, 1);
      CI_DEBUG(tofdi->on_ref_count_zero = FDI_ON_RCZ_NONE);
      citp_fdtable_busy_clear(tofd, tofdip, 0);
      tofd = -1;
    }
    else {
      ci_assert(tofdi->on_rcz.dup2_result == tofd);
      citp_fdinfo_get_ops(tofdi)->dtor(tofdi, 0);
      citp_fdinfo_free(tofdi);
    }
    goto out;
  }

  ci_assert(fdip_is_passthru(tofdip) | fdip_is_unknown(tofdip));

  { /* We're dupping onto an O/S descriptor, or it may be closed.  Create a
    ** dummy [citp_fdinfo], just so we can share code with the case above.
    */
    citp_fdinfo fdi;
    fdi.fd = tofd;
    fdi.on_rcz.dup2_fd = fromfd;
    dup2_complete(&fdi, tofdip, 0);
    if( fdi.on_rcz.dup2_result < 0 ) {
      errno = -fdi.on_rcz.dup2_result;
      citp_fdtable_busy_clear(tofd, tofdip, 0);
      tofd = -1;
    }
    else
      ci_assert(fdi.on_rcz.dup2_result == tofd);
  }

 out:
  pthread_mutex_unlock(&citp_dup_lock);
  return tofd;
}


/**********************************************************************
 * citp_ep_close()
 */

int citp_ep_close(unsigned fd)
{
  volatile citp_fdinfo_p* p_fdip;
  citp_fdinfo_p fdip;
  int rc, got_lock;

  /* Interlock against other closes, against the fdtable being extended,
  ** and against select and poll.
  */
  CITP_FDTABLE_LOCK();
  got_lock = 1;

  __citp_fdtable_extend(fd);

  if( fd >= citp_fdtable.inited_count ) {
    rc = ci_sys_close(fd);
    goto done;
  }

  p_fdip = &citp_fdtable.table[fd].fdip;
 again:
  fdip = *p_fdip;
  if( fdip_is_busy(fdip) )  fdip = citp_fdtable_busy_wait(fd, 1);

  if( fdip_is_closing(fdip) | fdip_is_reserved(fdip) ) {
    /* Concurrent close or attempt to close reserved. */
    Log_V(ci_log("%s: fd=%d closing=%d reserved=%d", __FUNCTION__, fd,
		 fdip_is_closing(fdip), fdip_is_reserved(fdip)));
    errno = EBADF;
    rc = -1;
    goto done;
  }

  ci_assert(fdip_is_normal(fdip) | fdip_is_passthru(fdip) |
	    fdip_is_unknown(fdip));

  /* Swap in the "closed" pseudo-fdinfo.  This lets any other thread know
  ** that we're in the middle of closing this fd.
  */
  if( fdip_cas_fail(p_fdip, fdip, fdip_closing) )
    goto again;

  if( fdip_is_normal(fdip) ) {
    citp_fdinfo* fdi = fdip_to_fdi(fdip);

    CITP_FDTABLE_UNLOCK();
    got_lock = 0;

    if( fdi->is_special ) {
      Log_V(ci_log("%s: fd=%d is_special, returning EBADF", __FUNCTION__, fd));
      errno = EBADF;
      rc = -1;
      fdtable_swap(fd, fdip_closing, fdip, 0);
      goto done;
    }

    rc = citp_fdinfo_get_ops(fdi)->close(fdi, 1);
#if CI_CFG_FD_CACHING
    if( rc == 1 ) {
      /* We've decided to cache this socket.  So we don't actually close
      ** the file descriptor, but pretend that we have.  The close op will
      ** have replaced the ops to make it look closed.
      */
      ci_assert(fdi->is_cached);
      Log_V(ci_log("%s: fd=%d is now cached", __FUNCTION__, fd));
      rc = 0;
      fdtable_swap(fd, fdip_closing, fdip, 0);
      goto done;
    }
#endif

    Log_V(ci_log("%s: fd=%d u/l socket", __FUNCTION__, fd));
    ci_assert_equal(fdi->fd, fd);
    ci_assert_equal(fdi->on_ref_count_zero, FDI_ON_RCZ_NONE);
    fdi->on_ref_count_zero = FDI_ON_RCZ_CLOSE;
    citp_fdinfo_release_ref(fdi, 0);
  }
  else {
    ci_assert(fdip_is_passthru(fdip) ||
	      fdip_is_unknown(fdip));
    if( ! fdtable_strict() ) {
      CITP_FDTABLE_UNLOCK();
      got_lock = 0;
    }
    Log_V(ci_log("%s: fd=%d passthru=%d unknown=%d", __FUNCTION__, fd,
		 fdip_is_passthru(fdip), fdip_is_unknown(fdip)));
    fdtable_swap(fd, fdip_closing, fdip_unknown, fdtable_strict());
    rc = ci_tcp_helper_close_no_trampoline(fd);
  }

 done:
  if( got_lock )  CITP_FDTABLE_UNLOCK();
  FDTABLE_ASSERT_VALID();
  return rc;
}

/*! \cidoxg_end */
