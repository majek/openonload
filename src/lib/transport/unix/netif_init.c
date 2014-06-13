/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
*//*! \file netif_init.c
** <L5_PRIVATE L5_SOURCE>
** \author  stg
**  \brief  Common functionality used by TCP & UDP
**   \date  2004/06/09
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_unix */

#include <internal.h>
#include <ci/internal/transport_config_opt.h>
#include <ci/tools/sllist.h>


#define LPF "citp_netif_"
#define LPFIN "-> " LPF
#define LPFOUT "<- " LPF


int citp_netif_init_ctor(void)
{
  Log_S(ci_log("%s()", __FUNCTION__));

  citp_set_log_level(CITP_OPTS.log_level);

  citp_cmn_netif_init_ctor(CITP_OPTS.netif_dtor);

  return 0;
}

/* Storage for stackname context across fork() */
static struct oo_stackname_state stackname_config_across_fork;

/* Storage for library context across fork() */
static citp_lib_context_t citp_lib_context_across_fork;

/* Lock to protect citp_lib_context_across_fork across fork(). 
 * Signal handlers should not call fork(), so this lock may not be 
 * protected by citp_enter_lib()/citp_exit_lib() */
static citp_ul_lock_t citp_fork_lock;

/* I do not understand why, but __register_atfork seems to work better than
 * __libc_atfork */
extern int __register_atfork(void (*prepare)(void), void (*parent)(void), 
                             void (*child)(void), void *dso);

int ci_setup_fork(void)
{
    Log_CALL(ci_log("%s()", __FUNCTION__));
    CITP_LOCK_CTOR(&citp_fork_lock);
    return __register_atfork(citp_netif_pre_fork_hook,
                             citp_netif_parent_fork_hook, 
                             citp_netif_child_fork_hook, NULL);
}


/* Handles user-level netif internals pre fork() */
void citp_netif_pre_fork_hook(void)
{
  struct oo_stackname_state *stackname_state;

  /* If we have not inited fork hook, how can we get here in the first
   * place? */
  if( citp.init_level < CITP_INIT_FORK_HOOKS) {
    ci_assert(0);
    return;
  }

  Log_CALL(ci_log("%s()", __FUNCTION__));

  CITP_LOCK(&citp_fork_lock);

  if( citp.init_level < CITP_INIT_FDTABLE )
    return;

  citp_enter_lib(&citp_lib_context_across_fork);
  CITP_LOCK(&citp_ul_lock);

  if( citp.init_level < CITP_INIT_NETIF )
    return;

  stackname_state = oo_stackname_thread_get();
  memcpy(&stackname_config_across_fork, stackname_state, 
         sizeof(stackname_config_across_fork));
  
  /* If the call to _fork() subsequently fails we potentially have
   * marked all of our netifs as shared when ideally we shouldn't
   * have.  However, this is non-fatal and is probably the least of
   * our worries if the system can't fork!
   */
  __citp_netif_mark_all_shared();
  if( CITP_OPTS.fork_netif == CI_UNIX_FORK_NETIF_BOTH )
    __citp_netif_mark_all_dont_use();
}

/* Handles user-level netif internals post fork() in the parent */
void citp_netif_parent_fork_hook(void)
{
  /* If we have not inited fork hook, how can we get here in the first
   * place? */
  if( citp.init_level < CITP_INIT_FORK_HOOKS) {
    ci_assert(0);
    return;
  }

  Log_CALL(ci_log("%s()", __FUNCTION__));

  if( citp.init_level < CITP_INIT_FDTABLE)
    goto unlock_fork;
  else if( citp.init_level < CITP_INIT_NETIF)
    goto unlock;

  if( CITP_OPTS.fork_netif == CI_UNIX_FORK_NETIF_PARENT ) 
    __citp_netif_mark_all_dont_use();

unlock:
  CITP_UNLOCK(&citp_ul_lock);
  citp_exit_lib(&citp_lib_context_across_fork, 0);
unlock_fork:
  CITP_UNLOCK(&citp_fork_lock);
}

/* Handles user-level netif internals post fork() in the child */
void citp_netif_child_fork_hook(void)
{
  ci_netif* ni;

  /* If we have not inited fork hook, how can we get here in the first
   * place? */
  if( citp.init_level < CITP_INIT_FORK_HOOKS) {
    ci_assert(0);
    return;
  }

  /* We can't just use CITP_UNLOCK since we are not allowed to call
   * non-async-safe functions from the child hook.
   * For now we are the only thread so we may re-init all locks.
   *
   * Formally, we are not allowed to do this: these are not async-safe
   * functions.  However, "The GNU C Library Reference Manual" tells us in
   * "POSIX Threads" -> "Threads and Fork":
   * "... install handlers with pthread_atfork as follows: have the prepare
   * handler lock the mutexes (in locking order), and the parent handler
   * unlock the mutexes. The child handler should reset the mutexes using
   * pthread_mutex_init, as well as any other synchronization objects such
   * as condition variables."
   * So, we just follow this book recommendation.
   */
  CITP_LOCK_CTOR(&citp_fork_lock);

  if( citp.init_level < CITP_INIT_FDTABLE)
    return;

  CITP_LOCK(&citp_fork_lock);
  CITP_LOCK_CTOR(&citp_ul_lock);
  CITP_LOCK(&citp_ul_lock);

  if( citp.init_level < CITP_INIT_NETIF)
    goto setup_fdtable;

  citp_setup_logging_prefix();
  Log_CALL(ci_log("%s()", __FUNCTION__));

  ni = __citp_get_any_netif();

  if( ni ) {
    /* Register the trampoline.  FIXME: What should we do if this
     * fails? */
    CI_DEBUG_TRY(citp_init_trampoline(ci_netif_get_driver_handle(ni)));
  }

  oo_stackname_update(&stackname_config_across_fork);

  if( CITP_OPTS.fork_netif == CI_UNIX_FORK_NETIF_CHILD ) 
    __citp_netif_mark_all_dont_use();

setup_fdtable:
  /*
  ** Ditch fds marked as cached endpoints. We only want them to remain
  ** cached in the parent table.
  */
  citp_fdtable_close_cached(1);

  CITP_UNLOCK(&citp_ul_lock);
  citp_exit_lib(&citp_lib_context_across_fork, 0);
  CITP_UNLOCK(&citp_fork_lock);
}

/* Handles user-level netif internals pre bproc_move() */
void citp_netif_pre_bproc_move_hook(void)
{
  CITP_LOCK(&citp_ul_lock);

  /* Remove any user-level destruct protection from the active netifs,
   * also remove the reference given to each netif if netif
   * destruction has been disabled (EF_NETIF_DTOR=0).  We want no open
   * endpoints, sockets or references to EtherFabric devices at the
   * time of the bproc_move().
   */
  __citp_netif_unprotect_all();
  
  CITP_UNLOCK(&citp_ul_lock);
}


/* Move a NIC file descriptor away from fds 0, 1 or 2.
 *
 * It is assumed that this is called immediately after ef_onload_driver_open(), if
 * necessary, so we don't need to worry about any updating of the fdtable.
 */
static int __citp_netif_move_fd(ef_driver_handle* fd)
{
  int rc;

  /* means the first available fd >= 3 */
  rc = oo_fcntl_dupfd_cloexec(*fd, 3);
  if (rc >= 0) {
    ci_sys_close(*fd);
    Log_V(ci_log("%s: fd %d moved to %d", __FUNCTION__, *fd, rc));
    *fd = rc;
    rc = 0;
  }
  else {
    Log_E(ci_log("%s: move of fd %d failed", __FUNCTION__, *fd));
  }

  return rc;
}


static dev_t onloadfs_dev_t = 0;
dev_t citp_onloadfs_dev_t(void)
{
  if( onloadfs_dev_t == 0 ) {
    int fd;
    if( fdtable_strict() )  CITP_FDTABLE_LOCK();
    if( ef_onload_driver_open(&fd, 1) != 0 ) {
      Log_E(log("%s: Failed to open /dev/onload", __FUNCTION__));
      if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
      return 0;
    }
    if( ci_sys_ioctl(fd, OO_IOC_GET_ONLOADFS_DEV, &onloadfs_dev_t) != 0 ) {
      Log_E(log("%s: Failed to find onloadfs dev_t", __FUNCTION__));
    }
    ci_sys_close(fd);
    if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
  }
  return onloadfs_dev_t;
}

/* Platform specific code, called after netif construction */
void  citp_netif_ctor_hook(ci_netif* ni, int realloc)
{
  if (!realloc) {
    /* Don't want netifs on fds 0..3 - move it elsewhere.
     * TODO: This is kind of sucks -- not exactly elegant.
     *       Perhaps a better approach is to grow the fdtable but pretend to
     *       the user that it's smaller.  Then any FDs we need can be placed in
     *       the "invisible" part of the fd table.
     */
    if (ci_netif_get_driver_handle(ni) <= 3) {
      CI_DEBUG_TRY(__citp_netif_move_fd(&(ni->driver_handle)));
    }

    /* Protect the netif's FD table entry */
    __citp_fdtable_reserve(ci_netif_get_driver_handle(ni), 1);
  }

  /* Make sure the trampoline is registered. */
  CI_DEBUG_TRY(citp_init_trampoline(ci_netif_get_driver_handle(ni)));

  /* Init onloadfs_dev_t if necessary */
  if( onloadfs_dev_t == 0 )
    ci_sys_ioctl(ci_netif_get_driver_handle(ni), OO_IOC_GET_ONLOADFS_DEV,
                 &onloadfs_dev_t);
}


/* Platform specific code, called proir to netif destruction */
void  citp_netif_free_hook(ci_netif* ni)
{
  /* Unprotect the netif's FD table entry */
  __citp_fdtable_reserve(ci_netif_get_driver_handle(ni), 0);
}

/*! \cidoxg_end */
