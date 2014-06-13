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
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  kjm
**  \brief  Intercept of onload extension API calls
**   \date  2010/12/11
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#define _GNU_SOURCE /* for dlsym(), RTLD_NEXT, etc */

#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>

#include "internal.h"
#include <onload/extensions.h>
#include <onload/ul/stackname.h>
#include <ci/internal/tls.h>

#if CI_CFG_USERSPACE_PIPE
#include "ul_pipe.h"
#endif

#if CI_CFG_USERSPACE_EPOLL
#include "ul_epoll.h"
#endif


int onload_is_present(void)
{
  return 1;
}


static int onload_fd_stat_netif(ci_netif *ni, struct onload_stat* stat)
{
  int len;

  stat->stack_id = NI_ID(ni);
  len = strlen(ni->state->name);
  stat->stack_name = malloc(len + 1);
  if( stat->stack_name == NULL )
    return -ENOMEM;
  strcpy(stat->stack_name, ni->state->name);
  return 1;
}


int onload_fd_stat(int fd, struct onload_stat* stat)
{
  citp_fdinfo* fdi;
  citp_sock_fdi* sock_epi;
  citp_pipe_fdi* pipe_epi;
  int rc;
  citp_lib_context_t lib_context;

  citp_enter_lib(&lib_context);

  if( (fdi = citp_fdtable_lookup(fd)) != NULL ) {
    switch( citp_fdinfo_get_type(fdi) ) {
    case CITP_UDP_SOCKET:
    case CITP_TCP_SOCKET:
      sock_epi = fdi_to_sock_fdi(fdi);
      stat->endpoint_id = SC_FMT(sock_epi->sock.s);
      stat->endpoint_state = sock_epi->sock.s->b.state;
      rc = onload_fd_stat_netif(sock_epi->sock.netif, stat);
      break;
#if CI_CFG_USERSPACE_EPOLL
    case CITP_EPOLL_FD:
      rc = 0;
      break;
#endif
#if CI_CFG_USERSPACE_PIPE
    case CITP_PIPE_FD:
      pipe_epi = fdi_to_pipe_fdi(fdi);
      stat->endpoint_id = -1;
      stat->endpoint_state = 0;
      rc = onload_fd_stat_netif(pipe_epi->ni, stat);
      break;
#endif
    default:
      LOG_U(log("%s: unknown fdinfo type %d", __FUNCTION__, 
                citp_fdinfo_get_type(fdi)));
      rc = 0;
    }
    citp_fdinfo_release_ref(fdi, 0);
  }
  else
    rc = 0;
  citp_exit_lib(&lib_context, TRUE);
  return rc;
}


static void onload_thread_set_spin2(enum onload_spin_type type, int spin)
{
  struct oo_per_thread* pt = oo_per_thread_get();
  if( spin ) 
    pt->spinstate |= (1 << type);
  else
    pt->spinstate &= ~(1 << type);
}


int onload_thread_set_spin(enum onload_spin_type type, int spin) 
{
  if( (unsigned) type >= (unsigned) ONLOAD_SPIN_MAX )
    return -EINVAL;

  if( type == ONLOAD_SPIN_ALL ) {
    for( type = ONLOAD_SPIN_ALL + 1; type < ONLOAD_SPIN_MAX; ++type )
      onload_thread_set_spin2(type, spin);
  }
  else {
    onload_thread_set_spin2(type, spin);
  }

  return 0;
}

int onload_move_fd(int fd)
{
  ef_driver_handle fd_ni;
  ci_fixed_descriptor_t op_arg;
  int rc;
  ci_netif* ni;
  citp_lib_context_t lib_context;
  citp_fdinfo *fdi;

  Log_CALL(ci_log("%s(%d)", __func__, fd));
  citp_enter_lib(&lib_context);

  rc = citp_netif_alloc_and_init(&fd_ni, &ni);
  if( rc != 0 )
    goto out;

  op_arg = ci_netif_get_driver_handle(ni);
  rc = oo_resource_op(fd, OO_IOC_MOVE_FD, &op_arg);
  if( rc != 0 )
    goto out;

  fdi = citp_fdtable_lookup(fd);
  fdi = citp_reprobe_moved(fdi, CI_FALSE);
  citp_fdinfo_release_ref(fdi, CI_FALSE);

out:
  citp_exit_lib(&lib_context, CI_TRUE);
  Log_CALL_RESULT(rc);
  return rc;
}


static int onload_fd_check_msg_warm(int fd)
{
  struct onload_stat stat = { .stack_name = NULL };
  int ok = CI_TCP_STATE_SOCKET | CI_TCP_STATE_TCP | CI_TCP_STATE_TCP_CONN;
  int rc;

  if ( ( onload_fd_stat(fd, &stat) > 0 ) &&
       ( ok == (stat.endpoint_state & ok) ) )
    rc = 1;
  else
    rc = 0;

  free(stat.stack_name);

  return rc;
}

int onload_fd_check_feature(int fd, enum onload_fd_feature feature)
{
  switch ( feature ) {
  case ONLOAD_FD_FEAT_MSG_WARM:
    return onload_fd_check_msg_warm( fd );
  default:
    break;
  }
  return -EOPNOTSUPP;
}


int onload_ordered_epoll_wait(int epfd, struct epoll_event *events,
                              struct onload_ordered_epoll_event *oo_events,
                              int maxevents, int timeout)
{
  citp_fdinfo* fdi;
  int rc = -EINVAL;

#if CI_CFG_USERSPACE_EPOLL
  citp_lib_context_t lib_context;
  citp_enter_lib(&lib_context);

  if( (fdi = citp_fdtable_lookup(epfd)) != NULL ) {
    if( fdi->protocol->type == CITP_EPOLL_FD ) {
      rc = citp_epoll_ordered_wait(fdi, events, oo_events, maxevents, timeout,
                                     NULL, &lib_context);
      citp_fdinfo_release_ref(fdi, 0);
      return rc;
    }
    citp_fdinfo_release_ref(fdi, 0);
  }

  citp_exit_lib(&lib_context, FALSE);

#endif
  return rc;
}


static int oo_extensions_version_check(void)
{
  static unsigned int* oev;

  /* Accept version of onload_ext library if:
   * - onload_ext is not present (no onload_ext_version symbol) 
   * - or major versions match and lib's minor is less than or
   *   equal to onload's
   */
  if( oev == NULL )
    if( (oev = dlsym(RTLD_NEXT, "onload_ext_version")) == NULL )
      return 0;
  if( (oev[0] == ONLOAD_EXT_VERSION_MAJOR) &&
      (oev[1] <= ONLOAD_EXT_VERSION_MINOR) )
    /* Onload is compatible with the extensions lib. */
    return 0;

  /* Extensions lib has different major version, or supports new features
   * that this version of Onload doesn't know about.  We don't know for
   * certain that the app is using the new features, be we can't detect
   * that either.
   */
  ci_log("ERROR: Onload extension library has incompatible version");
  ci_log("ERROR: libonload=%d.%d.%d libonload_ext=%d.%d.%d",
         ONLOAD_EXT_VERSION_MAJOR, ONLOAD_EXT_VERSION_MINOR,
         ONLOAD_EXT_VERSION_MICRO, oev[0], oev[1], oev[2]);
  return -1;
}


int oo_extensions_init(void)
{
  int rc; 

  if( (rc = oo_extensions_version_check()) != 0 ) 
    return rc;

  oo_stackname_init();

  return 0;
}


/* Export the version of the extensions interface this library supports.
 * This is used by the static version of the extensions stub library to
 * validate compatibility.
 */
unsigned onload_lib_ext_version[] = {
  ONLOAD_EXT_VERSION_MAJOR,
  ONLOAD_EXT_VERSION_MINOR,
  ONLOAD_EXT_VERSION_MICRO
};
