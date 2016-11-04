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
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: ctk
**     Started: 2004/03/15
** Description: TCP helper interface.
** </L5_PRIVATE>
\**************************************************************************/

/* 
 * stg 2006/11/06 : Moved to transport/ip from transport/ciul 
 */

#include "ip_internal.h"
#include <onload/common.h>

# include <netinet/in.h>
# include <onload/unix_intf.h>
#include <onload/dup2_lock.h>

#include <ci/internal/ip.h>
# include <ci/internal/trampoline.h>
# include <asm/unistd.h>

#define VERB(x)


int ci_tcp_helper_more_bufs(ci_netif* ni)
{
  return oo_resource_op(ci_netif_get_driver_handle(ni),
                        OO_IOC_TCP_MORE_BUFS, NULL);
}

int ci_tcp_helper_more_socks(ci_netif* ni)
{
  return oo_resource_op(ci_netif_get_driver_handle(ni),
                        OO_IOC_TCP_MORE_SOCKS, NULL);
}

#if CI_CFG_FD_CACHING
int ci_tcp_helper_clear_epcache(ci_netif* ni)
{
  return oo_resource_op(ci_netif_get_driver_handle(ni),
                        OO_IOC_TCP_CLEAR_EPCACHE, NULL);
}
#endif


/*--------------------------------------------------------------------
 *!
 * Set the corresponding filters for an endpoint. This includes
 *    - hardware IP filters
 *    - filters in the software connection hash table
 *    - filters for NET to CHAR driver comms to support fragments
 *
 * \param fd              File descriptor of tcp_helper
 * \param ep              TCP control block id
 * \param phys_port       L5 physcial port index to support SO_BINDTODEVICE
 *                        (ignored unless raddr/rport = 0/0)
 * \param from_tcp_id     block id of listening socket to "borrow" filter from
 *                        (-1 if not required)
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/
int ci_tcp_helper_ep_set_filters(ci_fd_t           fd,
                                 oo_sp             ep,
                                 ci_ifid_t         bindto_ifindex,
                                 oo_sp             from_tcp_id)
{
  oo_tcp_filter_set_t op;
  int rc;

  op.tcp_id       = ep;
  op.bindto_ifindex = bindto_ifindex;
  op.from_tcp_id  = from_tcp_id;

  VERB(ci_log("%s: id=%d", __FUNCTION__, ep));
  rc = oo_resource_op(fd, OO_IOC_EP_FILTER_SET, &op);

  if( rc < 0 )
    LOG_SV(ci_log("%s: failed for %d (rc=%d)", __FUNCTION__,
                  OO_SP_FMT(ep), rc));
  return rc;
}


/*--------------------------------------------------------------------
 *!
 * TODO
 *
 *--------------------------------------------------------------------*/
int ci_tcp_helper_ep_reuseport_bind(ci_fd_t           fd,
                                    const char*       cluster_name,
                                    ci_int32          cluster_size,
                                    ci_uint32         cluster_restart_opt,
                                    ci_uint32         addr_be32,
                                    ci_uint16         port_be16)
{
  oo_tcp_reuseport_bind_t op;
  int rc;

  strncpy(op.cluster_name, cluster_name, CI_CFG_CLUSTER_NAME_LEN);
  op.cluster_name[CI_CFG_CLUSTER_NAME_LEN] = '\0';
  op.cluster_size = cluster_size;
  op.cluster_restart_opt = cluster_restart_opt;
  op.addr_be32 = addr_be32;
  op.port_be16 = port_be16;
  VERB(ci_log("%s: id=%d", __FUNCTION__, fd));
  rc = oo_resource_op(fd, OO_IOC_EP_REUSEPORT_BIND, &op);

  if( rc < 0 )
    LOG_SV(ci_log("%s: failed for %d (rc=%d)", __FUNCTION__, fd, rc));
  return rc;
}


/*--------------------------------------------------------------------
 *!
 * TODO
 *
 *--------------------------------------------------------------------*/
int ci_tcp_helper_cluster_dump(void* opaque, void* buf, int buf_len)
{
  cluster_dump_args* args = opaque;
  oo_cluster_dump_t op;
  CI_USER_PTR_SET(op.buf, buf);
  op.buf_len = buf_len;
  return oo_resource_op(args->fd, OO_IOC_CLUSTER_DUMP, &op);
}


/*--------------------------------------------------------------------
 *!
 * Clear all filters for an endpoint
 *
 * \param fd              File descriptor of tcp_helper
 * \param ep              TCP control block id
 * \param need_update     Whether the filter info needs update before clear
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/
int ci_tcp_helper_ep_clear_filters(ci_fd_t fd, oo_sp ep, int need_update)
{
  oo_tcp_filter_clear_t op;
  int rc;

  op.tcp_id       = ep;
  op.need_update  = !!need_update;

  VERB(ci_log("%s: id=%d", __FUNCTION__, ep));
  rc = oo_resource_op(fd, OO_IOC_EP_FILTER_CLEAR, &op);

  if( rc < 0 )
    LOG_SV(ci_log("%s: failed for %d (rc=%d)", __FUNCTION__,
                  OO_SP_FMT(ep), rc));
  return rc;
}


/*--------------------------------------------------------------------
 *!
 * Debug filter hook on an endpoint
 *
 * \param fd              File descriptor of tcp_helper
 * \param ep              TCP control block id
 * \param debug_op        Debug operation to perform
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/
int ci_tcp_helper_ep_filter_dump(void* opaque, void* buf, int buf_len)
{
  filter_dump_args* args = opaque;
  oo_tcp_filter_dump_t op;
  op.sock_id = args->sock_id;
  CI_USER_PTR_SET(op.buf, buf);
  op.buf_len = buf_len;
  return oo_resource_op(args->fd, OO_IOC_EP_FILTER_DUMP, &op);
}


/*--------------------------------------------------------------------
 *!
 * Adds or deletes multicast address to/from socket list.
 * 
 * \param fd              File descriptor of tcp_helper
 * \param ep              TCP control block id
 * \param phys_port       L5 physcial port index to support SO_BINDTODEVICE
 *                        (ignored unless raddr/rport = 0/0)
 * \param mcast_addr      Multicast address to add to the socket list
 * \param add             Add or delete?
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/
int ci_tcp_helper_ep_mcast_add_del(ci_fd_t           fd,
                                   oo_sp             ep,
                                   ci_uint32         mcast_addr,
                                   ci_ifid_t         ifindex,
                                   int               add)
{
  oo_tcp_filter_mcast_t op;
  int rc;

  op.tcp_id     = ep;
  op.ifindex    = ifindex;
  op.addr       = mcast_addr;

  VERB(ci_log("%s: id=%d %s", __FUNCTION__, OO_SP_FMT(ep),
              add ? "add" : "del"));
  rc = oo_resource_op(fd,
                      add ? OO_IOC_EP_FILTER_MCAST_ADD :
                            OO_IOC_EP_FILTER_MCAST_DEL,
                      &op);

  if( rc < 0 )
    LOG_SV(ci_log("%s: %s failed for %d (rc=%d)", 
                  __FUNCTION__, add ? "add" : "del", OO_SP_FMT(ep), rc));
  return rc;
}


int ci_tcp_helper_stack_attach(ci_fd_t from_fd,
                               efrm_nic_set_t *out_ptr_nic_set,
                               ci_uint32 *out_map_size)
{
  int rc;
  oo_stack_attach_t op;

  ci_assert(out_ptr_nic_set);
  ci_assert(out_map_size);
  rc = oo_resource_op(from_fd, OO_IOC_STACK_ATTACH, &op);
  if( rc < 0 )
    return rc;
  *out_ptr_nic_set = op.out_nic_set;
  *out_map_size = op.out_map_size;
  return op.fd;
}


int ci_tcp_helper_sock_attach(ci_fd_t stack_fd, oo_sp ep_id,
                              int domain, int type)
{
  int rc;
  oo_sock_attach_t op;

  op.ep_id = ep_id;
  op.type = type;
  op.domain = domain;
  oo_rwlock_lock_read(&citp_dup2_lock);
  rc = oo_resource_op(stack_fd, OO_IOC_SOCK_ATTACH, &op);
  oo_rwlock_unlock_read (&citp_dup2_lock);
  if( rc < 0 )
    return rc;
  return op.fd;
}


int ci_tcp_helper_tcp_accept_sock_attach(ci_fd_t stack_fd, oo_sp ep_id,
                                         int type)
{
  int rc;
  oo_tcp_accept_sock_attach_t op;

  op.ep_id = ep_id;
  op.type = type;
  oo_rwlock_lock_read(&citp_dup2_lock);
  rc = oo_resource_op(stack_fd, OO_IOC_TCP_ACCEPT_SOCK_ATTACH, &op);
  oo_rwlock_unlock_read (&citp_dup2_lock);
  if( rc < 0 )
    return rc;
  return op.fd;
}

int ci_tcp_helper_pipe_attach(ci_fd_t stack_fd, oo_sp ep_id,
                              int flags, int fds[2])
{
  int rc;
  oo_pipe_attach_t op;

  op.ep_id = ep_id;
  op.flags = flags;
  rc = oo_resource_op(stack_fd, OO_IOC_PIPE_ATTACH, &op);
  if( rc < 0 )
    return rc;
  fds[0] = op.rfd;
  fds[1] = op.wfd;
  return rc;
}

int ci_tcp_helper_close_no_trampoline(int fd) {
  int res;
  int call_num = __NR_close;

#if defined(__i386__)
  /* Since ebx is the PIC register, gcc fails register allocation if
   * we use the "b" constraint when compiling with -fpic.  We
   * therefore pass the fd in ecx. */
  __asm__ __volatile__("xchgl %%ebx, %%ecx\n\t"
                       "int $0x80\n"
                       "ci_tcp_helper_close_no_trampoline_retaddr:\n\t"
                       ".global ci_tcp_helper_close_no_trampoline_retaddr\n\t"
                       ".hidden ci_tcp_helper_close_no_trampoline_retaddr\n\t"
                       "xchgl %%ebx, %%ecx"
                       :"=a"(res)
                       :"0"(call_num),"c"(fd));

  if (CI_UNLIKELY(res < 0)) {
    errno = -res;
    return -1;
  }

#elif defined(__x86_64__)
  __asm__ __volatile__("syscall\n"
                       "ci_tcp_helper_close_no_trampoline_retaddr:"
                       ".global ci_tcp_helper_close_no_trampoline_retaddr\n\t"
                       ".hidden ci_tcp_helper_close_no_trampoline_retaddr\n\t"
                       :"=a"(res)
                       :"a"(call_num),"D"(fd));

  if (CI_UNLIKELY(res < 0)) {
    errno = -res;
    return -1;
  }

#elif defined(__PPC__)
  {
    register unsigned long r0 asm("r0");
    register unsigned long r3 asm("r3");

    r0 = call_num;
    r3 = fd;

    asm volatile("sc\n"
                 "ci_tcp_helper_close_no_trampoline_retaddr:"
                 ".global ci_tcp_helper_close_no_trampoline_retaddr\n\t"
                 ".hidden ci_tcp_helper_close_no_trampoline_retaddr\n\t"
                 "mfcr %0"
                 :"=r"(r0),"=r"(r3)
                 :"r"(r0),"r"(r3)
                 :"cr0", "ctr", "r9", "r10", "r11", "r12");
    res = r3;

    if(r0 & (1<<28)) {
      errno = res;
      return -1;
    }
  }
#elif defined(__ia64__)
  /* SPH: This is wrong */
  {
    __attribute__((unused)) int i = call_num;
  }
  res = 0;
#else
#error "Unsupported close system call"
#endif

  return res;
}



#include <onload/dup2_lock.h>
oo_rwlock citp_dup2_lock;


ci_fd_t ci_tcp_helper_get_sock_fd(ci_fd_t fd)
{
  oo_os_sock_fd_get_t op;
  int rc;

  oo_rwlock_lock_read(&citp_dup2_lock);
  op.sock_id = -1;
  rc = oo_resource_op(fd, OO_IOC_OS_SOCK_FD_GET, &op);
  if( rc == 0 )
    return op.fd_out;
  oo_rwlock_unlock_read (&citp_dup2_lock);
  return (ci_fd_t) rc; /*! \TODO FIXME: remove cast */
}


int ci_tcp_helper_rel_sock_fd(ci_fd_t fd)
{
  int rc = 0;
  rc = ci_sys_close (fd);
  oo_rwlock_unlock_read (&citp_dup2_lock);
  return rc;
}



int ci_tcp_helper_bind_os_sock(ci_fd_t fd, const struct sockaddr* address,
                               size_t addrlen, ci_uint16* out_port)
{
  int rc;
  oo_tcp_bind_os_sock_t op;

  CI_USER_PTR_SET(op.address, address);
  op.addrlen = addrlen;

  rc = oo_resource_op(fd, OO_IOC_TCP_BIND_OS_SOCK, &op);

  if (rc < 0) {
    errno = -rc;
    return -1;
  }
  ci_assert(rc == 0);

  /* Bug 646: only write back source port if bind succeeds! */
  if (out_port)
    *out_port = op.addrlen;
  return rc;
}


int ci_tcp_helper_listen_os_sock(ci_fd_t fd, int backlog)
{
  int rc;

  rc = oo_resource_op(fd, OO_IOC_TCP_LISTEN_OS_SOCK, &backlog);
  if (rc < 0) {
    errno = -rc;
    return -1;
  }
  ci_assert (rc == 0);
  return rc;
}


int ci_tcp_helper_endpoint_shutdown(ci_fd_t fd, int how, ci_uint32 old_state)
{
  oo_tcp_endpoint_shutdown_t op;
  int rc;

  op.how = how;
  op.old_state = old_state;
  rc = oo_resource_op(fd, OO_IOC_TCP_ENDPOINT_SHUTDOWN, &op);
  if (rc < 0) {
    errno = -rc;
    return -1;
  }
  ci_assert (rc == 0);
  return rc;
}


int ci_tcp_helper_connect_os_sock(ci_fd_t fd, const struct sockaddr*address,
                                  size_t addrlen)
{
  int rc;
  oo_tcp_sockaddr_with_len_t op;

  CI_USER_PTR_SET(op.address, address);
  op.addrlen = addrlen;
  rc = oo_resource_op(fd, OO_IOC_TCP_CONNECT_OS_SOCK, &op);
  if (rc < 0) {
    errno = -rc;
    return -1;
  }
  ci_assert (rc == 0);
  return rc;
}


int ci_tcp_helper_set_tcp_close_os_sock(ci_netif *ni, oo_sp sock_id)
{
  return oo_resource_op(ci_netif_get_driver_handle(ni),
                        OO_IOC_TCP_CLOSE_OS_SOCK, &sock_id);
}


/* This ioctl creates a backing OS socket for a TCP endpoint. If a socket
 * option is passed with level >= 0 then that option is synced to the OS
 * socket after creation.
 */
int ci_tcp_helper_os_sock_create_and_set(ci_netif *ni, ci_fd_t fd,
                                         ci_sock_cmn *s, int level,
                                         int optname, const void* optval,
                                         int optlen)
{
  int rc;
  oo_tcp_create_set_t op;

  /* State sync must be done while the state is not being changed under out
   * feet.
   */
  ci_assert(ci_netif_is_locked(ni));
  /* When we install filters we take a reference to the OS socket.  That means
   * we need to have created the OS socket (if needed) before installing a
   * filter.
   */
  ci_assert_nflags(s->s_flags, CI_SOCK_FLAG_FILTER);
  /* This must be called before we turn into a listening socket.  If F_SETFL
   * is used after a socket enters the listening state onload filters the
   * request to ensure that the OS socket remains non-blocking.
   */
  ci_assert_nequal(s->b.state, CI_TCP_LISTEN);

  op.level = level;
  op.optname = optname;
  CI_USER_PTR_SET(op.optval, optval);
  op.optlen = optlen;
  rc = oo_resource_op(fd, OO_IOC_OS_SOCK_CREATE_AND_SET, &op);
  return rc;
}


int ci_tcp_helper_alloc_active_wild(ci_netif *ni)
{
  return oo_resource_op(ci_netif_get_driver_handle(ni),
                        OO_IOC_ALLOC_ACTIVE_WILD, NULL);
}

