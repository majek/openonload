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
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2006/06/06
** Description: Functions and inliners for the tcp_helper_resource.
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab  */

#ifndef __CI_DRIVER_EFAB_TCP_HELPER_FNS_H__
#define __CI_DRIVER_EFAB_TCP_HELPER_FNS_H__

#include <ci/efrm/vi_resource.h>
#include <onload/common.h>
#include <onload/fd_private.h>
#include <onload/tcp_helper.h>
#include <onload/tcp_driver.h> /* For efab_tcp_driver */

#if !defined(__KERNEL__)
#error "Kernel-only header!"
#endif

/**********************************************************************
 */

#define TCP_HELPER_WAITQ(rs, i) (&((rs)->netif.ep_tbl[OO_SP_TO_INT(i)]->waitq))


extern int tcp_helper_alloc_kernel(ci_resource_onload_alloc_t* alloc,
                                   const ci_netif_config_opts* opts,
                                   const int* ifindices, int ifindices_len,
                                   tcp_helper_resource_t** rs_out);

extern int tcp_helper_alloc_ul(ci_resource_onload_alloc_t* alloc,
                               const int* ifindices, int ifindices_len,
                               tcp_helper_resource_t** rs_out);

extern int efab_tcp_helper_rm_mmap(tcp_helper_resource_t*,
                                   unsigned long* bytes,
                                   void* opaque, int* map_num,
                                   unsigned long* offset, int index);

extern unsigned tcp_helper_rm_nopage(tcp_helper_resource_t* trs,
                                     void* opaque,
                                     unsigned long offset,
                                     unsigned long map_size);

extern void tcp_helper_rm_dump(int fd_type, oo_sp sock_id,
                               tcp_helper_resource_t* trs,
                               const char *line_prefix);
#define THR_PRIV_DUMP(priv, line_prefix) \
    tcp_helper_rm_dump(priv->fd_type, priv->sock_id, priv->thr, line_prefix)

extern unsigned efab_tcp_helper_netif_lock_callback(eplock_helper_t*,
                                                    ci_uint32 lock_val);

extern int efab_ioctl_get_ep(ci_private_t*, oo_sp,
                             tcp_helper_endpoint_t** ep_out);


extern void efab_tcp_helper_os_pollwait_register(tcp_helper_endpoint_t* ep);
extern void efab_tcp_helper_os_pollwait_unregister(tcp_helper_endpoint_t* ep);

/* get a resource installed install_resource_into_priv, or return a
 negative error code (does not remove the resource from the priv) */
ci_inline int
efab_get_tcp_helper_of_priv(ci_private_t* priv, tcp_helper_resource_t**trs_out,
			    const char *context)
{
  ci_assert(NULL != priv);
  if (priv->thr == NULL) {
    LOG_U(ci_log("WARNING: %s no tcp helper in %p; noop", context, priv));
    return -ENOENT;
  } 

  if (!trs_out)
    return -ENXIO;
  *trs_out = priv->thr;

  return 0;
}

/* For a priv that is known to be specialised as a userlevel socket (or
** netif fd) return the tcp_helper_resource_t.
*/
ci_inline tcp_helper_resource_t* efab_priv_to_thr(ci_private_t* priv) {
  ci_assert(priv->thr);
  return priv->thr;
}


#define EFAB_THR_TABLE_LOOKUP_NO_CHECK_USER  0
#define EFAB_THR_TABLE_LOOKUP_CHECK_USER     1
#define EFAB_THR_TABLE_LOOKUP_NO_UL          2

extern int efab_thr_can_access_stack(tcp_helper_resource_t* thr,
                                     int check_user);

/*! Lookup a stack and grab a reference if found.  If [name] is not NULL,
 * search by name, else by [id].  Only stacks that still have a userland
 * reference are found.
 */
extern int efab_thr_table_lookup(const char* name, unsigned id,
                                 int check_user,
                                 tcp_helper_resource_t** stack_out);


/*! Dump a stack's netif state to syslog */
extern int tcp_helper_dump_stack(unsigned id, unsigned orphan_only);

/*! Try to kill an orphan/zombie stack */
extern int tcp_helper_kill_stack(unsigned id);

ci_inline void
efab_thr_ref(tcp_helper_resource_t *thr)
{
  TCP_HELPER_RESOURCE_ASSERT_VALID(thr, -1);
#ifndef NDEBUG
  /* Only allowed to increment from zero under rm lock.  See
  ** efab_thr_release(). */
  if( oo_atomic_read(&thr->ref_count) == 0 )
    ci_irqlock_check_locked(&efab_tcp_driver.thr_table.lock);
  /* We MUST NOT increment refcount after userland disappear */
  ci_assert(~thr->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND);
#endif
  oo_atomic_inc(&thr->ref_count);
}


extern void efab_thr_release(tcp_helper_resource_t *thr);




extern int efab_tcp_helper_poll_os_sock(tcp_helper_resource_t* trs,
                                        oo_sp, ci_uint16* p_mask_out);

extern int efab_tcp_helper_xfer_cached (ci_private_t *priv, void *arg);

extern int efab_tcp_helper_sock_sleep(tcp_helper_resource_t*,
				      oo_tcp_sock_sleep_t* op
				      CI_BLOCKING_CTX_ARG(ci_blocking_ctx_t));

extern int efab_tcp_helper_pkt_wait(tcp_helper_resource_t* trs,
                                    int* lock_flags
				    CI_BLOCKING_CTX_ARG(ci_blocking_ctx_t));

extern int efab_tcp_helper_sock_lock_slow(tcp_helper_resource_t*, oo_sp
				  CI_BLOCKING_CTX_ARG(ci_blocking_ctx_t));
extern void efab_tcp_helper_sock_unlock_slow(tcp_helper_resource_t*, oo_sp);

extern int efab_tcp_helper_can_cache_fd(ci_private_t *priv_ni, void *arg);


extern int efab_tcp_helper_get_sock_fd(ci_private_t*, void*);

extern int efab_tcp_helper_os_sock_sendmsg(ci_private_t*, void*);
extern int efab_tcp_helper_os_sock_sendmsg_raw(ci_private_t*, void*);

extern int efab_tcp_helper_os_sock_recvmsg(ci_private_t *priv, void *arg);

extern int efab_tcp_helper_os_sock_accept(ci_private_t *priv, void *arg);

extern int efab_tcp_helper_bind_os_sock (tcp_helper_resource_t* trs,
                                         oo_sp sock_id,
                                         struct sockaddr *addr,
                                         int addrlen, ci_uint16 *out_port);

extern int efab_tcp_helper_listen_os_sock (tcp_helper_resource_t* trs,
					   oo_sp sock_id, int backlog);

extern int efab_tcp_helper_shutdown_os_sock (tcp_helper_endpoint_t* ep,
                                             ci_int32 how);

extern int efab_tcp_helper_connect_os_sock (ci_private_t *priv, void *arg);


extern int efab_tcp_helper_more_bufs(tcp_helper_resource_t* trs);

extern int efab_tcp_helper_more_socks(tcp_helper_resource_t* trs);

#if CI_CFG_USERSPACE_PIPE
extern int efab_tcp_helper_pipebufs_to_socks(tcp_helper_resource_t* trs);
extern int efab_tcp_helper_more_pipe_bufs(ci_netif* ni,
                                          ci_int32 bufs_num,
                                          ci_int32* bufs_start);
#endif

extern void efab_tcp_helper_close_endpoint(tcp_helper_resource_t* trs,
                                           oo_sp ep_id);


extern void tcp_helper_pace(tcp_helper_resource_t*, int pace_val);


/*--------------------------------------------------------------------
 *!
 * Called to release a kernel reference to a stack.  This is called
 * by ci_drop_orphan() when userlevel is no longer around.
 * 
 * \param trs             TCP helper resource
 * \param can_destroy_now true if in a context than can call destructor
 *
 *--------------------------------------------------------------------*/

extern void
efab_tcp_helper_k_ref_count_dec(tcp_helper_resource_t* trs,
                                int can_destroy_now);

/*--------------------------------------------------------------------
 *!
 * Called to increment a kernel reference to a stack.
 * Returns error if the stack is dead.
 * 
 * \param trs             TCP helper resource
 * \todo add parameter to forbid TCP_HELPER_K_RC_NO_USERLAND flag
 *
 *--------------------------------------------------------------------*/
ci_inline int
efab_tcp_helper_k_ref_count_inc(tcp_helper_resource_t* trs)
{
  int tmp;
  do {
    tmp = trs->k_ref_count;
    if( tmp & TCP_HELPER_K_RC_DEAD )
      return -EBUSY;
  } while( ci_cas32_fail(&trs->k_ref_count, tmp, tmp + 1) );
  return 0;
}

/*--------------------------------------------------------------------
 *!
 * Called by kernel code to get the shared user/kernel mode netif lock
 * This obtains the kernel netif "lock" first so we can deduce who owns 
 * the eplock
 *
 * \param trs             TCP helper resource
 * \param addr_spc        Address space id we wnat to run the stack in
 *
 * \return                non-zero if callee succeeded in obtaining 
 *                        the netif lock
 *
 *--------------------------------------------------------------------*/

extern int
efab_tcp_helper_netif_try_lock(tcp_helper_resource_t*, ci_addr_spc_t);


/*--------------------------------------------------------------------
 *!
 * Called by kernel code to unlock the netif lock. Only to be called
 * after a successful call to efab_tcp_helper_netif_try_lock
 *
 * \param trs             TCP helper resource
 *
 *--------------------------------------------------------------------*/

extern void
efab_tcp_helper_netif_unlock(tcp_helper_resource_t*);


/*--------------------------------------------------------------------
 *!
 * Sets the thread context in the TCP helper resource     
 *    - this is the thread used for APC scheduling 
 *
 * \param trs             tcp helper resource manager
 * \param thread          new context thread
 *
 *--------------------------------------------------------------------*/





/**********************************************************************
***************** Iterators to find netifs ***************************
**********************************************************************/
extern int iterate_netifs_unlocked(ci_netif **p_ni);

ci_inline void
iterate_netifs_unlocked_dropref(ci_netif * netif)
{
  ci_assert(netif);
  efab_tcp_helper_k_ref_count_dec(netif2tcp_helper_resource(netif), 1); 
}


ci_inline void
tcp_helper_request_wakeup_nic(tcp_helper_resource_t* trs, int intf_i) {
  /* This assertion is good, but fails on linux so currently disabled */
  /* ci_assert(ci_bit_test(&trs->netif.state->evq_primed, nic_i)); */
  efrm_eventq_request_wakeup(trs->nic[intf_i].vi_rs,
                             ef_eventq_current(&trs->netif.nic_hw[intf_i].vi));
}


ci_inline void tcp_helper_request_wakeup(tcp_helper_resource_t* trs) {
  int intf_i;
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i)
    if( ! ci_bit_test(&trs->netif.state->evq_primed, intf_i) &&
        ! ci_bit_test_and_set(&trs->netif.state->evq_primed, intf_i) )
      tcp_helper_request_wakeup_nic(trs, intf_i);
}


extern void generic_tcp_helper_close(ci_private_t* priv);

extern int efab_tcp_helper_sock_callback_arm(tcp_helper_resource_t*,
                                             oo_sp, void* arg);
extern int efab_tcp_helper_sock_callback_disarm(tcp_helper_resource_t*, oo_sp);

extern int efab_tcp_helper_sock_callback_set(tcp_helper_resource_t*,
                                             void (*fn)(void* arg, int why));



extern
int efab_tcp_helper_set_tcp_close_os_sock(tcp_helper_resource_t *thr,
                                          oo_sp sock_id);




extern int linux_tcp_helper_fop_fasync(int fd, struct file *filp, int mode);

extern int efab_tcp_helper_set_addr_spc(ci_private_t *priv, void *arg);

extern unsigned efab_linux_tcp_helper_fop_poll_tcp(struct file*,
						   tcp_helper_resource_t*,
						   oo_sp, poll_table*);

/* UDP fd poll function, timout should be NULL in case sleep is unlimited */
extern int efab_tcp_helper_poll_udp(struct file *filp, int *mask, s64 *timeout);


extern int efab_attach_os_socket(tcp_helper_endpoint_t*, int os_sock_fd);


extern int oo_create_fd(tcp_helper_endpoint_t* ep, int flags, int fd_type);
extern int oo_create_stack_fd(tcp_helper_resource_t *thr);
extern int onloadfs_get_dev_t(ci_private_t* priv, void* arg);
extern void oo_move_file(ci_private_t* priv, tcp_helper_resource_t *new_thr,
                         oo_sp new_sockid);

ci_inline void
efab_get_os_settings(ci_netif_config_opts *opts)
{
  /* We do not overwrite values from userland, so exit if opts are already
   * inited. */
  if (opts->inited)
    return;

  opts->tcp_sndbuf_min = sysctl_tcp_wmem[0];
  opts->tcp_sndbuf_def = sysctl_tcp_wmem[1];
  opts->tcp_sndbuf_max = sysctl_tcp_wmem[2];
  opts->tcp_rcvbuf_min = CI_MAX(sysctl_tcp_rmem[0], CI_CFG_TCP_RCVBUF_MIN);
  opts->tcp_rcvbuf_def = sysctl_tcp_rmem[1];
  opts->tcp_rcvbuf_max = sysctl_tcp_rmem[2];
#ifdef LINUX_HAS_SYSCTL_MEM_MAX
  opts->udp_sndbuf_max = sysctl_wmem_max;
  opts->udp_rcvbuf_max = sysctl_rmem_max;
#endif

  if( opts->tcp_sndbuf_user != 0 ) {
    opts->tcp_sndbuf_min = opts->tcp_sndbuf_max =
      opts->tcp_sndbuf_def = opts->tcp_sndbuf_user;
  }
  if( opts->tcp_rcvbuf_user != 0 ) {
    opts->tcp_rcvbuf_min = opts->tcp_rcvbuf_max =
      opts->tcp_rcvbuf_def = opts->tcp_rcvbuf_user;
  }
  if( opts->udp_sndbuf_user != 0 ) {
    opts->udp_sndbuf_min = opts->udp_sndbuf_max =
      opts->udp_sndbuf_def = opts->udp_sndbuf_user;
  }
  if( opts->udp_rcvbuf_user != 0 ) {
    opts->udp_rcvbuf_min = opts->udp_rcvbuf_max =
      opts->udp_rcvbuf_def = opts->udp_rcvbuf_user;
  }

  opts->inited = CI_TRUE;
}


/*****************************************************************
 * Table with all ioctl handlers
 *****************************************************************/

#ifdef NDEBUG
# define OO_OPS_TABLE_HAS_NAME  0
#else
# define OO_OPS_TABLE_HAS_NAME  1
#endif

/*! Ioctl handler for a giver ioctl operation
 * \param priv      Private file structure
 * \param arg       Ioctl argument, copied in kernel memspace if necessary
 *
 * \return 0 or -errno
 *
 * \note 
 * All these handlers MUST return 0 on success, -errno on failure.
 * 1. We do not copy any out parameters on non-zero rc.
 * 2. Some OSes (for example, Solaris) has problems with handling ioctl
 * return code.
 *
 * \note Ioctl handler should not copy arguments from/to user space.
 * OS-specific part of the driver should pass them arguments which are
 * already in the kernel space.
 */
typedef int (*oo_ioctl_handler_t)(ci_private_t *priv, void *arg);

typedef struct {
  int ioc_cmd;
  oo_ioctl_handler_t handler;
#if OO_OPS_TABLE_HAS_NAME
  const char* name;
#endif
} oo_operations_table_t;

extern oo_operations_table_t oo_operations[];

#endif /* __CI_DRIVER_EFAB_TCP_HELPER_FNS_H__ */
/*! \cidoxg_end */
