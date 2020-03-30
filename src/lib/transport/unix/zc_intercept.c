/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  kjm
**  \brief  Intercept of zero-copy API calls
**   \date  2011/06/07
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include "internal.h"

#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/socket.h>

#include <onload/extensions.h>
#include <onload/extensions_zc.h>


int onload_zc_alloc_buffers(int fd, struct onload_zc_iovec* iovecs,
                            int iovecs_len, 
                            enum onload_zc_buffer_type_flags flags)
{
  int rc = 0, i;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  citp_sock_fdi* epi;
  ci_netif* ni;
  ci_ip_pkt_fmt *pkt;
  unsigned max_len;
  ci_tcp_state* ts = NULL;

  Log_CALL(ci_log("%s(%d, %p, %d, %x)", __FUNCTION__, fd, iovecs,
                  iovecs_len, flags));

  citp_enter_lib(&lib_context);

  if( (fdi = citp_fdtable_lookup(fd)) != NULL ) {
    switch( citp_fdinfo_get_type(fdi) ) {
    case CITP_UDP_SOCKET:
    case CITP_TCP_SOCKET:
      epi = fdi_to_sock_fdi(fdi);
      ni = epi->sock.netif;
      ci_netif_lock(ni);
      if( epi->sock.s->b.state & CI_TCP_STATE_TCP_CONN )
	ts = SOCK_TO_TCP(epi->sock.s);

      for( i = 0; i < iovecs_len; ++i ) {
        max_len = CI_CFG_PKT_BUF_SIZE;
        pkt = ci_netif_pkt_tx_tcp_alloc(ni, ts);
        if( pkt == NULL ) {
          while( --i >= 0 )
            ci_netif_pkt_release(ni, (ci_ip_pkt_fmt*)iovecs[i].buf);
          rc = -ENOMEM;
          ci_netif_unlock(ni);
          goto out;
        }
        /* Make sure this is clear as it affects behaviour when freeing */
        pkt->rx_flags &=~ CI_PKT_RX_FLAG_UDP_KEEP;
        iovecs[i].buf = (struct oo_zc_buf *)pkt;
        if( flags & ONLOAD_ZC_BUFFER_HDR_TCP ) {
	  if( ts != NULL ) {
	    oo_tx_pkt_layout_init(pkt);
            iovecs[i].iov_base = ((char *)oo_tx_ip_hdr(pkt)) + 
              ts->outgoing_hdrs_len;
            max_len = tcp_eff_mss(ts);
	  }
          else {
            /* Best guess.  We can fix it up later.  Magic 12 leaves
             * space for time stamp option (common case)
             */
            oo_tx_pkt_layout_init(pkt);
            iovecs[i].iov_base =
              (uint8_t*) oo_tx_ip_data(pkt) + sizeof(ci_tcp_hdr) + 12;
          }
        }
        else if( flags & ONLOAD_ZC_BUFFER_HDR_UDP ) {
          oo_tx_pkt_layout_init(pkt);
          iovecs[i].iov_base =
            (uint8_t*) oo_tx_ip_data(pkt) + sizeof(ci_udp_hdr);
        }
        else 
          iovecs[i].iov_base = PKT_START(pkt);
        iovecs[i].iov_len = CI_CFG_PKT_BUF_SIZE - 
          ((char *)iovecs[i].iov_base - (char *)pkt);
        if( iovecs[i].iov_len > max_len )
          iovecs[i].iov_len = max_len;
      }
      ni->state->n_async_pkts += iovecs_len;
      ci_netif_unlock(ni);
      break;
#if CI_CFG_USERSPACE_EPOLL
    case CITP_EPOLL_FD:
      rc = -ENOTSOCK;
      break;
#endif
#if CI_CFG_USERSPACE_PIPE
    case CITP_PIPE_FD:
      rc = -ENOTSOCK;
      break;
#endif
    case CITP_PASSTHROUGH_FD:
      rc = -ESOCKTNOSUPPORT;
      break;
    default:
      LOG_U(log("%s: unknown fdinfo type %d", __FUNCTION__, 
                citp_fdinfo_get_type(fdi)));
      rc = -EINVAL;
    }
    citp_fdinfo_release_ref(fdi, 0);
  } 
  else {
    /* Not onload socket */
    rc = -ESOCKTNOSUPPORT;
  }

 out:
  citp_exit_lib(&lib_context, TRUE);
  Log_CALL_RESULT(rc);
  return rc;
}



int onload_zc_release_buffers(int fd, onload_zc_handle* bufs, int bufs_len)
{
  int rc = 0, i, rx_pkt, released;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  citp_sock_fdi* epi;
  ci_netif* ni;
  ci_ip_pkt_fmt* pkt;

  Log_CALL(ci_log("%s(%d, %p, %d)", __FUNCTION__, fd, bufs, bufs_len));

  citp_enter_lib(&lib_context);

  if( (fdi = citp_fdtable_lookup(fd)) != NULL ) {
    switch( citp_fdinfo_get_type(fdi) ) {
    case CITP_UDP_SOCKET:
    case CITP_TCP_SOCKET:
      epi = fdi_to_sock_fdi(fdi);
      ni = epi->sock.netif;
      ci_netif_lock(ni);
      for( i = 0; i < bufs_len; ++i ) {
        pkt = (ci_ip_pkt_fmt*)bufs[i];
        if( pkt->stack_id != ni->state->stack_id ) {
          LOG_U(log("%s: attempt to free buffer from stack %d to stack %d",
                    __FUNCTION__, pkt->stack_id, ni->state->stack_id));
          rc = -EINVAL;
          break;
        }
      }
      if( rc == 0 ) {
        for( i = 0; i < bufs_len; ++i ) {
          pkt = (ci_ip_pkt_fmt*)bufs[i];
          /* If we are releasing a packet without the RX_FLAG then the user
           * allocated and then freed the packet (without using it).
           * We detect this to decrement n_asyn_pkts.
           * RX packets (kept via ONLOAD_ZC_KEEP) are counted differently
           * so don't decrement here.  (But may release)
           */
          rx_pkt = pkt->flags & CI_PKT_FLAG_RX;
          released = ci_netif_pkt_release_check_keep(ni, pkt);
          if ( ! rx_pkt ) {
            ci_assert(released == 1);
            (void) released;
            --ni->state->n_async_pkts;
          }
        }
      }
      ci_netif_unlock(ni);
      break;
#if CI_CFG_USERSPACE_EPOLL
    case CITP_EPOLL_FD:
      rc = -ENOTSOCK;
      break;
#endif
#if CI_CFG_USERSPACE_PIPE
    case CITP_PIPE_FD:
      rc = -ENOTSOCK;
      break;
#endif
    default:
      LOG_U(log("%s: unknown fdinfo type %d", __FUNCTION__, 
                citp_fdinfo_get_type(fdi)));
      rc = -EINVAL;
    }

    citp_fdinfo_release_ref(fdi, 0);
  } 
  else {
    /* Not onload socket */
    rc = -ESOCKTNOSUPPORT;
  }

  citp_exit_lib(&lib_context, TRUE);
  Log_CALL_RESULT(rc);

  return rc;
}



int onload_zc_recv(int fd, struct onload_zc_recv_args* args)
{
  int rc;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;

  Log_CALL(ci_log("%s(%d, %p(flags=%x))", __FUNCTION__, fd, args, args->flags));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    rc = citp_fdinfo_get_ops(fdi)->zc_recv(fdi, args);
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, rc >= 0);
  } else {
    citp_exit_lib_if(&lib_context, TRUE);
    rc = -ESOCKTNOSUPPORT;
  }

  Log_CALL_RESULT(rc);
  return rc;
}



int onload_zc_send(struct onload_zc_mmsg* msgs, int mlen, int flags)
{
  int done = 0, last_fd = -1, i;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi = NULL;

  Log_CALL(ci_log("%s(%p, %d, %x)", __FUNCTION__, msgs, mlen, flags));

  citp_enter_lib(&lib_context);

  for( i = 0; i < mlen; ++i ) {
    if( msgs[i].fd != last_fd ) {
      if( fdi != NULL )
        citp_fdinfo_release_ref(fdi, 0);
      fdi = citp_fdtable_lookup(msgs[i].fd);
      if( fdi == NULL ) {
        msgs[i].rc = -ESOCKTNOSUPPORT;
        ++done;
        goto out;
      }
      last_fd = msgs[i].fd;
    }

    CI_TRY_EQ( citp_fdinfo_get_ops(fdi)->zc_send(fdi, &msgs[i], flags), 1);
    /* If we got an error, return the number of msgs that have had
     * rc set and exit.  fd_op should have updated msgs.rc appropriately
     */
    ++done;
    if( msgs[i].rc < 0 )
      goto out;
  }

 out:

  if( fdi != NULL )
    citp_fdinfo_release_ref(fdi, 0);

  citp_exit_lib(&lib_context, TRUE);

  ci_assert_gt(done, 0);
  ci_assert_le(done, mlen);

  Log_CALL_RESULT(done);
  return done;
}


int onload_set_recv_filter(int fd, onload_zc_recv_filter_callback filter,
                           void* cb_arg, int flags)
{
  int rc;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;

  Log_CALL(ci_log("%s(%d, %p, %p, %x)", __FUNCTION__, fd, filter,
                  cb_arg, flags));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    rc = citp_fdinfo_get_ops(fdi)->zc_recv_filter(fdi, filter, cb_arg, flags);
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, rc >= 0);
  } else {
    citp_exit_lib_if(&lib_context, TRUE);
    rc = -ESOCKTNOSUPPORT;
  }

  Log_CALL_RESULT(rc);
  return rc;
}


int onload_recvmsg_kernel(int fd, struct msghdr *msg, int flags)
{
  int rc;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;

  Log_CALL(ci_log("%s(%d, %p, %x)", __FUNCTION__, fd, msg, flags));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    rc = citp_fdinfo_get_ops(fdi)->recvmsg_kernel(fdi, msg, flags);
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, rc >= 0);
  } else {
    citp_exit_lib_if(&lib_context, TRUE);
    rc = -ESOCKTNOSUPPORT;
  }

  Log_CALL_RESULT(rc);
  return rc; 
}
