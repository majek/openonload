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


#ifndef __ONLOAD_OO_PIPE_H__
#define __ONLOAD_OO_PIPE_H__

#if !CI_CFG_USERSPACE_PIPE
#error "Do not include oo_pipe.h when pipe is not enabled"
#endif

#define oo_pipe_data_len(_p) \
  ((_p)->bytes_added - (_p)->bytes_removed)

/* Amount of space left in the pipe */
#define oo_pipe_space(_p) \
  (OO_PIPE_BUF_SIZE * p->bufs_num - (oo_pipe_data_len(_p)))

/* if we don't have a free pipe buffer to use we
 * call this 'no space'. This is close to linux kernel
 * behaviour except they think that pipe is full if
 * they don't have a free 'page'.
 */
#define oo_pipe_is_writable(_p) \
  ( (_p)->bytes_added - (_p)->bytes_removed <   \
    OO_PIPE_BUF_SIZE * ((_p)->bufs_num - 1) )

ci_inline void oo_pipe_wake_peer(struct oo_pipe* p, ci_netif* ni,
                                 unsigned wake)
{
  if( ! (p->b.wake_request & wake) ) {
    /* we increment sleep_seq. This is done to avoid race
     * condition with other end which may go to sleep moments
     * after we've called wake and will sleep forever. But! with
     * sleep_seq incremented it will notice that wake had just
     * occured and waiter_dont_wait function will wake us!
     */
    /* fixme: do we need this mb here? */
    ci_wmb();
    if( wake & CI_SB_FLAG_WAKE_RX )
      ++p->b.sleep_seq.rw.rx;
    if( wake & CI_SB_FLAG_WAKE_TX )
      ++p->b.sleep_seq.rw.tx;
    ci_mb();
  }

  if((p->b.wake_request & wake) ) {
    ci_netif_lock(ni);
    ci_assert_equal(ni->state->in_poll, 0);
    citp_waitable_wake_not_in_poll(ni, &p->b, wake);
    ci_netif_unlock(ni);
  }
}

#endif /* __ONLOAD_OO_PIPE_H__ */
