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
** \author  djr
**  \brief  Implementation of Linux sendpage() for TCP.
**   \date  2006/02/10
**    \cop  (c) Level 5 Networks Ltd.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <onload/debug.h>
#include <onload/tcp_helper_fns.h>


CI_BUILD_ASSERT(CI_SB_AFLAG_O_NONBLOCK == MSG_DONTWAIT);


ci_inline int sendpage_copy(ci_netif* ni, ci_tcp_state* ts, struct page* page,
                            int offset, size_t size, int more)
{
  struct iovec io;
  struct msghdr m;
  int rc;

  CITP_STATS_NETIF(++ni->state->stats.tcp_sendpages);

  io.iov_base = (char*) kmap(page) + offset;
  io.iov_len = size;
  m.msg_iov = &io;
  m.msg_iovlen = 1;
  m.msg_controllen = 0;
  m.msg_namelen = 0;

  rc = ci_tcp_sendmsg(ni, ts, &m,
                      (ts->s.b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK) |
                      (more ? MSG_MORE : 0) 
		      CI_ARG_WIN(0), CI_ADDR_SPC_KERNEL);

  kunmap(page);
  return rc;
}


ssize_t linux_tcp_helper_fop_sendpage(struct file* filp, struct page* page, 
                                      int offset, size_t size,
                                      loff_t* ppos, int more)
{
  ci_private_t* priv = filp->private_data;
  tcp_helper_resource_t* trs = efab_priv_to_thr(priv);
  ci_sock_cmn* s;

  OO_DEBUG_VERB(ci_log("%s: %d:%d offset=%d size=%d more=%d", __FUNCTION__,
                       NI_ID(&trs->netif), OO_SP_FMT(priv->sock_id), offset,
                       (int) size, more));

  ci_assert(page);
  ci_assert_ge(offset, 0);
  ci_assert_gt(size, 0);
  ci_assert_le(offset + size, CI_PAGE_SIZE);

  /* [more] is sometimes true even for the last page.  We get a little
  ** closer to the truth by spotting that we're not reading to the end of
  ** the page.
  */
  if( offset + size < CI_PAGE_SIZE )  more = 0;

  s = SP_TO_SOCK(&trs->netif, priv->sock_id);
  if(CI_LIKELY( s->b.state & CI_TCP_STATE_TCP_CONN ))
    return sendpage_copy(&trs->netif,SOCK_TO_TCP(s),page,offset,size,more);
  else
    /* Closed or listening.  Return epipe.  Do not send SIGPIPE, because
    ** Linux will do it for us. */
    return -s->tx_errno;
}
