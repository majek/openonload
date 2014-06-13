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


#ifndef __ONLOAD_OO_PIPE_H__
#define __ONLOAD_OO_PIPE_H__

#if !CI_CFG_USERSPACE_PIPE
#error "Do not include oo_pipe.h when pipe is not enabled"
#endif

#define oo_pipe_data_len(_p) \
  ((_p)->bytes_added - (_p)->bytes_removed)

/* if we don't have a free pipe buffer to use we
 * call this 'no space'. This is close to linux kernel
 * behaviour except they think that pipe is full if
 * they don't have a free 'page'.
 */
#define oo_pipe_is_writable(_p) \
  ( (_p)->bytes_added - (_p)->bytes_removed <   \
    OO_PIPE_BUF_SIZE * ((_p)->bufs_num - 1) )


#ifdef __KERNEL__
void oo_pipe_wake_peer(ci_netif* ni, struct oo_pipe* p, unsigned wake);
#endif


#endif /* __ONLOAD_OO_PIPE_H__ */
