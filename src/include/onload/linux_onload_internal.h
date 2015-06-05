/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Internal API of linux onload driver.
**   \date  2005/04/25
**    \cop  (c) Solaraflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*
** Do not include this into any files except ones that form part of the
** linux onload driver.
*/

#ifndef __LINUX_ONLOAD_INTERNAL__
#define __LINUX_ONLOAD_INTERNAL__

#include <ci/efhw/efhw_types.h>
#include <ci/tools/sysdep.h>
#include <ci/internal/transport_config_opt.h>
#include <onload/primitive_types.h>
#include <onload/debug.h>


extern int phys_mode_gid;

extern struct rw_semaphore handover_rwlock;

/*--------------------------------------------------------------------
 *
 * Linux file operations.
 *
 *--------------------------------------------------------------------*/

extern struct file_operations oo_fops;

extern int  oo_fop_ioctl(struct inode*, struct file*, uint, ulong);
extern long oo_fop_unlocked_ioctl(struct file*, uint, ulong); 
#define oo_fop_compat_ioctl oo_fop_unlocked_ioctl
extern int  oo_fop_mmap(struct file* file, struct vm_area_struct*);
extern int  oo_fop_open(struct inode *inode, struct file*);
extern int  oo_fop_release(struct inode *inode, struct file*);

/* File-ops are external because they can be useful for discovering whether a
 * file structure is one of our's
 */
extern struct file_operations linux_tcp_helper_fops_udp;
extern struct file_operations linux_tcp_helper_fops_tcp;
#if CI_CFG_USERSPACE_PIPE
extern struct file_operations linux_tcp_helper_fops_pipe_reader;
extern struct file_operations linux_tcp_helper_fops_pipe_writer;
#endif
#if CI_CFG_USERSPACE_EPOLL
extern struct file_operations oo_epoll_fops;
#endif
extern struct file_operations linux_tcp_helper_fops_passthrough;
extern struct file_operations linux_tcp_helper_fops_alien;

/*--------------------------------------------------------------------
 *
 * Misc.
 *
 *--------------------------------------------------------------------*/

extern ssize_t
linux_tcp_helper_fop_sendpage(struct file*, struct page*, int offset,
                              size_t size, loff_t* ppos, int more);
extern ssize_t
linux_tcp_helper_fop_sendpage_udp(struct file*, struct page*, int offset,
                                  size_t size, loff_t* ppos, int more);

extern int efab_fds_dump(unsigned pid);

/* Decide whether a file descriptor is ours or not */
/* Check if file is our endpoint */
#define FILE_IS_ENDPOINT_SOCK(f) \
    ( (f)->f_op == &linux_tcp_helper_fops_tcp || \
      (f)->f_op == &linux_tcp_helper_fops_udp )
#define FILE_IS_ENDPOINT_SPECIAL(f) \
    ( (f)->f_op == &linux_tcp_helper_fops_passthrough || \
      (f)->f_op == &linux_tcp_helper_fops_alien )
#if CI_CFG_USERSPACE_PIPE
#define FILE_IS_ENDPOINT_PIPE(f) \
    ( (f)->f_op == &linux_tcp_helper_fops_pipe_reader || \
      (f)->f_op == &linux_tcp_helper_fops_pipe_writer )
#else
#define FILE_IS_ENDPOINT_PIPE(f) 0
#endif
#if CI_CFG_USERSPACE_EPOLL
#define FILE_IS_ENDPOINT_EPOLL(f) \
    ( (f)->f_op == &oo_epoll_fops )
#else
#define FILE_IS_ENDPOINT_EPOLL(f) 0
#endif

#define FILE_IS_ENDPOINT(f) \
    ( FILE_IS_ENDPOINT_SOCK(f) || FILE_IS_ENDPOINT_PIPE(f) || \
      FILE_IS_ENDPOINT_EPOLL(f) || FILE_IS_ENDPOINT_SPECIAL(f) )



#endif  /* __LINUX_ONLOAD_INTERNAL__ */
