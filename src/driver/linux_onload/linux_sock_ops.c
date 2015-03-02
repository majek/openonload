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
*//*! \file linux_sock_ops.c Socket operations interception for Linux
** <L5_PRIVATE L5_SOURCE>
** \author  mjs
**  \brief  Package - driver/linux	Linux driver support
**   \date  2005/02/14
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux */
 

/*--------------------------------------------------------------------
 *
 * CI headers
 *
 *--------------------------------------------------------------------*/

#include <ci/driver/internal.h>
#include <onload/linux_sock_ops.h>
#include <onload/linux_onload.h>


/**************************************************************************** 
 * 
 * efab_linux_dump_inode: debugging support for dumping inode info
 * 
 ****************************************************************************/ 

int
efab_linux_dump_inode(int fd) 
{
  struct file *filp;
  filp = fget(fd);
  if (filp && filp->f_dentry) {
    struct inode *inode = filp->f_dentry->d_inode;
    
    ci_log("dump inode: fd %d => filp=%p -> dentry %p", fd, filp,
           filp->f_dentry);
    ci_log("  inode at %p", inode);
    ci_log("    i_ino=%lu  i_rdev=%08x",
           inode->i_ino, inode->i_rdev);
    ci_log("    i_op=%p  i_fop=%p  i_sb=%p  i_state=%08lx",
           inode->i_op, inode->i_fop, inode->i_sb, inode->i_state);
    fput(filp);
  } else {
    ci_log("dump_inode: couldn't get struct file for fd %d", fd);
  }
  return 0;
}
