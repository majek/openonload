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
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  slp
**  \brief  Interface for invoking debug ops on resources.
**   \date  2004/08/30
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab  */

#ifndef __ONLOAD_DEBUG_OPS_H__
#define __ONLOAD_DEBUG_OPS_H__

# include <onload/unix_intf.h>

/*! dump inode for a file descriptor */
ci_inline int
oo_debug_dump_inode(ci_fd_t fp, int fd) 
{
  int rc;
  ci_debug_onload_op_t op;
  op.what = __CI_DEBUG_OP_DUMP_INODE__;
  op.u.fd = fd;
  rc = oo_debug_op(fp, &op);
  return rc;
}

/*! debug trampolines */
ci_inline int
oo_debug_trampoline(ci_fd_t fp, ci_uintptr_t * io) 
{					
  int rc;                               
  ci_debug_onload_op_t op;			
  op.what = __CI_DEBUG_OP_TRAMPOLINE__;	
  op.u.tramp_debug = *io;		
  rc = oo_debug_op(fp, &op);		
  *io = op.u.tramp_debug;		
  return rc;                            
}


ci_inline int
oo_debug_fds_dump(ci_fd_t fp, ci_uint32 pid)
{					
  int rc;				
  ci_debug_onload_op_t op;			
  op.what = __CI_DEBUG_OP_FDS_DUMP__;	
  op.u.fds_dump_pid = (pid);		
  rc = oo_debug_op(fp, &op);		
  return rc;				
}

/*! dump inode for a file descriptor */
ci_inline int
oo_debug_dump_stack(ci_fd_t fp, int stack_id) 
{
  int rc;
  ci_debug_onload_op_t op;
  op.what = __CI_DEBUG_OP_DUMP_STACK__;
  op.u.stack_id = stack_id;
  rc = oo_debug_op(fp, &op);
  return rc;
}



#endif  /* __ONLOAD_DEBUG_OPS_H__ */
/*! \cidoxg_end */
