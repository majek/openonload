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
** \author  slp
**  \brief  Linux-specific functions used in common code
**     $Id$
**   \date  2002/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux_onload */
 
/*--------------------------------------------------------------------
 *
 * CI headers
 *
 *--------------------------------------------------------------------*/

#include <onload/fd_private.h>
#include <ci/internal/ip.h>
#include <onload/linux_onload_internal.h>
#include <onload/efabcfg.h>
#include <onload/tcp_helper.h>


ci_private_t *
ci_fpriv(struct file *filp)
{
  if( filp->f_op != &oo_fops ) /* not one of ours */
    return NULL;

  return (ci_private_t *)(filp->private_data);
}

struct file *
ci_privf(ci_private_t *priv)
{
  return priv->_filp;
}


#if CI_MEMLEAK_DEBUG_ALLOC_TABLE
/* See ci/tools/memleak_debug.h */
struct ci_alloc_entry *ci_alloc_table[CI_ALLOC_TABLE_BULKS];
unsigned int ci_alloc_table_sz = 0;
EXPORT_SYMBOL(ci_alloc_table_add);
EXPORT_SYMBOL(ci_alloc_table_del);
#endif /* CI_MEMLEAK_DEBUG_ALLOC_TABLE */


/*! \cidoxg_end */
