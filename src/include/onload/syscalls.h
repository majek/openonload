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
** \author  David Riddoch
**  \brief  Declare the onload entry-points.
**   \date  2011/01/06
**    \cop  (c) Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_SYSCALLS_H__
#define __ONLOAD_SYSCALLS_H__

/*
 * This head declares the public interface for linking directly to the
 * Onload library.
 *
 */

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <signal.h>
#if __GNUC__ >= 3 		/* ?? XXX FIXME */
# include <sys/sendfile.h>
#endif


/*! Generate declarations of pointers to the system calls */
#define CI_MK_DECL(ret, fn, args)  extern ret onload_##fn args
#include <onload/declare_syscalls.h.tmpl>


#endif  /* __ONLOAD_SYSCALLS_H__ */
