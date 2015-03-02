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
** \author  adp
**  \brief  Ioctls for ioctl() call compatibilty 
**   \date  2004/7/29
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_net  */

#ifndef __CI_NET_IOCTLS_H__
#define __CI_NET_IOCTLS_H__


# define SIOCINQ  FIONREAD
# define SIOCOUTQ TIOCOUTQ
# ifndef SIOCOUTQNSD
#  define SIOCOUTQNSD 0x894b
# endif
# ifndef SIOCGSTAMPNS
#  define SIOCGSTAMPNS 0x8907
# endif

#endif /* __CI_NET_IOCTLS_H__ */
