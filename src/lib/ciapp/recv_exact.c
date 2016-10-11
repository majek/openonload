/*
** Copyright 2005-2016  Solarflare Communications Inc.
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
**  \brief  Receive an exact number of bytes from a socket.
**   \date  2004/12/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */

#include <ci/app.h>


int  ci_recv_exact(int sock, void* buf, size_t len, int flags)
{
  int n = 0, rc;

  ci_assert(buf);
  ci_assert(len >= 0);

  while( len ) {
    rc = recv(sock, buf, len, flags);
    if( rc <= 0 )  return n;

    buf = (char*) buf + rc;
    n += rc;
    len -= rc;
  }

  return n;
}

/*! \cidoxg_end */
