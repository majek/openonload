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
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Dump contents of select set.
**   \date  2004/11/09
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */
#include "internal.h"


int ci_format_select_set(char* s, int len_s, int nfds, const fd_set* fds)
{
  int i, rc, n = 0, first = 1;

  if( len_s < 3 ) {
    s[0] = '\0';
    return 0;
  }
  if( fds == 0 ) {
    s[0] = '[';
    s[1] = ']';
    s[2] = '\0';
    return 2;
  }

  s[0] = '[';
  s[1] = '\0';
  n = 1;

  for( i = 0; i < nfds && len_s - n > 1; ++i )
    if( FD_ISSET(i, fds) ) {
      rc = snprintf(s + n, len_s - n, first ? "%d":",%d", i);
      if( rc < 0 || rc >= len_s - n || len_s - n - rc < 2 ) {
	s[n++] = '-';
	s[n] = '\0';
	return n;
      }
      n += rc;
      first = 0;
    }

  if( len_s - n > 1 ) {
    s[n++] = ']';
    s[n] = '\0';
  }
  return n;
}


int ci_format_select(char* s, int len_s,
		     int nfds, const fd_set* rds, const fd_set* wrs,
		     const fd_set* exs, struct timeval* timeout)
{
  int n = 0, rc;

  rc = snprintf(s + n, len_s - n, "(%d, ", nfds);
  if( rc < 0 || rc >= len_s - n )  return n;
  n += rc;

  n += ci_format_select_set(s + n, len_s - n, nfds, rds);
  if( len_s - n < 3 )  return n;

  n += sprintf(s + n, ", ");

  n += ci_format_select_set(s + n, len_s - n, nfds, wrs);
  if( len_s - n < 3 )  return n;

  n += sprintf(s + n, ", ");

  n += ci_format_select_set(s + n, len_s - n, nfds, exs);
  if( len_s - n < 3 )  return n;

  if( timeout )
    rc = snprintf(s + n, len_s - n, ", {%ld,%ld})",
		  (long)timeout->tv_sec, (long)timeout->tv_usec);
  else
    rc = snprintf(s + n, len_s - n, ", NULL)");
  if( rc < 0 || rc >= len_s - n )  return n;
  n += rc;

  return n;
}

/*! \cidoxg_end */
