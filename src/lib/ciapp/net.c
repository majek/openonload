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
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */

#include <ci/app.h>

#include <fcntl.h>
#include <ctype.h>


#define MAX_HOSTNAME_LEN  100


int ci_host_port_to_sockaddr(const char* host, int port,
			     struct sockaddr_in* sa_out)
{
  ci_assert(sa_out);

  if( host && host[0] == '\0' )  host = 0;

  /* clobber! */
  sa_out->sin_family = 0;

  if( host == 0 ) {  /* port number only */
    sa_out->sin_addr.s_addr = CI_BSWAPC_BE32(INADDR_ANY);
  }
  else {
    /* try dotted quad format first */
    /* note that winsock doesn't have inet_aton */
    sa_out->sin_addr.s_addr = inet_addr(host);

    if( sa_out->sin_addr.s_addr == INADDR_NONE ) {
      /* no? then try looking up name */
      struct hostent* he;
      if( (he = gethostbyname(host)) == 0 )
	return -ENOENT;
      memcpy(&sa_out->sin_addr, he->h_addr_list[0], sizeof(sa_out->sin_addr));
    }
  }

  sa_out->sin_family = AF_INET;
  sa_out->sin_port = CI_BSWAP_BE16(port);
  return 0;
}


int ci_hostport_to_sockaddr(const char* hp, struct sockaddr_in* sa_out)
{
  char host[MAX_HOSTNAME_LEN];
  const char* s;
  char* d;
  int all_num = 1;
  unsigned port = 0;

  ci_assert(hp);  ci_assert(sa_out);

  /* clobber! */
  sa_out->sin_family = 0;

  /* copy out host bit, and find port bit (if any) */
  d = host;
  s = hp;
  while( *s && *s != ':' && d - host < MAX_HOSTNAME_LEN - 1 ) {
    if( !isdigit(*s) )  all_num = 0;
    *d++ = *s++;
  }
  *d = 0;

  if( d - host >= MAX_HOSTNAME_LEN )
    return -ENAMETOOLONG;

  if( *s != ':' && all_num ) {  /* port number only */
    if( sscanf(hp, "%u", &port) != 1 )
      return -ENOENT;
    sa_out->sin_addr.s_addr = CI_BSWAPC_BE32(INADDR_ANY);
  }
  else {
    /* try dotted quad format first */
    /* note that winsock doesn't have inet_aton */
    sa_out->sin_addr.s_addr = inet_addr(host);

    if( sa_out->sin_addr.s_addr == INADDR_NONE ) {
      /* no? then try looking up name */
      struct hostent* he;
      if( (he = gethostbyname(host)) == 0 )
	return -ENOENT;
      memcpy(&sa_out->sin_addr, he->h_addr_list[0], sizeof(sa_out->sin_addr));
    }

    if( *s == ':' )  /* port specified? */
      if( sscanf(s + 1, "%u", &port) != 1 )
	return -ENOENT;
  }

  sa_out->sin_family = AF_INET;
  sa_out->sin_port = htons((unsigned short) port);
  return 0;
}


int ci_ntoa(struct in_addr in, char* buf)
{
  ci_uint32 b;
  unsigned char *a = (unsigned char *)&b;
  b = CI_BSWAP_BE32(in.s_addr);
  return sprintf(buf, "%d.%d.%d.%d",
		 (int) a[3], (int) a[2], (int) a[1], (int) a[0]);
}


int ci_setfdblocking(int s, int blocking)
{
  int nonb = !blocking;
  return ioctl(s, FIONBIO, &nonb);
}

/*! \cidoxg_end */
