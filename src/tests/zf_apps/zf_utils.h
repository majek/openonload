/*
** Copyright 2005-2018  Solarflare Communications Inc.
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
** \author  mj
**  \brief  ZF logging facilities
**   \date  2015/10/20
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ZF_APPS_UTILS_H__
#define __ZF_APPS_UTILS_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>

#define ZF_TRY(x)                                                       \
  do {                                                                  \
    int __rc = (x);                                                     \
    if( __rc < 0 ) {                                                    \
      fprintf(stderr, "ERROR: %s: ZF_TRY(%s) failed\n", __func__, #x);  \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      fprintf(stderr, "ERROR: rc=%d (%s) errno=%d\n",                   \
              __rc, strerror(-__rc), errno);                            \
      abort();                                                          \
    }                                                                   \
  } while( 0 )


#define ZF_TEST(x)                                                      \
  do {                                                                  \
    if( ! (x) ) {                                                       \
      fprintf(stderr, "ERROR: %s: ZF_TEST(%s) failed\n", __func__, #x); \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      abort();                                                          \
    }                                                                   \
  } while( 0 )


static inline int getaddrinfo_hostport(const char* hostport_c,
                                       const struct addrinfo* hints,
                                       struct addrinfo** res)
{
  char* hostport = strdup(hostport_c);
  if( hostport == NULL )
    return EAI_MEMORY;
  char* port = strrchr(hostport, ':');
  if( port != NULL )
    *port++ = '\0';
  struct addrinfo hints2;
  if( hints == NULL ) {
    memset(&hints2, 0, sizeof(hints2));
    hints = &hints2;
  }
  int rc = getaddrinfo(hostport, port, hints, res);
  free(hostport);
  return rc;
}


#endif /* __ZF_APPS_UTILS_H__ */
