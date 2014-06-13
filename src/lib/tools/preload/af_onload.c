/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
** \author  stg
**  \brief  OpenOnload preload lib.
**   \date  2006/10/24
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_tools_preload  */

#define  _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>


/* TODO needs to go in hdr common with AF_ONLOAD kernel module */
#define PF_ONLOAD 27


static int load_sym_fail(const char* sym)
{
  fprintf(stderr, "libaf_onload: dlsym(\"%s\") failed\n", sym);
  fprintf(stderr, "libaf_onload: dlerror '%s'\n", dlerror());
  return -1;
}


static int accelerate_protocol(int protocol, const char* envname,
                               int accept_protocol, int default_on)
{
  const char* s;

  if( protocol != 0 && protocol != accept_protocol )
    return 0;

  if( (s = getenv(envname)) == NULL )
    return default_on;

  return atoi(s);
}


int socket(int domain, int type, int protocol)
{
  static int (*sys_socket)(int domain, int type, int protocol);

  if( sys_socket == 0 ) {
    sys_socket = dlsym(RTLD_NEXT, "socket");
    if( sys_socket == 0 )  
      return load_sym_fail("socket");
  }

  if( domain == PF_INET || domain == PF_INET6 )
    switch( type ) {
    case SOCK_STREAM:
      if( accelerate_protocol(protocol, "AFONLOAD_TCP", IPPROTO_TCP, 1) )
        domain = PF_ONLOAD;
      break;
    case SOCK_DGRAM:
      if( accelerate_protocol(protocol, "AFONLOAD_UDP", IPPROTO_UDP, 0) )
        domain = PF_ONLOAD;
      break;
    default:
      break;
    }

  return sys_socket(domain, type, protocol);
}

/*
 * vi: sw=2:ai:aw
 * vim: et:ul=0
 */
/*! \cidoxg_end */
