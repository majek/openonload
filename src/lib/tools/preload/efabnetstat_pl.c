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
** \author  djr
**  \brief  LD_PRELOAD library to modify "netstat" behaviour.
**   \date  2005/11/22
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#define  _GNU_SOURCE  /* for RTLD_NEXT */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <dlfcn.h>


#define ME		"libefabnetstat_pl.so: "


static int (*sys_open)(const char* path, int flags, ...);
static FILE* (*sys_fopen)(const char* path, const char* mode);


int load_sym_fail(const char* sym)
{
  fprintf(stderr, ME "dlsym(\"%s\") failed\n", sym);
  fprintf(stderr, ME "dlerror '%s'\n", dlerror());
  return -1;
}


const char* mangle(const char* path)
{
  const char* s;
  if( ! strcmp(path, "/proc/net/tcp") && (s = getenv("NETSTAT_TCP")) )
    path = s;
  else if( ! strcmp(path, "/proc/net/udp") && (s = getenv("NETSTAT_UDP")) )
    path = s;
  else if( ! strcmp(path, "/proc/net/tcp6") && (s = getenv("NETSTAT_TCP6")) )
    path = s;
  else if( ! strcmp(path, "/proc/net/udp6") && (s = getenv("NETSTAT_UDP6")) )
    path = s;
  else if( ! strcmp(path, "/proc/net/raw") && (s = getenv("NETSTAT_RAW")) )
    path = s;
  else if( ! strcmp(path, "/proc/net/raw6") && (s = getenv("NETSTAT_RAW6")) )
    path = s;
  else if( ! strcmp(path, "/proc/net/unix") && (s = getenv("NETSTAT_UNIX")) )
    path = s;
  else if( ! strcmp(path, "/proc/net/ipx") && (s = getenv("NETSTAT_IPX")) )
    path = s;
  else if( ! strcmp(path, "/proc/net/ax25") && (s = getenv("NETSTAT_AX25")) )
    path = s;
  else if( ! strcmp(path, "/proc/net/x25") && (s = getenv("NETSTAT_X25")) )
    path = s;
  else if( ! strcmp(path, "/proc/net/nr") && (s = getenv("NETSTAT_NR")) )
    path = s;
  return path;
}


FILE* fopen(const char* path, const char* mode)
{
  if( sys_fopen == 0 ) {
    sys_fopen = dlsym(RTLD_NEXT, "fopen");
    if( sys_fopen == 0 )  load_sym_fail("fopen");
  }

  return sys_fopen(mangle(path), mode);
}


int open(const char* path, int flags, ...)
{
  mode_t mode;
  va_list va;
  va_start(va, flags);
  mode = va_arg(va, mode_t);
  va_end(va);

  if( sys_open == 0 ) {
    sys_open = dlsym(RTLD_NEXT, "open");
    if( sys_open == 0 )  load_sym_fail("open");
  }

  return sys_open(mangle(path), flags, mode);
}
