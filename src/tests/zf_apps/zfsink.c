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
** <L5_PRIVATE L5_HEADER >
** \author  mj
**  \brief  zfsink application
**   \date  2015/10/20
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <zf/zf.h>
#include "zf_utils.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <stdbool.h>
#include <stdarg.h>


static bool cfg_quiet = false;


static void usage_msg(FILE* f)
{
  fprintf(f, "usage:\n");
  fprintf(f, "  zfsink <options> <local_host:port> [remote_host:port]\n");
  fprintf(f, "\n");
  fprintf(f, "options:\n");
  fprintf(f, "  -h       Print this usage message\n");
  fprintf(f, "  -m       Use the zf multiplexer\n");
  fprintf(f, "  -w       Use the zf waitable fd\n");
  fprintf(f, "  -q       Quiet -- do not emit progress messages\n");
}


static void usage_err(void)
{
  usage_msg(stderr);
  exit(1);
}


static void vlog(const char* fmt, ...)
{
  if( ! cfg_quiet ) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
  }
}


static void try_recv(struct zfur* ur)
{
  struct {
    struct zfur_msg msg;
    struct iovec iov[1];
  } rd;

  do {
    rd.msg.iovcnt = sizeof(rd.iov) / sizeof(rd.iov[0]);
    zfur_zc_recv(ur, &rd.msg, 0);

    if( rd.msg.iovcnt == 0 )
      break;

    /* Do something useful with the datagram here! */

    vlog("Received datagram of length %zu\n", rd.iov[0].iov_len);
    zfur_zc_recv_done(ur, &rd.msg);
  } while( rd.msg.dgrams_left );
}


static void poll_muxer(struct zf_muxer_set* muxer, int timeout)
{
  struct epoll_event evs[8];
  const int max_evs = sizeof(evs) / sizeof(evs[0]);

  vlog("Polling muxer\n");
  int n_ev = zf_muxer_wait(muxer, evs, max_evs, timeout);

  for( int i = 0; i < n_ev; ++i )
    try_recv(evs[i].data.ptr);
}


static void ev_loop_reactor(struct zf_stack* stack, struct zfur* ur)
{
  while( 1 ) {
    vlog("Polling reactor\n");
    while( zf_reactor_perform(stack) == 0 )
      ;
    try_recv(ur);
  }
}


static void ev_loop_muxer(struct zf_muxer_set* muxer)
{
  while( 1 )
    poll_muxer(muxer, -1);
}


static void ev_loop_waitable_fd(struct zf_stack* stack,
                                struct zf_muxer_set* muxer)
{
  int waitable_fd;
  ZF_TRY(zf_waitable_fd_get(stack, &waitable_fd));
  ZF_TRY(zf_waitable_fd_prime(stack));

  int epollfd = epoll_create(10);
  struct epoll_event ev = { .events = EPOLLIN, .data.fd = waitable_fd };
  ZF_TRY(epoll_ctl(epollfd, EPOLL_CTL_ADD, waitable_fd, &ev));

  while( 1 ) {
    struct epoll_event evs[8];
    const int max_evs = sizeof(evs) / sizeof(evs[0]);

    vlog("Calling epoll_wait\n");
    int n_ev = epoll_wait(epollfd, evs, max_evs, -1);

    for( int i = 0; i < n_ev; ++i )
      if( evs[i].data.fd == waitable_fd ) {
        poll_muxer(muxer, 0);
        ZF_TRY(zf_waitable_fd_prime(stack));
      }
      else {
        /* Not possible in this sample code. */
      }
  }
}


int main(int argc, char* argv[])
{
  int cfg_muxer = 0;
  int cfg_waitable_fd = 0;

  int c;
  while( (c = getopt(argc, argv, "hmwq")) != -1 )
    switch( c ) {
    case 'h':
      usage_msg(stdout);
      exit(0);
    case 'm':
      cfg_muxer = 1;
      break;
    case 'w':
      cfg_waitable_fd = 1;
      break;
    case 'q':
      cfg_quiet = true;
      break;
    case '?':
      exit(1);
    default:
      ZF_TEST(0);
    }

  argc -= optind;
  argv += optind;

  struct addrinfo *ai_local = NULL, *ai_remote = NULL;
  switch( argc ) {
  case 2:
    ZF_TEST(getaddrinfo_hostport(argv[1], NULL, &ai_remote) == 0);
    /* fall through */
  case 1:
    ZF_TEST(getaddrinfo_hostport(argv[0], NULL, &ai_local) == 0);
    break;
  default:
    usage_err();
    break;
  }

  ZF_TRY(zf_init());

  struct zf_attr* attr;
  ZF_TRY(zf_attr_alloc(&attr));

  struct zf_stack* stack;
  ZF_TRY(zf_stack_alloc(attr, &stack));

  struct zfur* ur;
  ZF_TRY(zfur_alloc(&ur, stack, attr));

  if( ai_remote )
    ZF_TRY(zfur_addr_bind(ur, ai_local->ai_addr, ai_local->ai_addrlen,
                          ai_remote->ai_addr, ai_remote->ai_addrlen, 0));
  else
    ZF_TRY(zfur_addr_bind(ur, ai_local->ai_addr, ai_local->ai_addrlen,
                          NULL, 0, 0));

  /* Initialise the multiplexer if we're going to use one. */
  struct epoll_event event = { .events = EPOLLIN, .data = { .ptr = ur } };
  struct zf_muxer_set* muxer;
  if( cfg_muxer || cfg_waitable_fd ) {
    ZF_TRY(zf_muxer_alloc(stack, &muxer));
    ZF_TRY(zf_muxer_add(muxer, zfur_to_waitable(ur), &event));
  } 

  if( cfg_waitable_fd )
    ev_loop_waitable_fd(stack, muxer);
  else if( cfg_muxer )
    ev_loop_muxer(muxer);
  else
    ev_loop_reactor(stack, ur);

  return 0;
}
