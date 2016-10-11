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
#include <zf/attr.h>
#include <zf/muxer.h>

#include <zf/zf_udp.h>

#include <arpa/inet.h>

#include <zf/zf_reactor.h>

#include <stdio.h>
#include <unistd.h>

#include "zf_utils.h"

static int cfg_muxer;


static void hexdump(const void* pv, int len)
{
  const unsigned char* p = (const unsigned char*) pv;
  int i;
  for( i = 0; i < len; ++i ) {
    const char* eos;
    switch( i & 15 ) {
    case 0:
      printf("%08x  ", i);
      eos = "";
      break;
    case 1:
      eos = " ";
      break;
    case 15:
      eos = "\n";
      break;
    default:
      eos = (i & 1) ? " " : "";
      break;
    }
    printf("%02x%s", (unsigned) p[i], eos);
  }
  printf(((len & 15) == 0) ? "\n" : "\n\n");
}


static void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  zfsink <options> <local_addr> <remote_addr>\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -m       Use the multiplexer\n");
  exit(1);
}


/* zf_init <laddr> <raddr> */
int main(int argc, char* argv[])
{
  ZF_TRY(zf_init());

  struct zf_attr* attr;
  ZF_TRY(zf_attr_alloc(&attr));

  struct zf_stack* stack;
  ZF_TRY(zf_stack_alloc(attr, &stack));

  struct zfur* ur;
  ZF_TRY(zfur_alloc(&ur, stack, attr));

  int c;
  while( (c = getopt(argc, argv, "m")) != -1 )
    switch( c ) {
    case 'm':
      cfg_muxer = 1;
      break;
    case '?':
      usage();
      /* Fall through. */
    default:
      ZF_TEST(0);
    }

  argc -= optind;
  argv += optind;

  ZF_TEST( argc >= 2 );

  struct sockaddr_in laddr = {
    .sin_family = AF_INET,
    .sin_addr = { inet_addr(argv[0]) },
    .sin_port = htons(2000),
  };
  struct sockaddr_in raddr = {
    .sin_family = AF_INET,
    .sin_addr = { inet_addr(argv[1]) },
    .sin_port = htons(2000),
  };
  ZF_TRY(zfur_addr_bind(ur, &laddr, &raddr, 0));

  struct {
    struct zfur_msg zcr;
    struct iovec iov[2];
  } rd = { { .iovcnt = 2 } };

  /* Initialise the multiplexer set if we're going to use one. */
  struct epoll_event event = { .events = EPOLLIN };
  struct zf_muxer_set *muxer;
  if( cfg_muxer ) {
    ZF_TRY(zf_muxer_alloc(stack, &muxer));
    ZF_TRY(zf_muxer_add(muxer, zfur_to_waitable(ur), &event));
  }

  while(1) {
    fprintf(stdout, "Waiting for pkt\n");
    if( cfg_muxer ) {
      int events;
      events = zf_muxer_wait(muxer, &event, 1, -1);
      ZF_TEST(events > 0);
    }
    else while( zf_reactor_perform(stack) == 0 )
      ;

    rd.zcr.iovcnt = 2;
    ZF_TRY(zfur_zc_recv(ur, &rd.zcr, 0));

    fprintf(stdout, "Received pkts %d\n", rd.zcr.iovcnt);
    if( rd.zcr.iovcnt != 0 ) {
      for( int i = 0 ; i < rd.zcr.iovcnt; ++i )
         hexdump(rd.zcr.iov[i].iov_base, rd.zcr.iov[i].iov_len);
      zfur_zc_recv_done(ur, &rd.zcr);
    }
 }

  return 0;
}
