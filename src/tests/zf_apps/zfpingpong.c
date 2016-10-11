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
**  \brief  zfpingpong application
**   \date  2015/10/20
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <zf/zf.h>
#include <zf/attr.h>

#include <zf/zf_udp.h>

#include <arpa/inet.h>

#include <zf/zf_reactor.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <inttypes.h>

#include "zf_utils.h"

__attribute__((unused)) static void hexdump(const void* pv, int len)
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


struct sockaddr_in parse_addr(char* addr)
{
  char* port = strchr(addr, ':');
  ZF_TEST(port != NULL);
  *port = 0;
  ++port;
  struct sockaddr_in laddr = {
    .sin_family = AF_INET,
    .sin_addr = { inet_addr(addr) },
    .sin_port = htons(atoi(port)),
  };
  return laddr;
}


static void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  zfpingpong [<options>] {ping|pong} <host:port> <host:port>\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -s udp payload in bytes\n");
  fprintf(stderr, "  -i number of iterations\n");
  fprintf(stderr, "\n");
  exit(1);
}

struct _cfg {
  int size;
  int itercount;
  int ping;
  const char* laddr;
  const char* raddr;

} cfg = {
  .size = 12,
  .itercount = 1000000,
};


static void
ping(struct zf_stack* stack, struct zfut* ut, struct zfur* ur, double* rtt)
{
  unsigned char data[1500];
  struct {
    struct zfur_msg zcr;
    struct iovec iov[2];
  } rd = { { .iovcnt = 2 } };

  uint64_t* ping_last_word = cfg.size >= 8 ? ((uint64_t*)&data[cfg.size]) -1 : 0;

  if( ping_last_word )
    *ping_last_word = 0x1122334455667788;
  ZF_TRY(zfut_send_single(ut, data, cfg.size));

  struct timeval start, end;
  gettimeofday(&start, NULL);
  for(int it = 0; it < cfg.itercount;) {
    while(zf_reactor_perform(stack) == 0);

    rd.zcr.iovcnt = 2;
    ZF_TRY(zfur_zc_recv(ur, &rd.zcr, 0));

    if( rd.zcr.iovcnt == 0 )
      continue;

    if( ping_last_word )
      ++*ping_last_word;
    ZF_TRY(zfut_send_single(ut, data, cfg.size));

    it += rd.zcr.iovcnt;
    zfur_zc_recv_done(ur, &rd.zcr);
  }
  gettimeofday(&end, NULL);

  int usec = (end.tv_sec - start.tv_sec) * 1000000;
  usec += end.tv_usec - start.tv_usec;
  *rtt = (double) usec / cfg.itercount;
}


void pong(struct zf_stack* stack, struct zfut* ut, struct zfur* ur)
{
  struct {
    struct zfur_msg zcr;
    struct iovec iov[2];
  } rd = { { .iovcnt = 2 } };

  for(int it = 0; it < cfg.itercount;) {
    while(zf_reactor_perform(stack) == 0);

    rd.zcr.iovcnt = 2;
    ZF_TRY(zfur_zc_recv(ur, &rd.zcr, 0));

    if( rd.zcr.iovcnt == 0 )
      continue;

    /* in pong we reply with the same data */
    for( int i = 0 ; i < rd.zcr.iovcnt; ++i ) {
      ZF_TRY(zfut_send_single(ut, rd.zcr.iov[i].iov_base,
                              rd.zcr.iov[i].iov_len));
    }

    it += rd.zcr.iovcnt;
    zfur_zc_recv_done(ur, &rd.zcr);
  }
}


int main(int argc, char* argv[])
{
  int c;
  while( (c = getopt(argc, argv, "s:i:")) != -1 )
    switch( c ) {
    case 's':
      cfg.size = atoi(optarg);
      break;
    case 'i':
      cfg.itercount = atoi(optarg);
      break;
    case '?':
      usage();
      /* Fall through. */
    default:
      ZF_TEST(0);
    }

  argc -= optind;
  argv += optind;

  ZF_TEST(argc >= 3);

  cfg.ping = strcmp(argv[0], "ping") == 0;
  cfg.laddr = argv[1];
  cfg.raddr = argv[2];

  ZF_TRY(zf_init());

  struct zf_attr* attr;
  ZF_TRY(zf_attr_alloc(&attr));

  struct zf_stack* stack;
  ZF_TRY(zf_stack_alloc(attr, &stack));

  struct zfur* ur;
  ZF_TRY(zfur_alloc(&ur, stack, attr));

  struct sockaddr_in laddr = parse_addr((char*)cfg.laddr);
  struct sockaddr_in raddr = parse_addr((char*)cfg.raddr);
  ZF_TRY(zfur_addr_bind(ur, &laddr, &raddr, 0));

  struct zfut* ut;
  ZF_TRY(zfut_alloc(&ut, stack, &laddr, &raddr, 0, attr));

  if( cfg.ping ) {
    double rtt;
    ping(stack, ut, ur, &rtt);
    printf("mean round-trip time: %0.3f usec\n", rtt);
  }
  else {
    pong(stack, ut, ur);
  }

  return 0;
}
