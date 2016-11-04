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

/*
 * TCPDirect sample application demonstrating low-latency UDP sends and
 * receives.
 */
#include <zf/zf.h>
#include "zf_utils.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <inttypes.h>


static void usage_msg(FILE* f)
{
  fprintf(f, "usage:\n");
  fprintf(f, "  zfudppingpong [options] pong <ponger:port> <pinger:port>\n");
  fprintf(f, "  zfudppingpong [options] ping <pinger:port> <ponger:port>\n");
  fprintf(f, "\n");
  fprintf(f, "options:\n");
  fprintf(f, "  -s udp payload in bytes\n");
  fprintf(f, "  -i number of iterations\n");
  fprintf(f, "\n");
}


static void usage_err(void)
{
  usage_msg(stderr);
  exit(1);
}


struct cfg {
  int size;
  int itercount;
  int ping;
};


static struct cfg cfg = {
  .size = 12,
  .itercount = 1000000,
};


static void ping_pongs(struct zf_stack* stack, struct zfur* ur, struct zfut* ut)
{
  char send_buf[cfg.size];
  int sends_left = cfg.itercount;
  int recvs_left = cfg.itercount;
  struct {
    struct zfur_msg msg;
    struct iovec iov[2];
  } msg;
  const int max_iov = sizeof(msg.iov) / sizeof(msg.iov[0]);

  if( cfg.ping ) {
    ZF_TEST(zfut_send_single(ut, send_buf, cfg.size) == cfg.size);
    --sends_left;
  }

  do {
    /* Poll the stack until something happens. */
    while( zf_reactor_perform(stack) == 0 )
      ;
    msg.msg.iovcnt = max_iov;
    zfur_zc_recv(ur, &msg.msg, 0);
    if( msg.msg.iovcnt == 0 )
      continue;
    if( sends_left ) {
      ZF_TEST(zfut_send_single(ut, send_buf, cfg.size) == cfg.size);
      --sends_left;
    }
    /* The current implementation of TCPDirect always returns a single
     * buffer for each datagram.  Future implementations may return
     * multiple buffers for large (jumbo) or fragmented datagrams.
     */
    ZF_TEST(msg.msg.iovcnt == 1);
    /* As we're doing a ping-pong we shouldn't ever see any more datagrams
     * queued!
     */
    ZF_TEST(msg.msg.dgrams_left == 0);
    zfur_zc_recv_done(ur, &msg.msg);
    --recvs_left;
  } while( recvs_left );
}


static void pinger(struct zf_stack* stack, struct zfur* ur, struct zfut* ut,
                   double* rtt)
{
  struct timeval start, end;
  gettimeofday(&start, NULL);

  ping_pongs(stack, ur, ut);

  gettimeofday(&end, NULL);
  int usec = (end.tv_sec - start.tv_sec) * 1000000;
  usec += end.tv_usec - start.tv_usec;
  *rtt = (double) usec / cfg.itercount;
}


static void ponger(struct zf_stack* stack, struct zfur* ur, struct zfut* ut)
{
  ping_pongs(stack, ur, ut);
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
      exit(1);
    default:
      ZF_TEST(0);
    }

  argc -= optind;
  argv += optind;
  if( argc != 3 )
    usage_err();

  if( ! strcmp(argv[0], "ping") )
    cfg.ping = true;
  else if( ! strcmp(argv[0], "pong") )
    cfg.ping = false;
  else
    usage_err();

  struct addrinfo *ai_local, *ai_remote;
  if( getaddrinfo_hostport(argv[1], NULL, &ai_local) != 0 ) {
    fprintf(stderr, "ERROR: failed to lookup address '%s'\n", argv[1]);
    exit(2);
  }
  if( getaddrinfo_hostport(argv[2], NULL, &ai_remote) != 0 ) {
    fprintf(stderr, "ERROR: failed to lookup address '%s'\n", argv[2]);
    exit(2);
  }

  /* Initialise the TCPDirect library and allocate a stack. */
  ZF_TRY(zf_init());

  struct zf_attr* attr;
  ZF_TRY(zf_attr_alloc(&attr));

  struct zf_stack* stack;
  ZF_TRY(zf_stack_alloc(attr, &stack));

  /* Allocate zockets and bind them to the given addresses.  TCPDirect has
   * separate objects for sending and receiving UDP datagrams.
   */
  struct zfur* ur;
  ZF_TRY(zfur_alloc(&ur, stack, attr));
  ZF_TRY(zfur_addr_bind(ur, ai_local->ai_addr, ai_local->ai_addrlen,
                        ai_remote->ai_addr, ai_remote->ai_addrlen, 0));

  struct zfut* ut;
  ZF_TRY(zfut_alloc(&ut, stack, ai_local->ai_addr, ai_local->ai_addrlen,
                    ai_remote->ai_addr, ai_remote->ai_addrlen, 0, attr));

  if( cfg.ping ) {
    double rtt;
    pinger(stack, ur, ut, &rtt);
    printf("mean round-trip time: %0.3f usec\n", rtt);
  }
  else {
    ponger(stack, ur, ut);
  }

  return 0;
}
