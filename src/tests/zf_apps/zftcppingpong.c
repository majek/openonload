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

#include <zf/zf.h>
#include <zf/attr.h>
#include <zf/muxer.h>

#include <zf/zf_tcp.h>

#include <arpa/inet.h>

#include <zf/zf_reactor.h>

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include "zf_utils.h"

#define BUFFER_SIZE 1500

static int shutdown_now;

static void handler(int sig)
{
  shutdown_now = 1;
}


struct zf_muxer_set *muxer;


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
  fprintf(stderr, "  zftcppingpong [<options>] {ping|pong} <local-host:port>");
  fprintf(stderr, " [remote-host:port]\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -s tcp payload in bytes\n");
  fprintf(stderr, "  -i number of iterations\n");
  fprintf(stderr, "  -d pong arbitrary data (not latency test pingpong)\n");
  fprintf(stderr, "  -e echo data locally (in -d mode)\n");
  fprintf(stderr, "  -m use multiplexer\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "remote-host:port should be specified when and only when");
  fprintf(stderr, " run in 'pong' mode.\n");
  fprintf(stderr, "\n");
  exit(1);
}

struct _cfg {
  int size;
  int itercount;
  int ping;
  int latency_test;
  int echo;
  int muxer;
  const char* laddr;
  const char* raddr;

} cfg = {
  .size = 12,
  .itercount = 1000000,
  .latency_test = 1,
  .echo = 0,
  .muxer = 0,
};


void ping(struct zf_stack* stack, struct zft* tcp, double* rtt)
{
  unsigned char data[BUFFER_SIZE];
  struct iovec siov = { data, 1};
  struct { 
    struct zft_msg zcr;
    struct iovec iov[2]; 
  } rd = { { .iovcnt = 2 } };
  struct epoll_event event;
  int events;


  uint64_t* ping_last_word = cfg.size >= 8 ?
                             ((uint64_t*)&data[cfg.size]) -1 : 0;

  siov.iov_len = cfg.size;
  if( ping_last_word )
    *ping_last_word = 0x1122334455667788;

  if( cfg.muxer ) {
    /* Poll until ready to send */
    do {
      events = zf_muxer_wait(muxer, &event, 1, -1);
      ZF_TEST(events > 0);
    } while( ! (event.events & EPOLLOUT) );
    ZF_TRY(zft_send(tcp, &siov, 1, 0));
  }
  else {
    while(zft_send(tcp, &siov, 1, 0) < 0);
  }

  struct timeval start, end;
  gettimeofday(&start, NULL);

  for(int it = 0; it < cfg.itercount;) {
    if( cfg.muxer ) {
      /* Must poll at least once */
      do {
        events = zf_muxer_wait(muxer, &event, 1, -1);
        ZF_TEST(events > 0);
      } while( ! (event.events & EPOLLIN) );
    }
    else {
      while(zf_reactor_perform(stack) == 0);
    }

    rd.zcr.iovcnt = 2;
    ZF_TRY(zft_zc_recv(tcp, &rd.zcr, 0));

    if( rd.zcr.iovcnt == 0 )
      continue;

    if( ping_last_word )
      ++*ping_last_word;
    if( cfg.muxer )
      /* May already be ready to send after poll above */
      while( ! (event.events & EPOLLOUT) ) {
        events = zf_muxer_wait(muxer, &event, 1, -1);
        ZF_TEST(events > 0);
      }
    ZF_TRY(zft_send(tcp, &siov, 1, 0));

    it += rd.zcr.iovcnt;
    zft_zc_recv_done(tcp, &rd.zcr);
  }

  gettimeofday(&end, NULL);

  int usec = (end.tv_sec - start.tv_sec) * 1000000;
  usec += end.tv_usec - start.tv_usec;
  *rtt = (double) usec / cfg.itercount;
}


void latency_pong(struct zf_stack* stack, struct zft* tcp)
{
  struct iovec siov;
  struct {
    struct zft_msg zcr;
    struct iovec iov[1];
  } rd = { { .iovcnt = 1 } };
  struct epoll_event event;
  int events;

  for(int it = 0; it < cfg.itercount; it++) {
    do {
      if( cfg.muxer ) {
        /* Poll until ready to receive */
        do {
          events = zf_muxer_wait(muxer, &event, 1, -1);
          ZF_TEST(events > 0);
        } while( ! (event.events & EPOLLIN) );
      }
      else {
        while(zf_reactor_perform(stack) == 0);
      }

      rd.zcr.iovcnt = 1;
      ZF_TRY(zft_zc_recv(tcp, &rd.zcr, 0));

    } while( rd.zcr.iovcnt == 0 );

    /* in pong we reply with the same data */
    siov.iov_base = ((char*)rd.zcr.iov[0].iov_base);
    siov.iov_len = rd.zcr.iov[0].iov_len;
    if( cfg.muxer )
      /* If not ready to send from earlier, poll until ready */
      while( ! (event.events & EPOLLOUT) ) {
        events = zf_muxer_wait(muxer, &event, 1, -1);
        ZF_TEST(events > 0);
      }
    ZF_TRY(zft_send(tcp, &siov, 1, 0));
    zft_zc_recv_done(tcp, &rd.zcr);
  }
}


void data_pong(struct zf_stack* stack, struct zft* tcp)
{
  struct iovec siov;
  struct {
    struct zft_msg zcr;
    struct iovec iov[2];
  } rd = { { .iovcnt = 2 } };

  while( 1 ) {
    struct epoll_event event;
    int events;

    if( cfg.muxer ) {
      /* Poll until ready to receive */
      do {
        events = zf_muxer_wait(muxer, &event, 1, -1);
        ZF_TEST(events > 0);
      } while( !(event.events & (EPOLLIN | EPOLLRDHUP)) && !shutdown_now );

      if( event.events & EPOLLRDHUP )
        shutdown_now = 1;
    }
    else {
      while(!zf_reactor_perform(stack) && !shutdown_now);
    }

    if( shutdown_now )
      return;

    rd.zcr.iovcnt = 2;
    ZF_TRY(zft_zc_recv(tcp, &rd.zcr, 0));

    /* Drain the receive queue */
    while( rd.zcr.iovcnt ) {
      for( int i = 0 ; i < rd.zcr.iovcnt; ++i ) {
        if( rd.zcr.iov[i].iov_len > 0 ) {
          int rc;

          siov.iov_base = ((char*)rd.zcr.iov[i].iov_base);
          siov.iov_len = rd.zcr.iov[i].iov_len;

          if( cfg.muxer ) {
            while( 1 ) {
              /* If not ready to send from earlier, poll until ready */
              while( ! (event.events & EPOLLOUT) ) {
                events = zf_muxer_wait(muxer, &event, 1, -1);
                ZF_TEST(events > 0);
              }

              rc = zft_send(tcp, &siov, 1, 0);
              if( rc == -EAGAIN ) {
                /* Although ready for EPOLLOUT, send buffer space could be
                 * too small for the outgoing packet; mark as not ready so
                 * that the muxer is polled to attempt to free some space
                 */
                event.events &= ~EPOLLOUT;
                continue;
              }
              else {
                break;
              }
            }
          }
          else {
            rc = zft_send(tcp, &siov, 1, 0);

            while( rc == -EAGAIN ) {
              /* Poll to free up send buffer space and then retry send */
              while( ! zf_reactor_perform(stack) );

              rc = zft_send(tcp, &siov, 1, 0);
            }
          }
          ZF_TEST(rc == 0);

          if(cfg.echo) {
            fwrite(siov.iov_base, sizeof(char), siov.iov_len, stdout);
            fwrite("\n", sizeof(char), strlen("\n"), stdout);
          }
        }
        else {
          printf("Got EOF - doing shutdown\n");
          zf_assert_equal(i+1, rd.zcr.iovcnt);
          zft_zc_recv_done(tcp, &rd.zcr);
          return;
        }
      }
      zft_zc_recv_done(tcp, &rd.zcr);
      ZF_TRY(zft_zc_recv(tcp, &rd.zcr, 0));
    }
  }
}


int main(int argc, char* argv[])
{
  int c;
  while( (c = getopt(argc, argv, "s:i:dem")) != -1 ) {
    switch( c ) {
    case 's':
      cfg.size = atoi(optarg);
      break;
    case 'i':
      cfg.itercount = atoi(optarg);
      break;
    case 'd':
      cfg.latency_test = 0;
      break;
    case 'e':
      cfg.echo = 1;
      break;
    case 'm':
      cfg.muxer = 1;
      break;
    case '?':
      usage();
      /* Fall through. */
    default:
      ZF_TEST(0);
    }
  }

  argc -= optind;
  argv += optind;

  cfg.ping = strcmp(argv[0], "ping") == 0;
  ZF_TEST(argc >= 2 + ! cfg.ping);

  cfg.laddr = argv[1];
  cfg.raddr = argv[2];

  ZF_TEST(cfg.size > 0);
  ZF_TEST(cfg.size <= BUFFER_SIZE);

  struct sigaction sa;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handler;
  ZF_TRY(sigaction(SIGUSR1, &sa, NULL));

  ZF_TRY(zf_init());

  struct zf_attr* attr;
  ZF_TRY(zf_attr_alloc(&attr));

  struct zf_stack* stack;
  ZF_TRY(zf_stack_alloc(attr, &stack));

  struct zft_handle* tcp_handle;
  ZF_TRY(zft_alloc(stack, attr, &tcp_handle));

  struct sockaddr_in laddr = parse_addr((char*)cfg.laddr);
  struct zft* tcp;

  if( ! cfg.ping ) {
    /* In 'pong' mode, just connect to the specified remote address. */
    struct sockaddr_in raddr = parse_addr((char*)cfg.raddr);
    ZF_TRY(zft_addr_bind(tcp_handle, &laddr, 0));
    ZF_TRY(zft_connect(tcp_handle, &raddr, &tcp));
  }
  else {
    /* In 'ping' mode, create a listening zocket and wait until we've accepted
     * a connection from the 'ping' end. */
    struct zftl* listener;
    int rc;
    ZF_TRY(zftl_listen(stack, &laddr, attr, &listener));
    printf("Listening for incoming connection\n");
    do {
      while( zf_reactor_perform(stack) == 0 );
    } while( (rc = zftl_accept(listener, &tcp)) == -EAGAIN );
    ZF_TRY(rc);
    printf("Connection accepted\n");
    ZF_TRY(zftl_free(listener));
  }

  if( cfg.muxer ) {
    struct epoll_event event = { .events = EPOLLIN | EPOLLOUT | 
                                           EPOLLHUP | EPOLLRDHUP };
    ZF_TRY(zf_muxer_alloc(stack, &muxer));
    ZF_TRY(zf_muxer_add(muxer, zft_to_waitable(tcp), &event));
  }

  if(cfg.ping) {
    double rtt;
    ping(stack, tcp, &rtt);
    printf("mean round-trip time: %0.3f usec\n", rtt);
  }
  else if(cfg.latency_test) {
    latency_pong(stack, tcp);
  }
  else {
    data_pong(stack, tcp);
  }

  while( zft_shutdown_tx(tcp) == -ENOSPC )
    zf_reactor_perform(stack);

  while( ! zf_stack_is_quiescent(stack) )
    zf_reactor_perform(stack);

  if( cfg.muxer ) {
    zf_muxer_del(zft_to_waitable(tcp));
    zf_muxer_free(muxer);
  }

  ZF_TRY(zft_free(tcp));

  return 0;
}
