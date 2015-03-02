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

/*
** Copyright 2005-2015  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are
** met:
**
** * Redistributions of source code must retain the above copyright notice,
**   this list of conditions and the following disclaimer.
**
** * Redistributions in binary form must reproduce the above copyright
**   notice, this list of conditions and the following disclaimer in the
**   documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
** IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
** TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
** PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
** HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
** TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
** PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
** LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
** NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


/* efdelegated_server
 *
 * Copyright 2009-2015 Solarflare Communications Inc.
 * Author: Akhi Singhania
 * Date: 2015/1/20
 *
 *
 * This is a sample application to demonstrate usage of the
 * onload_delegated_sends() API.  This API allows you to do sends via
 * ef_vi on an Onloaded TCP socket to get better latency.  The API
 * essentially boils down to first retriving the TCP header, adding
 * your own payload, sending via ef_vi layer, and finally telling the
 * API how many bytes you sent so it can update the internal TCP state
 * machinery.
 *
 * In this application, we compare the performance of an echo server
 * using normal sockets with using the delegated sends API.
 *
 * For normal sends, run apps like below:
 *
 * onload ./efdelegated_server 12345
 * onload ./efdelegated_client <srv-ip-addr> 12345
 *
 * For delegated sends, run apps like below:
 *
 * onload ./efdelegated_server -d 12345
 * onload ./efdelegated_client <srv-ip-addr> 12345
 */

#include <etherfabric/vi.h>
#include <etherfabric/pio.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <onload/extensions.h>
#include "utils.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <ifaddrs.h>


#define MEMBER_OFFSET(c_type, mbr_name)  \
  ((uint32_t) (uintptr_t)(&((c_type*)0)->mbr_name))

#define DEFAULT_PAYLOAD_SIZE  28
#define CACHE_ALIGN           __attribute__((aligned(EF_VI_DMA_ALIGN)))
#define BUF_SIZE              2048

/* To get best performance possible, we prepare to do the next send
 * right after having done the current one.  Therefore, we need at
 * least 2 pkt buffers. */
#define N_BUFS                2

struct pkt_buf {
  ef_addr         dma_buf_addr;
  uint8_t         dma_buf[1] CACHE_ALIGN;
};

static unsigned  cfg_payload_len = DEFAULT_PAYLOAD_SIZE;
static int       cfg_iter        = 100000;
static int       cfg_warm        = 10;
static int       cfg_delegated;

static int      tcp_sock, udp_sock;
static ef_vi    vi;
struct pkt_buf* pkt_bufs[N_BUFS];
static struct onload_delegated_send ods[N_BUFS];


static int min(int x, int y)
{
  return x < y ? x : y;
}


static void evq_poll(void)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event      evs[EF_VI_EVENT_POLL_MIN_EVS];
  int           n_ev, i;

  n_ev = ef_eventq_poll(&vi, evs, sizeof(evs) / sizeof(evs[0]));
  for( i = 0; i < n_ev; ++i )
    switch( EF_EVENT_TYPE(evs[i]) ) {
    case EF_EVENT_TYPE_TX:
      ef_vi_transmit_unbundle(&vi, &evs[i], ids);
      break;
    default:
      fprintf(stderr, "ERROR: unexpected event "EF_EVENT_FMT"\n",
              EF_EVENT_PRI_ARG(evs[i]));
      TEST(0);
      break;
    }
}


static int sock_rx(void)
{
  char buf[1];
  int rc = recv(udp_sock, buf, 1, MSG_DONTWAIT);
  if( rc > 0 ) {
    return rc;
  }
  else if( rc == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) )
    return 0;
  else
    TEST(0);
}


static void rx_wait(void)
{
  do {
    evq_poll();
  } while( sock_rx() == 0 );
}


static void sock_tx(void)
{
  char buf[cfg_payload_len];
  ssize_t size = 0;
  while( size != cfg_payload_len ) {
    ssize_t rc;
    TRY(rc = send(tcp_sock, buf, cfg_payload_len, 0));
    size += rc;
  }
}


/**********************************************************************/
/* Below is the most interesting bit of code in the app */
/**********************************************************************/

/* Prepare to do a delegated send.  You want to try to call this out
 * of the critical path of sending or else you will not be getting
 * very much benefit from the API.
 *
 * In this app, we call this function right after having done the
 * previous send and while we wait for the next ping from the client.
 *
 * This function can be called speculatively.  If later on you decide
 * that you don't want to do a delegated send, you can call
 * onload_delegated_send_cancel().
 */
static void delegated_prepare(int iter)
{
  /* pkt_buf->dma_buf is beginning of the ef_vi packet buffer.  That
   * is where we get the API to copy the TCP header. */
  void* buf = pkt_bufs[iter]->dma_buf;
  int bytes;
  ods[iter].headers = buf;

  /* We also need to tell the API how much space it has to copy the
   * header.  We give it the entire pkt buffer even though we know
   * that it will not need all of it. */
  ods[iter].headers_len = BUF_SIZE -
    (int)((uint8_t*)pkt_bufs[iter] - pkt_bufs[iter]->dma_buf);
  TRY(onload_delegated_send_prepare(tcp_sock, cfg_payload_len, 0, &ods[iter]));
  /* If we want to send more than MSS, we will have to use multiple
   * delegated sends.  We do not handle that case in this app. */
  TEST(cfg_payload_len <= ods[iter].mss);

  /* Figure out how much we are actually allowed to send.  If we are
   * going to send less than MSS, then we need to tell the API. */
  bytes = min(min(min(ods[iter].send_wnd, ods[iter].cong_wnd), ods[iter].mss),
              ods[iter].user_size);
  if( bytes == cfg_payload_len ) {
    int pio_len = ROUND_UP(ods[iter].headers_len + bytes, 16);
    if( bytes < ods[iter].mss )
      onload_delegated_send_tcp_update(&ods[iter], cfg_payload_len, 1);
    TRY(ef_pio_memcpy(&vi, pkt_bufs[iter]->dma_buf, iter * pio_len, pio_len));
  }
}


/* Do the actual delegated send. */
static void delegated_send(int iter)
{
  /* Figure out how much we are actually allowed to send. */
  int bytes = min(min(min(ods[iter].send_wnd, ods[iter].cong_wnd),
                      ods[iter].mss), ods[iter].user_size);
  int pio_len = ROUND_UP(ods[iter].headers_len + bytes, 16);

  /* If we cannot send as much as we want to, either do a set of
   * delegated sends or just call onload_delegated_send_cancel() and
   * do a normal send.  Both approaches should have comparable
   * performance.  We do the latter here. */
  if( bytes < cfg_payload_len ) {
    TRY(onload_delegated_send_cancel(tcp_sock));
    sock_tx();
  }
  else {
    struct iovec iov;
    TRY(ef_vi_transmit_pio(&vi, iter * pio_len, pio_len, 0));
    iov.iov_len  = cfg_payload_len;
    iov.iov_base = (uint8_t*)pkt_bufs[iter]->dma_buf + ods[iter].headers_len;
    TRY(onload_delegated_send_complete(tcp_sock, &iov, 1, 0));
  }
}


static void delegated_tx(int iter)
{
  if( iter == 0 )
    delegated_prepare(0);
  delegated_send(iter % N_BUFS);
  delegated_prepare((iter + 1) % N_BUFS);
}


static void loop(void)
{
  int i;
  /* Do some warmup sends to open up the TCP windows. */
  for( i = 0; i < cfg_warm; ++i ) {
    rx_wait();
    sock_tx();
  }

  for( i = 0; i < cfg_iter; ++i ) {
    rx_wait();
    if( cfg_delegated )
      delegated_tx(i);
    else
      sock_tx();
  }
  if( cfg_delegated )
    TRY(onload_delegated_send_cancel(tcp_sock));
}


/**********************************************************************/
/* Below is just initialization cruft and not really interesting for
 * delegated sends API. */
/**********************************************************************/

static int parse_interface(const char* intf_name, int* ifindex_out)
{
  if( (*ifindex_out = if_nametoindex(intf_name)) == 0 )
    return -errno;
  return 0;
}


static int get_ifindex(int sock, int* ifindex_out)
{
  int rc = -1;
  struct ifaddrs *addrs, *iap;
  struct sockaddr_in sa;
  char sock_ip_addr[32];
  socklen_t len = sizeof(sa);
  TRY(getsockname(sock, (struct sockaddr*)&sa, &len));
  snprintf(sock_ip_addr, sizeof(sock_ip_addr), "%s", inet_ntoa(sa.sin_addr));

  getifaddrs(&addrs);
  for( iap = addrs; iap != NULL; iap = iap->ifa_next) {
    if( iap->ifa_addr &&
        iap->ifa_flags & IFF_UP &&
        iap->ifa_addr->sa_family == AF_INET ) {
      struct sockaddr_in* sa = (struct sockaddr_in*)iap->ifa_addr;
      char intf_ip_addr[32];
      inet_ntop(iap->ifa_addr->sa_family, (void *)&(sa->sin_addr), intf_ip_addr,
                sizeof(intf_ip_addr));
      if( ! strcmp(sock_ip_addr, intf_ip_addr) ) {
        TRY(parse_interface(iap->ifa_name, ifindex_out));
        rc = 0;
        goto done;
      }
    }
  }

 done:
  freeifaddrs(addrs);
  return rc;
}


static int ef_vi_init(void)
{
  ef_pd pd;
#ifdef __x86_64__
  ef_pio pio;
#endif
  ef_memreg memreg;
  ef_driver_handle dh;
  enum ef_pd_flags pd_flags = EF_PD_DEFAULT;
  enum ef_vi_flags vi_flags = EF_VI_FLAGS_DEFAULT;
  void* mem;
  int ifindex;
  int i;

  TRY(get_ifindex(tcp_sock, &ifindex));
  TRY(ef_driver_open(&dh));
  TRY(ef_pd_alloc(&pd, dh, ifindex, pd_flags));
  TRY(ef_vi_alloc_from_pd(&vi, dh, &pd, dh, -1, 0, -1, NULL, -1, vi_flags));
#ifdef __x86_64__
  TRY(ef_pio_alloc(&pio, dh, &pd, -1, dh));
  TRY(ef_pio_link_vi(&pio, dh, &vi, dh));
#else
  /* PIO is only available on x86_64 systems */
  TEST(0);
#endif
  TEST(posix_memalign(&mem, 4096, BUF_SIZE * N_BUFS) == 0);
  TRY(ef_memreg_alloc(&memreg, dh, &pd, dh, mem, BUF_SIZE * N_BUFS));

  for( i = 0; i < N_BUFS; ++i ) {
    pkt_bufs[i] = (void*) ((uint8_t*) mem + i * BUF_SIZE);
    pkt_bufs[i]->dma_buf_addr = ef_memreg_dma_addr(&memreg, i * BUF_SIZE) +
      MEMBER_OFFSET(struct pkt_buf, dma_buf);
  }

  return 0;
}


static int my_bind(int sock, int port)
{
  struct sockaddr_in sa;
  bzero(&sa, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  sa.sin_port = htons(port);
  return bind(sock, (struct sockaddr*)&sa, sizeof(sa));
}


static int init(int port)
{
  int lsock;
  int one = 1;

  TRY(udp_sock = socket(AF_INET, SOCK_DGRAM, 0));
  TRY(my_bind(udp_sock, port));

  TRY(lsock = socket(AF_INET, SOCK_STREAM, 0));
  TRY(setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one)));
  TRY(setsockopt(lsock, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(one)));
  TRY(my_bind(lsock, port));
  TRY(listen(lsock, 1));
  TRY(tcp_sock = accept(lsock, NULL, NULL));
  TRY(ef_vi_init());
  return 0;
}


static void usage(void)
{
  fprintf(stderr, "\nusage:\n");
  fprintf(stderr, "efdelegated_server [options] port\n");
  fprintf(stderr, "\noptions:\n");
  fprintf(stderr, "  -w <iterations> - set number of warmup interations\n");
  fprintf(stderr, "  -n <iterations> - set number of iterations\n");
  fprintf(stderr, "  -s <msg-size>   - set payload size\n");
  fprintf(stderr, "  -d              - use delegated sends API to send\n");
  fprintf(stderr, "\n");
  exit(1);
}


int main(int argc, char* argv[])
{
  int port;
  int c;

  while( (c = getopt(argc, argv, "n:s:w:d")) != -1 )
    switch( c ) {
    case 'n':
      cfg_iter = atoi(optarg);
      break;
    case 'w':
      cfg_warm = atoi(optarg);
      break;
    case 's':
      cfg_payload_len = atoi(optarg);
      break;
    case 'd':
      cfg_delegated = 1;
      break;
    case '?':
      usage();
    default:
      TEST(0);
    }

  argc -= optind;
  argv += optind;

  if( argc != 1 )
    usage();
  port = atoi(argv[0]);

  if( cfg_delegated && ! onload_is_present() ) {
    fprintf(stderr, "ERROR: Must run with Onload to use delegated sends\n");
    exit(1);
  }

  TRY(init(port));
  loop();

  return 0;
}

/*! \cidoxg_end */
