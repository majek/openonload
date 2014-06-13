/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
** Copyright 2005-2014  Solarflare Communications Inc.
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


/* eftap
 *
 * Sample app that sends UDP packets on a specified interface.
 *
 * The application sends a UDP packet, waits for transmission of the
 * packet to finish and then sends the next.
 *
 * The number of packets sent, the size of the packet, the amount of
 * time to wait between sends can be controlled.  The time the packet
 * was actually transmitted can also be requested.
 *
 * 2014 Solarflare Communications Inc.
 * Author: Akhi Singhania
 * Date: 2014/02/17
 */


#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <ci/tools.h>
#include <ci/tools/ippacket.h>
#include <ci/net/ipv4.h>

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>
#include <netdb.h>
#include <ifaddrs.h>


#define TEST(x)                                                 \
  do {                                                          \
    if( ! (x) ) {                                               \
      fprintf(stderr, "ERROR: '%s' failed\n", #x);              \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )


#define TRY(x)                                                  \
  do {                                                          \
    int __rc = (x);                                             \
    if( __rc < 0 ) {                                            \
      fprintf(stderr, "ERROR: '%s' failed\n", #x);              \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",           \
              __rc, errno, strerror(errno));                    \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )


#define MAX_UDP_PAYLEN	(1500 - sizeof(ci_ip4_hdr) - sizeof(ci_udp_hdr))
#define N_BUFS          1
#define BUF_SIZE        2048

/* This gives a frame len of 70, which is the same as:
**   eth + ip + tcp + tso + 4 bytes payload
*/
#define DEFAULT_PAYLOAD_SIZE  28
#define CACHE_ALIGN           __attribute__((aligned(EF_VI_DMA_ALIGN)))
#define LOCAL_PORT            12345

static uint8_t mcast_mac[6];
static ef_vi vi;
static ef_driver_handle dh;
static struct sockaddr_in sa_local, sa_mcast;
static struct pkt_buf* pb;
static int tx_frame_len;
static int cfg_timestamping;
static int cfg_local_port = LOCAL_PORT;
static int n_sent;

#define MEMBER_OFFSET(c_type, mbr_name)  \
  ((uint32_t) (uintptr_t)(&((c_type*)0)->mbr_name))


struct pkt_buf {
  ef_addr         dma_buf_addr;
  uint8_t         dma_buf[1] CACHE_ALIGN;
};


/* The memory for ipaddr_out is allocated by this function and must be
 * freed using free(). */
static void get_ipaddr_of_intf(const char* intf, char** ipaddr_out)
{
  struct ifaddrs *ifaddrs, *ifa;
  char* ipaddr = calloc(NI_MAXHOST, sizeof(char));
  TEST(ipaddr);
  TRY(getifaddrs(&ifaddrs));
  for( ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next ) {
    if( ifa->ifa_addr == NULL )
      continue;
    if( strcmp(ifa->ifa_name, intf) != 0 )
      continue;
    if( ifa->ifa_addr->sa_family != AF_INET )
      continue;
    TRY(getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), ipaddr,
                    NI_MAXHOST, NULL, 0, NI_NUMERICHOST));
    break;
  }
  freeifaddrs(ifaddrs);
  *ipaddr_out = ipaddr;
}


static int my_getaddrinfo(const char* host, const char* port,
                          struct addrinfo**ai_out)
{
  struct addrinfo hints;
  hints.ai_flags = 0;
  hints.ai_family = AF_INET;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;
  return getaddrinfo(host, port, &hints, ai_out);
}


static int parse_host(const char* s, struct in_addr* ip_out)
{
  const struct sockaddr_in* sin;
  struct addrinfo* ai;
  if( my_getaddrinfo(s, 0, &ai) < 0 )
    return 0;
  sin = (const struct sockaddr_in*) ai->ai_addr;
  *ip_out = sin->sin_addr;
  return 1;
}


static int parse_interface(const char* s, int* ifindex_out)
{
  char dummy;
  if( (*ifindex_out = if_nametoindex(s)) == 0 )
    if( sscanf(s, "%d%c", ifindex_out, &dummy) != 1 )
      return 0;
  return 1;
}


static int init_udp_pkt(void* pkt_buf, int paylen)
{
  int ip_len = sizeof(ci_ip4_hdr) + sizeof(ci_udp_hdr) + paylen;
  ci_ether_hdr* eth;
  ci_ip4_hdr* ip4;
  ci_udp_hdr* udp;

  eth = pkt_buf;
  ip4 = (void*) ((char*) eth + 14);
  udp = (void*) (ip4 + 1);

  memcpy(eth->ether_dhost, mcast_mac, 6);
  ef_vi_get_mac(&vi, dh, eth->ether_shost);
  eth->ether_type = htons(0x0800);
  ci_ip4_hdr_init(ip4, CI_NO_OPTS, ip_len, 0, IPPROTO_UDP,
		  sa_local.sin_addr.s_addr,
		  sa_mcast.sin_addr.s_addr, 0);
  ci_udp_hdr_init(udp, ip4, sa_local.sin_port,
		  sa_mcast.sin_port, udp + 1, paylen, 0);

  return ETH_HLEN + ip_len;
}


static void send_pkt(void)
{
  TRY(ef_vi_transmit(&vi, pb->dma_buf_addr, tx_frame_len, n_sent));
}


static int wait_for_some_completions(void)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event      evs[EF_VI_EVENT_POLL_MIN_EVS];
  int           n_ev, i, n_unbundled = 0;
  struct timespec ts;

  while( 1 ) {
    n_ev = ef_eventq_poll(&vi, evs, sizeof(evs) / sizeof(evs[0]));
    if( n_ev > 0 )
      for( i = 0; i < n_ev; ++i )
        switch( EF_EVENT_TYPE(evs[i]) ) {
        case EF_EVENT_TYPE_TX:
          /* We will only see these events if timestamping was not
           * requested. */
          assert(cfg_timestamping == 0);
          /* One TX event can signal completion of multiple TXs */
          n_unbundled += ef_vi_transmit_unbundle(&vi, &evs[i], ids);
          /* We only ever have one packet in flight */
          assert(n_unbundled == 1);
          TEST(ids[0] == n_sent);
          ++n_sent;
          break;
        case EF_EVENT_TYPE_TX_WITH_TIMESTAMP:
          /* We will only see these events if timestamping was
           * requested. */
          assert(cfg_timestamping == 1);
          /* One TX event can signal completion of of just one TX.  So
           * there is no need to call ef_vi_transmit_unbundle().
           */
          ++n_unbundled;
          TEST(EF_EVENT_TX_WITH_TIMESTAMP_RQ_ID(evs[i]) == n_sent);
          ++n_sent;
          ts.tv_nsec = EF_EVENT_TX_WITH_TIMESTAMP_NSEC(evs[i]);
          ts.tv_sec = EF_EVENT_TX_WITH_TIMESTAMP_SEC(evs[i]);
          printf("eftap: timestamp event %ld.%ld sync %d\n",
                 ts.tv_sec, ts.tv_nsec,
                 EF_EVENT_TX_WITH_TIMESTAMP_SYNC_FLAGS(evs[i]));
          break;
        default:
          TEST(0);
        }
    if( n_unbundled > 0 )
      return n_unbundled;
  }
}


static void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  eftap [options] <interface> <mcast-ip> <mcast-port>\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "positionals:\n");
  fprintf(stderr, " <interface>     local interface for sends and receives\n");
  fprintf(stderr, " <mcast-ip>      multicast ip address to send packets to\n");
  fprintf(stderr, " <mcast-port>    multicast port to send packets to\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -n <iterations>     - number of packets to send\n");
  fprintf(stderr, "  -p <message-size>   - set udp payload size\n");
  fprintf(stderr, "  -s <microseconds>   - time to sleep between sends\n");
  fprintf(stderr, "  -l <local-port>     - Change local port to send from\n");
  fprintf(stderr, "  -t                  - request time packet hit wire\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "e.g.:\n");
  fprintf(stderr, "  - Send pkts to 239.1.2.3:1234 from eth2:\n"
          "          eftap eth2 239.1.2.3 1234\n");
  fprintf(stderr, "  - Additionally request TX timestamping:\n"
          "          eftap -t eth2 239.1.2.3 1234\n");
  exit(1);
}


#define CL_CHK(x)                               \
  do{                                           \
    if( ! (x) )                                 \
      usage();                                  \
  }while(0)


int main(int argc, char* argv[])
{
  const char *interface, *mcast_ip;
  char* local_ip;
  ef_pd pd;
  ef_memreg mr;
  int ifindex, mcast_port;
  int cfg_payload_len = DEFAULT_PAYLOAD_SIZE, cfg_iter = 10,
    cfg_usleep = 0;
  int i, c;
  void* p;

  while( (c = getopt(argc, argv, "n:p:s:l:t")) != -1 )
    switch( c ) {
    case 'n':
      cfg_iter = atoi(optarg);
      break;
    case 'p':
      cfg_payload_len = atoi(optarg);
      break;
    case 'l':
      cfg_local_port = atoi(optarg);
      break;
    case 's':
      cfg_usleep = atoi(optarg);
      break;
    case 't':
      cfg_timestamping = 1;
      break;
    case '?':
      usage();
    default:
      TEST(0);
    }

  argc -= optind;
  argv += optind;
  if( argc != 3 )
    usage();

  interface = argv[0];
  argc -= 1;
  argv += 1;
  mcast_ip = argv[0];
  argc -= 1;
  argv += 1;
  mcast_port = atoi(argv[0]);

  get_ipaddr_of_intf(interface, &local_ip);
  CL_CHK(parse_interface(interface, &ifindex));
  CL_CHK(parse_host(local_ip, &sa_local.sin_addr));
  sa_local.sin_port = htons(cfg_local_port);
  CL_CHK(parse_host(mcast_ip, &sa_mcast.sin_addr));
  sa_mcast.sin_port = htons(mcast_port);

  mcast_mac[0] = 0x1;
  mcast_mac[1] = 0;
  mcast_mac[2] = 0x5e;
  mcast_mac[3] = 0x7f & (sa_mcast.sin_addr.s_addr >> 8);
  mcast_mac[4] = 0xff & (sa_mcast.sin_addr.s_addr >> 16);
  mcast_mac[5] = 0xff & (sa_mcast.sin_addr.s_addr >> 24);

  if( cfg_payload_len > MAX_UDP_PAYLEN ) {
    fprintf(stderr, "WARNING: UDP payload length %d is larged than standard "
            "MTU\n", cfg_payload_len);
  }

  TRY(ef_driver_open(&dh));
  TRY(ef_pd_alloc(&pd, dh, ifindex, 0));
  TRY(ef_vi_alloc_from_pd(&vi, dh, &pd, dh, -1, -1, -1, NULL, -1,
                          cfg_timestamping ? EF_VI_TX_TIMESTAMPS :
                          EF_VI_FLAGS_DEFAULT));

  printf("txq_size=%d\n", ef_vi_transmit_capacity(&vi));
  printf("rxq_size=%d\n", ef_vi_receive_capacity(&vi));
  printf("evq_size=%d\n", ef_eventq_capacity(&vi));
  printf("sync_check_enabled=%d\n",
         (vi.vi_out_flags & EF_VI_OUT_CLOCK_SYNC_STATUS) != 0);

  TEST(posix_memalign(&p, CI_PAGE_SIZE, BUF_SIZE) == 0);
  TRY(ef_memreg_alloc(&mr, dh, &pd, dh, p, BUF_SIZE));
  pb = (void*)p;
  pb->dma_buf_addr = ef_memreg_dma_addr(&mr, 0) +
    MEMBER_OFFSET(struct pkt_buf, dma_buf);
  tx_frame_len = init_udp_pkt(pb->dma_buf, cfg_payload_len);

  for( i = 0; i < cfg_iter; ++i ) {
    send_pkt();
    wait_for_some_completions();
    if( cfg_usleep )
      usleep(cfg_usleep);
  }

  printf("Sent %d packets\n", cfg_iter);
  return 0;
}
