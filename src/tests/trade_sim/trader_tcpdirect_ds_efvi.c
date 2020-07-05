/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* trader_tcpdirect_ds_efvi
 *
 * Copyright 2018-19 Solarflare Communications Inc.
 * Author: Sami Farhat, David Riddoch, Matthew Robinson
 *
 * This is a sample application to demonstrate usage of TCPDirect's
 * "delegated sends" feature.  Please read README for details of what this
 * application does and how to run it.
 *
 * The delegated sends API allows applications to take over the send
 * critical path for TCP sockets, whilst continuing to use TCPDirect to
 * manage most of the complexity of TCP.  This sample application uses the
 * ef_vi layer-2 API in order to get even lower latency than is possible
 * with a zft_send() call.
 *
 * The API essentially boils down to first retriving the packet headers,
 * adding your own payload to form a raw packet, sending the packet and
 * finally telling Onload what it was you sent so it can update the
 * internal TCP state of the socket.
 *
 * For normal socket-based sends, run as follows:
 *
 *   onload -p latency-best ./exchange <mcast-intf>
 *   ./trader_tcpdirect_ds_efvi <mcast-intf> <server>
 *
 * For "delegated" sends, run as follows:
 *
 *   onload -p latency-best ./exchange <mcast-intf>
 *   ./trader_tcpdirect_ds_efvi -d <mcast-intf> <server>
 */

#include "utils.h"

#include <zf/zf.h>
#include <etherfabric/vi.h>
#include <etherfabric/pio.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/capabilities.h>
#include <etherfabric/checksum.h>
#include <ci/tools.h>
#include <ci/tools/ippacket.h>

#include <stddef.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <netdb.h>
#include <pthread.h>


#define MTU                   1500
#define MAX_ETH_HEADERS       (14/*ETH*/ + 4/*802.1Q*/)
#define MAX_IP_TCP_HEADERS    (20/*IP*/ + 20/*TCP*/ + 12/*TCP options*/)
#define MAX_PACKET            (MTU + MAX_ETH_HEADERS)
#define MAX_MESSAGE           (MTU - MAX_IP_TCP_HEADERS)
#define N_TX_BUFS             1u
#define FIRST_TX_BUF          0u
#define PKT_BUF_SIZE          2048


static bool        cfg_delegated;
static int         cfg_rx_size = 300;
static int         cfg_tx_size = 200;
static const char* cfg_port = "8122";
static const char* cfg_mcast_addr = "224.1.2.3";
static bool        cfg_ctpio_no_poison = 0;
static unsigned    cfg_ctpio_thresh = 64;
static bool        cfg_pio_only = 0;

struct pkt_buf {
  ef_addr           dma_addr;
  int               id;
  char              dma_start[1]  EF_VI_ALIGN(EF_VI_DMA_ALIGN);
};


struct client_state {
  unsigned                     alarm_usec;
  bool                         alarm;
  struct zf_stack*             stack;
  struct zft*                  tcp_sock;
  struct zfur*                 udp_sock;
  ef_pd                        pd;
  ef_pio                       pio;
  ef_driver_handle             dh;
  ef_vi                        vi;
  char*                        msg_buf;
  int                          msg_len;
  /* pio_pkt_len: Non-zero means that we have a prepared send ready to go. */
  int                          pio_pkt_len;
  bool                         pio_in_use;
  bool                         use_ctpio;
  struct zf_ds                 zfds;
  struct pkt_buf*              pkt_bufs[N_TX_BUFS];
  ef_memreg                    memreg;
  char                         recv_buf[MTU];
  unsigned                     n_normal_sends;
  unsigned                     n_delegated_sends;
  unsigned                     n_ctpio_sends;
};


static int min(int x, int y)
{
  return x < y ? x : y;
}


static void evq_poll(struct client_state* cs)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event      evs[EF_VI_EVENT_POLL_MIN_EVS];
  int           n_ev, i, n_tx;

  n_ev = ef_eventq_poll(&(cs->vi), evs, sizeof(evs) / sizeof(evs[0]));
  for( i = 0; i < n_ev; ++i )
    switch( EF_EVENT_TYPE(evs[i]) ) {
    case EF_EVENT_TYPE_TX:
      if( (n_tx = ef_vi_transmit_unbundle(&(cs->vi), &evs[i], ids)) )
        cs->pio_in_use = false;
      if( EF_EVENT_TX_CTPIO(evs[i]) )
        cs->n_ctpio_sends += n_tx;
      break;
    default:
      fprintf(stderr, "ERROR: unexpected event "EF_EVENT_FMT"\n",
              EF_EVENT_PRI_ARG(evs[i]));
      TEST(0);
      break;
    }
}


static int poll_udp_rx(struct client_state* cs)
{
  struct {
    /* The iovec used by zfur_msg must be immediately afterwards */
    struct zfur_msg msg;
    struct iovec iov[1];
  } msg;

  zf_reactor_perform(cs->stack);
  msg.msg.iovcnt = 1;
  zfur_zc_recv(cs->udp_sock, &(msg.msg), 0);
  if( msg.msg.iovcnt == 0 )
    return -1;

  int is_hit_me = msg.iov[0].iov_len >= 6 &&
                  strncmp(msg.iov[0].iov_base, "hit me", 6) == 0;
  zfur_zc_recv_done(cs->udp_sock, &(msg.msg));

  return is_hit_me;
}


static void normal_send(struct client_state* cs)
{
  if( cs->zfds.delegated_wnd ) {
    TRY( zf_delegated_send_cancel(cs->tcp_sock) );
    cs->zfds.delegated_wnd = 0;
  }

  ssize_t rc = zft_send_single(cs->tcp_sock, cs->msg_buf, cs->msg_len, 0);
  if( rc != cs->msg_len )
    fprintf(stderr, "zft_send_single: len=%d rc=%zd pio_in_use=%d\n",
            cs->msg_len, rc, cs->pio_in_use);
  TEST( rc == cs->msg_len );
  ++(cs->n_normal_sends);
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
 * This function can be called speculatively.  If later on you decide that
 * you don't want to do a delegated send, you can call
 * zf_delegated_send_cancel().
 */
static void delegated_prepare(struct client_state* s)
{
  /* Prepare to do a delegated send: Tell the stack how much data we might
   * send, and retrieve the current packet headers.  In this sample
   * application we always send a message of length s->msg_len, but we pass
   * a larger value to zf_delegated_send_prepare() just to show that this
   * is supported.
   */
  s->zfds.headers = s->pkt_bufs[FIRST_TX_BUF]->dma_start;
  s->zfds.headers_size = MAX_ETH_HEADERS + MAX_IP_TCP_HEADERS;
  enum zf_delegated_send_rc rc;
  rc = zf_delegated_send_prepare(s->tcp_sock, s->msg_len * 2, 0, 0, &(s->zfds));
  if( rc != ZF_DELEGATED_SEND_RC_OK ) {
    fprintf(stderr, "ERROR: zf_delegated_send_prepare: rc=%d\n", (int) rc);
    exit(3);
  }

  /* Update the payload start location to directly after the headers */
  s->msg_buf = s->pkt_bufs[FIRST_TX_BUF]->dma_start + s->zfds.headers_len;

  /* If we want to send more than MSS (maximum segment size), we will have
   * to segment the message into multiple packets.  We do not handle that
   * case in this demo app.
   */
  int allowed_to_send = min(s->zfds.delegated_wnd, s->zfds.mss);

  if( s->msg_len <= allowed_to_send ) {
    s->pio_pkt_len = s->zfds.headers_len + s->msg_len;
    zf_delegated_send_tcp_update(&(s->zfds), s->msg_len, 1);
    if( s->use_ctpio ) {
      /* for CPTIO we need to fill in the IP and TCP checksums */
      struct ci_ether_hdr* eth =
        ((void*)s->pkt_bufs[FIRST_TX_BUF]->dma_start);
      struct iphdr* ip4 = (void*) ((char*) eth + 14);
      struct tcphdr* tcp = (void*) (ip4 + 1);

      struct iovec local_iov;
      local_iov.iov_base = s->msg_buf;
      local_iov.iov_len = s->msg_len;

      ip4->check = ef_ip_checksum(ip4);
      tcp->check = ef_tcp_checksum(ip4, tcp, &local_iov, 1);
    }
    else {
      TRY( ef_pio_memcpy(&(s->vi), s->zfds.headers, 0, s->pio_pkt_len) );
    }
  }
  else {
    /* We can't do a delegated send at the moment, due to congestion window
     * or receive window being closed, or message size being larger than
     * the MSS.  Cancel the delegated send and use normal send instead.
     */
    TRY( zf_delegated_send_cancel(s->tcp_sock) );
    s->zfds.delegated_wnd = 0;
    s->pio_pkt_len = 0;
  }
}


static void delegated_send(struct client_state* cs)
{
  /* Fast path send: */
  if( cs->use_ctpio ) {
    struct pkt_buf* pb = cs->pkt_bufs[FIRST_TX_BUF];
    ef_vi_transmit_ctpio(&cs->vi, pb->dma_start, cs->pio_pkt_len, cfg_ctpio_thresh);
    TRY(ef_vi_transmit_ctpio_fallback(&cs->vi, pb->dma_addr, cs->pio_pkt_len, 0));
  }
  else {
    TRY( ef_vi_transmit_pio(&(cs->vi), 0, cs->pio_pkt_len, 0) );
  }
  cs->pio_pkt_len = 0;
  cs->pio_in_use = 1;

  /* Now tell TCPDirect what we've sent.  It needs to know so that it can
   * update internal state (eg. sequence numbers) and take a copy of the
   * payload sent so that it can be retransmitted if needed.
   *
   * NB. This does not have to happen immediately after the delegated send
   * (and is not part of the critical path) but should be done soon after.
   */
  struct iovec iov;
  iov.iov_len  = cs->msg_len;
  iov.iov_base = cs->msg_buf;
  TRY( zf_delegated_send_complete(cs->tcp_sock, &iov, 1, 0) );

  ++(cs->n_delegated_sends);
}


static ssize_t zft_recv_single(struct zft* ts, void* buf, size_t len, int flags)
{
  struct iovec iov = { buf, len };
  return zft_recv(ts, &iov, 1, flags);
}


static void ev_loop(struct client_state* cs)
{
  while( 1 ) {
    /* Spend most of our time polling the UDP socket, since that is the
     * latency sensitive path.
     */
    int i;
    for( i = 0; i < 10; ++i )
      if( poll_udp_rx(cs) > 0 ) {
        if( cs->pio_pkt_len )
          delegated_send(cs);
        else
          normal_send(cs);
      }

    /* Less often poll ef_vi to pick-up TX completions, get ready for sends
     * and poll for TCP receives.
     */
    evq_poll(cs);
    if( ! cs->pio_in_use && (cs->alarm || ! cs->pio_pkt_len) ) {
      /* Get ready for the next delegated send (or refresh headers)... */
      delegated_prepare(cs);
      cs->alarm = false;
    }
    if( zft_recv_single(cs->tcp_sock, cs->recv_buf,
                        sizeof(cs->recv_buf), 0) == 0 )
      break;
  }

  if( cs->pio_pkt_len )
    TRY( zf_delegated_send_cancel(cs->tcp_sock) );
  zft_free(cs->tcp_sock);

  printf("n_normal_sends: %u\n", cs->n_normal_sends);
  printf("n_delegated_sends: %u (ctpio=%u)\n", cs->n_delegated_sends,
         cs->n_ctpio_sends);
}


/**********************************************************************
 * The alarm thread just sets a flag periodically to remind the event loop
 * to refresh the headers.
 *
 * (In a real application you would want this thread to run on a junk
 * core).
 */

static void* alarm_thread(void* arg)
{
  struct client_state* cs = (void*) arg;
  while( 1 ) {
    usleep(cs->alarm_usec);
    cs->alarm = true;
  }
  return NULL;
}


/**********************************************************************
 * Initialisation code follows...
 */

static void zock_put_int(struct zft* ts, int i)
{
  i = htonl(i);
  TEST( zft_send_single(ts, &i, sizeof(i), 0) == sizeof(i) );
}


static void ef_vi_init(struct client_state* cs, const char* interface)
{
  unsigned long capability_val;
  int ifindex;
  enum ef_vi_flags vi_flags = EF_VI_TX_CTPIO;
  if( cfg_ctpio_no_poison )
    vi_flags |= EF_VI_TX_CTPIO_NO_POISON;

  cs->pio_pkt_len = 0;
  cs->pio_in_use = ! cfg_delegated;
  TRY( ef_driver_open(&(cs->dh)) );
  TRY( ef_pd_alloc_by_name(&(cs->pd), cs->dh, interface, EF_PD_DEFAULT) );

  /* If NIC supports CTPIO use it */
  TEST( parse_interface(interface, &ifindex) );
  if( ! cfg_pio_only &&
      ef_vi_capabilities_get(cs->dh, ifindex, EF_VI_CAP_CTPIO,
                             &capability_val) == 0 && capability_val ) {
    if( ef_vi_alloc_from_pd(&(cs->vi), cs->dh, &(cs->pd), cs->dh,
                            -1, 0, -1, NULL, -1, vi_flags) == 0 ) {
      cs->use_ctpio = 1;
      fprintf(stderr, "Using VI with CTPIO.\n");
    }
    else {
      fprintf(stderr, "Failed to allocate VI with CTPIO.\n");
      TEST(0);
    }
  }
  else {
    TRY( ef_vi_alloc_from_pd(&(cs->vi), cs->dh, &(cs->pd), cs->dh,
                             -1, 0, -1, NULL, -1, EF_VI_FLAGS_DEFAULT) );
    cs->use_ctpio = 0;
  }

  TRY( ef_pio_alloc(&(cs->pio), cs->dh, &(cs->pd), -1, cs->dh));
  TRY( ef_pio_link_vi(&(cs->pio), cs->dh, &(cs->vi), cs->dh));

  int bytes = N_TX_BUFS * PKT_BUF_SIZE;
  void* p;
  TEST( posix_memalign(&p, CI_PAGE_SIZE, bytes) == 0 );
  TRY( ef_memreg_alloc(&cs->memreg, cs->dh,
                       &cs->pd, cs->dh, p, bytes) );
  int i;
  for( i = 0; i < N_TX_BUFS; ++i ) {
    cs->pkt_bufs[i] = (void*) ((char*) p + i * PKT_BUF_SIZE);
    cs->pkt_bufs[i]->dma_addr =
      ef_memreg_dma_addr(&cs->memreg, i * PKT_BUF_SIZE) +
      offsetof(struct pkt_buf, dma_start);
    cs->pkt_bufs[i]->id = i;
  }
}


static void init(struct client_state* cs, const char* interface,
                 const char* server, const char* port)
{
  cs->alarm = false;
  cs->alarm_usec = 20000;

  TRY( zf_init() );
  struct zf_attr* attr;
  TRY( zf_attr_alloc(&attr) );
  TRY( zf_attr_set_str(attr, "interface", interface) );
  TRY( zf_attr_set_str(attr, "ctpio_mode", "ct") );
  TRY( zf_stack_alloc(attr, &(cs->stack)) );

  struct addrinfo hints, *ai;
  memset(&hints, 0, sizeof(hints));
  int rc = getaddrinfo(server, port, &hints, &ai);
  if( rc != 0 ) {
    fprintf(stderr, "ERROR: failed to lookup address '%s:%s': %s\n",
            server, port, gai_strerror(rc));
    exit(2);
  }

  /* Create TCP socket, connect to server, give it configuration. */
  struct zft_handle* tcp_handle;
  TRY( zft_alloc(cs->stack, attr, &tcp_handle) );
  TRY( zft_connect(tcp_handle, ai->ai_addr, ai->ai_addrlen,
                      &(cs->tcp_sock)) );
  freeaddrinfo(ai);
  while( zft_state(cs->tcp_sock) == TCP_SYN_SENT )
    zf_reactor_perform(cs->stack);
  TEST( zft_state(cs->tcp_sock) == TCP_ESTABLISHED );
  zock_put_int(cs->tcp_sock, cfg_tx_size);
  zock_put_int(cs->tcp_sock, cfg_rx_size);

  /* Create UDP socket, bind, join multicast group. */
  rc = getaddrinfo(cfg_mcast_addr, cfg_port, &hints, &ai);
  if( rc != 0 ) {
    fprintf(stderr, "ERROR: failed to lookup address '%s:%s': %s\n",
            cfg_mcast_addr, cfg_port, gai_strerror(rc));
    exit(2);
  }
  TRY( zfur_alloc(&cs->udp_sock, cs->stack, attr) );
  TRY( zfur_addr_bind(cs->udp_sock, ai->ai_addr, ai->ai_addrlen,
                         NULL, 0, 0) );
  freeaddrinfo(ai);

  ef_vi_init(cs, interface);

  cs->msg_len = cfg_tx_size;
  cs->msg_buf = cs->pkt_bufs[FIRST_TX_BUF]->dma_start + MAX_ETH_HEADERS +
    MAX_IP_TCP_HEADERS;
}


static void usage_msg(FILE* f)
{
  fprintf(f, "\nusage:\n");
  fprintf(f, "  trader_tcpdirect_ds_efvi [options] <interface> <server>\n");
  fprintf(f, "\noptions:\n");
  fprintf(f, "  -h                - print usage info\n");
  fprintf(f, "  -d                - use delegated sends API to send\n");
  fprintf(f, "  -s <msg-size>     - TX (TCP) message size\n");
  fprintf(f, "  -r <msg-size>     - RX (UDP) message size\n");
  fprintf(f, "  -p <port>         - set TCP/UDP port number\n");
  fprintf(f, "  -c <threshold>    - CTPIO cut-through threshold\n");
  fprintf(f, "  -n                - CTPIO no-poison mode\n");
  fprintf(f, "  -P                - use PIO (rather than CTPIO)\n");
  fprintf(f, "\n");
}


static void usage_err(void)
{
  usage_msg(stderr);
  exit(1);
}


int main(int argc, char* argv[])
{
  int c;

  while( (c = getopt(argc, argv, "hs:r:dp:c:nP")) != -1 )
    switch( c ) {
    case 'h':
      usage_msg(stdout);
      exit(0);
      break;
    case 'd':
      cfg_delegated = 1;
      break;
    case 's':
      cfg_tx_size = atoi(optarg);
      break;
    case 'r':
      cfg_rx_size = atoi(optarg);
      break;
    case 'p':
      cfg_port = optarg;
      break;
    case 'c':
      cfg_ctpio_thresh = atoi(optarg);
      break;
    case 'n':
      cfg_ctpio_no_poison = 1;
      break;
    case 'P':
      cfg_pio_only = 1;
      break;
    case '?':
      usage_err();
      break;
    default:
      TEST(0);
      break;
    }
  argc -= optind;
  argv += optind;
  if( argc != 2 )
    usage_err();
  const char* interface = argv[0];
  const char* server = argv[1];

  struct client_state* cs = calloc(1, sizeof(*cs));
  init(cs, interface, server, cfg_port);
  pthread_t tid;
  TEST( pthread_create(&tid, NULL, alarm_thread, cs) == 0 );
  ev_loop(cs);
  return 0;
}

/*! \cidoxg_end */
