/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* trader_tcpdirect_ds_efvi
 *
 * Copyright 2019 Solarflare Communications Inc.
 * Author: Sami Farhat, David Riddoch, Matthew Robinson
 *
 * This is a sample application to demonstrate usage of EF_VI cut-though
 * receive. It also makes use of TCPDirect's "delegated sends" feature.
 * Please read README for details of what this application does and how to run
 * it.
 *
 * It is potentially easier to read trader_tcpdirect_ds_efvi to learn about
 * Delegated Send. This code is focussed on adding the use of EF_VI cut-through
 * receive
 *
 * For this benchmark, a response is sent as soon as a certain number of bytes
 * of payload have been received (default 0)
 * For example using cut-through receive and delegated send, run as follows:
 *
 *   onload -p latency ./exchange <mcast-intf>
 *   ./trader_tcpdirect_ds_efvi_ct_rx -d -u -o 0 -r 1472 <mcast-intf> <server>
 *
 * To compare with conventional receive:
 *
 *   onload -p latency ./exchange <mcast-intf>
 *   ./trader_tcpdirect_ds_efvi_ct_rx -d -C -r 1472 <mcast-intf> <server>
 *
 */

#include "utils.h"
#include "ct_rx.h"

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
#define UDP_HEADER_SIZE       (ETH_HLEN + sizeof(ci_ip4_hdr) + sizeof(ci_udp_hdr))
#define N_RX_BUFS             128u
#define N_TX_BUFS             1u
#define FIRST_TX_BUF          N_RX_BUFS
#define PKT_BUF_SIZE          2048
#define REFILL_BATCH          8

static bool        cfg_delegated;
static int         cfg_rx_size = 300;
static int         cfg_tx_size = 200;
static const char* cfg_port = "8122";
static const char* cfg_mcast_addr = "224.1.2.3";
static int         cfg_ct_rx = 1;
static unsigned    cfg_trigger_offset = 0;
static int         cfg_do_rx_work = 0;
static bool        cfg_unsafe_tx = 0;
static bool        cfg_ctpio_no_poison = 0;
static unsigned    cfg_ctpio_thresh = 64;
static int         cfg_pio_only = 0;

struct pkt_buf {
  ef_addr           dma_addr;
  int               id;
  char              dma_start[1]  EF_VI_ALIGN(EF_VI_DMA_ALIGN);
};


enum poll_state {
  PS_POLL_CUT_THROUGH,
  PS_CUT_THROUGH_IN_PROGRESS,
  PS_POLL_EV
};


struct client_state {
  unsigned                     alarm_usec;
  bool                         alarm;
  struct zf_stack*             stack;
  struct zft*                  tcp_sock;
  int                          udp_sock;
  ef_pd                        pd;
  ef_pio                       pio;
  ef_driver_handle             dh;
  ef_vi                        vi;
  unsigned                     rx_prefix_len;
  char*                        msg_buf;
  int                          msg_len;
  /* pio_pkt_len: Non-zero means that we have a prepared send ready to go. */
  int                          pio_pkt_len;
  bool                         pio_in_use;
  bool                         use_ctpio;
  struct zf_ds                 zfds;
  struct pkt_buf*              pkt_bufs[N_RX_BUFS + N_TX_BUFS];
  ef_memreg                    memreg;
  char                         recv_buf[MTU]; /* for TCP RX */

  /* State. */
  unsigned                     rx_posted;
  unsigned                     rx_completed;

  ef_rx_sentinel_cfg           rx_stnl_cfg;
  ef_rx_sentinel               rx_stnl;
  unsigned                     rx_msg_len;
  unsigned                     rx_msg_consumed;
  const char*                  rx_msg;
  unsigned                     rx_csum;

  unsigned                     n_tx_todo;

  enum poll_state              poll_state;

  /* stats */
  unsigned                     n_normal_sends;
  unsigned                     n_delegated_sends;
  unsigned                     n_ctpio_sends;
  unsigned                     n_fp_give_up;
  unsigned                     n_fp_success;
  unsigned                     n_slow;
  unsigned                     n_rx_err;
};


static int min(int x, int y)
{
  return x < y ? x : y;
}


static inline bool message_interesting(const char* msg, unsigned len)
{
  return len >= 6 && strncmp(msg, "hit me", 6) == 0;
}


static inline const void* rx_frame_start(const struct client_state* cs,
                                         const struct pkt_buf* pb)
{
  return pb->dma_start + cs->rx_prefix_len;
}


static inline bool rx_need_refill(const struct client_state* cs)
{
  return cs->rx_posted - cs->rx_completed < N_RX_BUFS - REFILL_BATCH;
}


static inline void rx_post(struct client_state* cs)
{
  unsigned pb_id = (cs->rx_posted)++ & (N_RX_BUFS - 1);
  struct pkt_buf* pb = cs->pkt_bufs[pb_id];
  ef_rx_sentinel_init_buf(&cs->rx_stnl_cfg, pb->dma_start);
  TRY( ef_vi_receive_init(&cs->vi, pb->dma_addr, pb->id) );
}


static void rx_refill(struct client_state* cs)
{
  assert( rx_need_refill(cs) );
  int i;
  for( i = 0; i < REFILL_BATCH; ++i )
    rx_post(cs);
  ef_vi_receive_push(&cs->vi);
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


/**********************************************************************
 * Below is delegated send code - see trader_tcpdirect_ds_efvi for more
 * details
 **********************************************************************/

static void delegated_prepare(struct client_state* s)
{
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

  int allowed_to_send = min(s->zfds.delegated_wnd, s->zfds.mss);

  if( s->msg_len <= allowed_to_send ) {
    s->pio_pkt_len = s->zfds.headers_len + s->msg_len;
    zf_delegated_send_tcp_update(&(s->zfds), s->msg_len, 1);
    if( s->use_ctpio ) {
      /* for CPTIO we need to fill in the IP and TCP checksums */
      struct ci_ether_hdr* eth =
        ((void*)s->pkt_bufs[FIRST_TX_BUF]->dma_start);
      struct iphdr* ip4 = (void*) ((char*) eth + ETH_HLEN);
      struct tcphdr* tcp = (void*) (ip4 + 1);

      struct iovec local_iov[1];
      const char* payload = ((const char*)tcp) + 4 * tcp->doff;
      local_iov[0].iov_base = (void*)payload;
      local_iov[0].iov_len = s->msg_len;

      ip4->check = ef_ip_checksum(ip4);
      tcp->check = ef_tcp_checksum(ip4, tcp, local_iov, 1);
    }
    else {
      TRY( ef_pio_memcpy(&(s->vi), s->zfds.headers, 0, s->pio_pkt_len) );
    }
  }
  else {
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

  struct iovec iov;
  iov.iov_len  = cs->msg_len;
  iov.iov_base = cs->msg_buf;
  TRY( zf_delegated_send_complete(cs->tcp_sock, &iov, 1, 0) );

  ++(cs->n_delegated_sends);
}


/* call appropriate send method */
static void do_send(struct client_state* cs)
{
  if( cs->pio_pkt_len )
    delegated_send(cs);
  else
    normal_send(cs);
  --(cs->n_tx_todo);
}


static ssize_t zft_recv_single(struct zft* ts, void* buf, size_t len, int flags)
{
  struct iovec iov = { buf, len };
  return zft_recv(ts, &iov, 1, flags);
}


/**********************************************************************/
/* Below is the most interesting bit of code in the app */
/**********************************************************************/

/* Test whether the packet headers are correct */
static inline bool rx_parse(const void* frame_start,
                            const char** msg_out, unsigned* msg_len_out)
{
  const ci_ether_hdr* eth = frame_start;
  if(CI_UNLIKELY( eth->ether_type != ntohs(ETHERTYPE_IP) ))
    goto not_ip;

  const ci_ip4_hdr* ip4 = (void*) (eth + 1);
  if(CI_UNLIKELY( ip4->ip_ihl_version != CI_IP4_IHL_VERSION(20) ))
    goto unexpected_ip_len;

  /* This is guaranteed to be true because we installed a UDP filter. */
  assert( ip4->ip_protocol == IPPROTO_UDP );

  const ci_udp_hdr* udp = (void*) (ip4 + 1);
  unsigned udp_len = ntohs(udp->udp_len_be16);
  if(CI_UNLIKELY( udp_len < sizeof(*udp) ))
    goto bad_udp_len;

  *msg_len_out = udp_len - sizeof(*udp);
  *msg_out = (void*) (udp + 1);
  return true;

 not_ip:
  TEST( 0 );
 unexpected_ip_len:
  TEST( 0 );
 bad_udp_len:
  TEST( 0 );
  return false;
}


/* Consume a chunk of data */
static inline void rx_consume_msg(struct client_state* cs, const char* end)
{
  assert( end <= cs->rx_msg_len + cs->rx_msg );
  const char* start = cs->rx_msg + cs->rx_msg_consumed;
  cs->rx_msg_consumed = end - cs->rx_msg;

  if( cfg_do_rx_work ) {
    while( start < end )
      cs->rx_csum += *(start++);
  }

  if( cfg_unsafe_tx ) {
    /* Warning - we cannot yet be 100% certain that RX packet was good.
     * As a  benchmark, we can choose to respond as soon as we have consumed
     * cfg_trigger_offset bytes of payload.
     * For real apps, only do reversible actions at this stage. Need to wait
     * for RX_EVENT to be sure packet was good.
     */
    if( cs->n_tx_todo && cs->rx_msg_consumed >= cfg_trigger_offset )
      do_send(cs);
  }
}


/* Conventional receive. We already have the entire packet, so can handle it
 * all in one go */
static void rx_slow(struct client_state* cs, const char* frame_start,
                    unsigned frame_len)
{
  TEST( rx_parse(frame_start, &cs->rx_msg, &cs->rx_msg_len) );
  if( message_interesting(cs->rx_msg, cs->rx_msg_len) )
    cs->n_tx_todo = 1;

  cs->rx_msg_consumed = 0;
  if( cs->rx_msg_len > cfg_trigger_offset )
    cs->rx_msg_len = cfg_trigger_offset;

  const char* frame_end = frame_start + frame_len;
  TEST( cs->rx_msg + cs->rx_msg_len <= frame_end );

  rx_consume_msg(cs, cs->rx_msg + cs->rx_msg_len);
  ++(cs->n_slow);
}


/* RX_EVENT has been received for the packet, finish processing it */
static inline void rx_handle_rx_ev(struct client_state* cs, unsigned frame_len)
{
  unsigned pb_id = cs->rx_completed & (N_RX_BUFS - 1);
  struct pkt_buf* pb = cs->pkt_bufs[pb_id];
  const char* frame_start = rx_frame_start(cs, pb);

  switch( cs->poll_state ) {
  case PS_CUT_THROUGH_IN_PROGRESS:
    /* Now we know the frame length, check the message fits. */
    TEST( cs->rx_msg + cs->rx_msg_len <= frame_start + frame_len );
    if( cs->rx_msg_consumed < cs->rx_msg_len )
      /* Finish processing any part of the message not consumed in
       * cut-through mode (because we ran out of sentinels).
       */
      rx_consume_msg(cs, cs->rx_msg + cs->rx_msg_len);
    break;
  default:
    rx_slow(cs, frame_start, frame_len);
    break;
  }

  /* Now safe to send as we can be sure that data was OK.
   * (If we already did an unsafe_tx, then n_tx_todo will have been cleared) */
  if( cs->n_tx_todo && cs->rx_msg_consumed >= cfg_trigger_offset )
    do_send(cs);

  ++(cs->rx_completed);
  cs->poll_state = PS_POLL_EV;
}


/* Cut-through receive. Checks how much data has been DMAed from the NIC and
 * starts processing it as it arrives */
static inline void rx_fast(struct client_state* cs, const void* frame_start)
{
  if(CI_UNLIKELY( ! rx_parse(frame_start, &cs->rx_msg, &cs->rx_msg_len) ))
    goto bad_frame;
  if( message_interesting(cs->rx_msg, cs->rx_msg_len) )
    cs->n_tx_todo = 1;

  cs->poll_state = PS_CUT_THROUGH_IN_PROGRESS;
  cs->rx_msg_consumed = 0;
  if( cs->rx_msg_len > cfg_trigger_offset )
    cs->rx_msg_len = cfg_trigger_offset;

  /* recalculate number of sentinels to check based on actual payload */
  unsigned end_of_msg_off, n_sentinels;
  end_of_msg_off = cs->rx_prefix_len + UDP_HEADER_SIZE + cs->rx_msg_len;
  n_sentinels = (end_of_msg_off + CI_CACHE_LINE_SIZE - 1) / CI_CACHE_LINE_SIZE;
  ef_rx_sentinel_adjust_num(&cs->rx_stnl, &cs->rx_stnl_cfg, n_sentinels);

  const char* msg_end = cs->rx_msg + cs->rx_msg_len;
  const char* msg_ready = ef_rx_sentinel_ready_end(&cs->rx_stnl);
  if( msg_end <= msg_ready ) {
    rx_consume_msg(cs, msg_end);
    ++(cs->n_fp_success);
    return;
  }
  rx_consume_msg(cs, msg_ready);

  while( ! ef_rx_sentinel_is_last(&cs->rx_stnl) ) {
    ef_rx_sentinel_next(&cs->rx_stnl, &cs->rx_stnl_cfg);
    /* max wait needs to be chosen so we don't give up too soon */
    if(CI_LIKELY( ef_rx_sentinel_wait(&cs->rx_stnl,
                                      &cs->rx_stnl_cfg, 1000) )) {
      msg_ready = ef_rx_sentinel_ready_end(&cs->rx_stnl);
      if( msg_end <= msg_ready ) {
        rx_consume_msg(cs, msg_end);
        /* We've got the whole message.  Wait for the event so we know
         * whether the packet is good.
         */
        break;
      }
      rx_consume_msg(cs, msg_ready);
    }
    else {
      /* We've waited long enough for packet data.  Perhaps the packet
       * was truncated, or matched the sentinel?  Give up and wait for
       * an event instead.
       */
      cs->poll_state = PS_POLL_EV;
      ++(cs->n_fp_give_up);
      return;
    }
  }
  /* We've reached the end of our sentinels.  Wait for the event to
   * get the rest of the data.
   */
  ++(cs->n_fp_success);
  return;

 bad_frame:
  TEST( 0 );
}


/* Normal poll of the event queue */
static void poll_evq(struct client_state* cs)
{
  ef_event evs[8];
  const unsigned max_evs = sizeof(evs) / sizeof(evs[0]);
  ef_request_id tx_ids[EF_VI_TRANSMIT_BATCH];
  unsigned frame_len;
  int ev_i, ev_n, n_tx;

  ev_n = ef_eventq_poll(&cs->vi, evs, max_evs);
  if( ev_n == 0 ) {
    /* We're idle, so switch back to cut-through polling.  Also a good time
     * to refill the rx ring.
     */
    if( cs->poll_state == PS_POLL_EV && cfg_ct_rx )
      cs->poll_state = PS_POLL_CUT_THROUGH;
    if( rx_need_refill(cs) )
      rx_refill(cs);
    return;
  }

  for( ev_i = 0; ev_i < ev_n; ++(ev_i) )
    switch( EF_EVENT_TYPE(evs[ev_i]) ) {
    case EF_EVENT_TYPE_RX:
      frame_len = EF_EVENT_RX_BYTES(evs[ev_i]) - cs->rx_prefix_len;
      rx_handle_rx_ev(cs, frame_len);
      break;
    case EF_EVENT_TYPE_TX:
      n_tx = ef_vi_transmit_unbundle(&(cs->vi), &evs[ev_i], tx_ids);
      if( n_tx )
        cs->pio_in_use = false;
      if( EF_EVENT_TX_CTPIO(evs[ev_i]) )
        cs->n_ctpio_sends += n_tx;
      break;
    case EF_EVENT_TYPE_RX_DISCARD:
      if( EF_EVENT_RX_DISCARD_TYPE(evs[ev_i]) ==
          EF_EVENT_RX_DISCARD_CRC_BAD ) {
        /* We assume this is a frame poisoned by a failed CTPIO
         * send, and so a good copy will follow.
         */
        if( cs->poll_state == PS_CUT_THROUGH_IN_PROGRESS ) {
          /* Unwind any side-effects of cut-through processing so far. */
          cs->n_tx_todo = 0;
          cs->poll_state = PS_POLL_EV;
        }
        ++(cs->rx_completed);
        ++(cs->n_rx_err);
        break;
      }
      /* Otherwise, fall through. */
    default:
      fprintf(stderr, "ERROR: unexpected event "EF_EVENT_FMT"\n",
              EF_EVENT_PRI_ARG(evs[ev_i]));
      abort();
      break;
    }
}



/* Poll for a partial packet receive.
 * Checks the packet buffer we expect to be filled next. If the sentinel value
 * changes, this indicates that data has started arriving. After a certain
 * number of cycles, drop back and check the event queue as normal. */
static inline void poll_cut_through(struct client_state* cs)
{
  unsigned pb_id = cs->rx_completed & (N_RX_BUFS - 1);
  struct pkt_buf* pb = cs->pkt_bufs[pb_id];

  ef_rx_sentinel_init(&cs->rx_stnl, &cs->rx_stnl_cfg, pb->dma_start);

  if(CI_LIKELY( ef_rx_sentinel_wait(&cs->rx_stnl, &cs->rx_stnl_cfg, 100) ))
    rx_fast(cs, rx_frame_start(cs, pb));
  else
    poll_evq(cs);
}


/**********************************************************************/


static void ev_loop(struct client_state* cs)
{
  while( 1 ) {
    /* Spend most of our time polling EFVI as this recieves UDP data,
     * so is the latency sensitive path.
     */
    int i;
    for( i = 0; i < 10; ++i )
      if( cs->poll_state == PS_POLL_CUT_THROUGH )
        poll_cut_through(cs);
      else
        poll_evq(cs);

    /* Less often poll TCPDirect to pick-up TX completions, get ready for sends
     * and poll for TCP receives.
     */
    if ( zf_stack_has_pending_work(cs->stack) )
      zf_reactor_perform(cs->stack);
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
  printf("n_fp_success: %u\n", cs->n_fp_success);
  printf("n_fp_give_up: %u\n", cs->n_fp_give_up);
  printf("n_slow: %u\n", cs->n_slow);
  printf("n_rx_err: %u\n", cs->n_rx_err);
  if( cfg_unsafe_tx && cs->n_rx_err )
    printf("WARNING: responses were sent to bad RX packets - timing from this"
           " run will be invalid.\n");
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
                            -1, -1, -1, NULL, -1, vi_flags) == 0 ) {
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
                             -1, -1,-1, NULL, -1, EF_VI_FLAGS_DEFAULT) );
    cs->use_ctpio = 0;
  }
  TRY( ef_pio_alloc(&(cs->pio), cs->dh, &(cs->pd), -1, cs->dh));
  TRY( ef_pio_link_vi(&(cs->pio), cs->dh, &(cs->vi), cs->dh));

  cs->rx_prefix_len = ef_vi_receive_prefix_len(&cs->vi);

  /* Configure cut-through receive.  We choose to consume one cache
   * line at a time, and place enough sentinels to get to offset
   * cfg_trigger_offset within the message.
   */
  unsigned end_of_msg_off, n_sentinels;
  end_of_msg_off = cs->rx_prefix_len + UDP_HEADER_SIZE + cfg_trigger_offset;
  n_sentinels = (end_of_msg_off + CI_CACHE_LINE_SIZE - 1) / CI_CACHE_LINE_SIZE;
  /* Need to pick an initial value for sentinels which is very unlikely to
   * be in the real data (so that the value changes when packet data arrives)
   * Here we use 0x586954c9a81285cd */
  ef_rx_sentinel_cfg_init(&cs->rx_stnl_cfg, 0x586954c9a81285cd,
                          CI_CACHE_LINE_SIZE, CI_CACHE_LINE_SIZE, n_sentinels);

  int bytes = (N_RX_BUFS + N_TX_BUFS) * PKT_BUF_SIZE;
  void* p;
  TEST( posix_memalign(&p, CI_PAGE_SIZE, bytes) == 0 );
  TRY( ef_memreg_alloc(&cs->memreg, cs->dh,
                       &cs->pd, cs->dh, p, bytes) );
  int i;
  for( i = 0; i < (N_RX_BUFS + N_TX_BUFS); ++i ) {
    cs->pkt_bufs[i] = (void*) ((char*) p + i * PKT_BUF_SIZE);
    cs->pkt_bufs[i]->dma_addr =
      ef_memreg_dma_addr(&cs->memreg, i * PKT_BUF_SIZE) +
      offsetof(struct pkt_buf, dma_start);
    cs->pkt_bufs[i]->id = i;
  }
}


static void ef_vi_add_udp_filter(struct client_state* cs)
{
  ef_filter_spec filter_spec;
  struct in_addr ip;
  ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
  TEST( parse_host(cfg_mcast_addr, &ip) );
  TRY( ef_filter_spec_set_ip4_local(&filter_spec, IPPROTO_UDP,
                                    ip.s_addr, htons(atoi(cfg_port))) );
  TRY( ef_vi_filter_add(&(cs->vi), cs->dh, &filter_spec, NULL) );
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
  TRY( zf_attr_set_int(attr, "reactor_spin_count", 1) );
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

  /* initialise stats */
  cs->poll_state = PS_POLL_EV;
  cs->n_fp_success = 0;
  cs->n_fp_give_up = 0;
  cs->n_slow = 0;

  /* Create EFVI VI and add filter for UDP data */
  ef_vi_init(cs, interface);

  cs->n_tx_todo = 0;
  cs->rx_posted = 0;
  cs->rx_completed = 0;
  while( rx_need_refill(cs) )
    rx_refill(cs);

  ef_vi_add_udp_filter(cs);

  /* Create UDP backing socket, bind, join multicast group. */
  TRY( cs->udp_sock = mk_socket(0, SOCK_DGRAM, bind,
                                cfg_mcast_addr, cfg_port) );
  if( interface != NULL ) {
    struct ip_mreqn mreqn;
    TEST( inet_aton(cfg_mcast_addr, &mreqn.imr_multiaddr) );
    mreqn.imr_address.s_addr = htonl(INADDR_ANY);
    TEST( (mreqn.imr_ifindex = if_nametoindex(interface)) != 0 );
    TRY( setsockopt(cs->udp_sock, SOL_IP, IP_ADD_MEMBERSHIP,
                    &mreqn, sizeof(mreqn)) );
  }

  /* setup for TX */
  cs->msg_len = cfg_tx_size;
  cs->msg_buf = cs->pkt_bufs[FIRST_TX_BUF]->dma_start + MAX_ETH_HEADERS +
    MAX_IP_TCP_HEADERS;
}


static void usage_msg(FILE* f)
{
  fprintf(f, "\nusage:\n");
  fprintf(f, "  trader_tcpdirect_ds_efvi_ct_rx [options] <interface> <server>\n");
  fprintf(f, "\noptions:\n");
  fprintf(f, "  -h                - print usage info\n");
  fprintf(f, "  -d                - use delegated sends API to send\n");
  fprintf(f, "  -s <msg-size>     - TX (TCP) message size\n");
  fprintf(f, "  -r <msg-size>     - RX (UDP) message size\n");
  fprintf(f, "  -p <port>         - set TCP/UDP port number\n");
  fprintf(f, "  -o BYTES          - number of bytes which must be read before"
          "sending response\n");
  fprintf(f, "  -C                - disable cut-through receive\n");
  fprintf(f, "  -u                - unsafe send - allow send before checksum "
          "has been checked\n");
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

  while( (c = getopt(argc, argv, "hs:r:dp:o:Cuc:nP")) != -1 )
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
    case 'o':
      cfg_trigger_offset = atoi(optarg);
      break;
    case 'C':
      cfg_ct_rx = 0;
      break;
    case 'u':
      cfg_unsafe_tx = 1;
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
  cfg_trigger_offset = min(cfg_trigger_offset, cfg_rx_size);

  struct client_state* cs = calloc(1, sizeof(*cs));
  init(cs, interface, server, cfg_port);
  pthread_t tid;
  TEST( pthread_create(&tid, NULL, alarm_thread, cs) == 0 );
  ev_loop(cs);
  return 0;
}

/*! \cidoxg_end */
