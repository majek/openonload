/*
** Copyright 2005-2018  Solarflare Communications Inc.
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

#include "rtt.h"

#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/pio.h>
#include <etherfabric/memreg.h>
#include <etherfabric/ef_vi.h>

#include <stdbool.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#define BUF_SIZE    2048
#define N_TX_ALT    2


struct pkt_buf {
  ef_addr           dma_addr;
  uint8_t           payload[1] EF_VI_ALIGN(EF_VI_DMA_ALIGN);
};


struct tx_alt {
  bool                 busy;
};


struct vi {
  ef_driver_handle     dh;
  ef_vi		       vi;
  ef_pd                pd;
  ef_memreg            memreg;
  ef_pio               pio;
  uint8_t*             bufs;
  unsigned             num_bufs;
  unsigned             posted;
  unsigned             completed;
};


struct efvi_endpoint {
  struct rtt_endpoint  ep;
  bool                 mcast;

  struct vi            tx;
  struct vi            rx;

  void*                tx_buf;
  int                  tx_len;
  ef_addr              tx_dma_addr;
  struct tx_alt        tx_alt[N_TX_ALT];
  unsigned             tx_alt_prep;
  unsigned             tx_alt_send;
};


#define PKT_BUF(vi, id)  ((struct pkt_buf*) ((vi)->bufs + (id) * BUF_SIZE))


#define EFVI_ENDPOINT(pep)                      \
  CONTAINER_OF(struct efvi_endpoint, ep, (pep))


static const char* local_ip = "192.168.0.1";
static const char* dest_ip_uc = "192.168.0.2";
static const char* dest_ip_mc = "224.1.2.3";
static int udp_port = 8080;


static const char* dest_ip(bool mcast)
{
  if( mcast )
    return dest_ip_mc;
  else
    return dest_ip_uc;
}


static void poll_tx_completions(struct vi* tx)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event evs[EF_VI_EVENT_POLL_MIN_EVS];
  const int max_evs = sizeof(evs) / sizeof(evs[0]);
  int i;

  int n_ev = ef_eventq_poll(&(tx->vi), evs, max_evs);
  for( i = 0; i < n_ev; ++i )
    switch( EF_EVENT_TYPE(evs[i]) ) {
    case EF_EVENT_TYPE_TX:
      tx->completed += ef_vi_transmit_unbundle(&(tx->vi), &(evs[i]), ids);
      break;
    default:
      RTT_TEST( 0 );
      break;
    }
}


static void efvi_ping_pio(struct rtt_endpoint* ep)
{
  struct efvi_endpoint* eep = EFVI_ENDPOINT(ep);
  RTT_TRY( ef_vi_transmit_copy_pio(&(eep->tx.vi), 0,
                                   eep->tx_buf, eep->tx_len, 0) );
  poll_tx_completions(&(eep->tx));
  ++(eep->tx.posted);
}


static void efvi_ping_pio_nc(struct rtt_endpoint* ep)
{
  struct efvi_endpoint* eep = EFVI_ENDPOINT(ep);
  RTT_TRY( ef_vi_transmit_pio(&(eep->tx.vi), 0, eep->tx_len, 0) );
  poll_tx_completions(&(eep->tx));
  ++(eep->tx.posted);
}


static void efvi_ping_dma(struct rtt_endpoint* ep)
{
  struct efvi_endpoint* eep = EFVI_ENDPOINT(ep);
  RTT_TRY( ef_vi_transmit(&(eep->tx.vi), eep->tx_dma_addr, eep->tx_len, 0) );
  poll_tx_completions(&(eep->tx));
}


static int poll_tx_alt_completions(struct vi* tx)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event evs[EF_VI_EVENT_POLL_MIN_EVS];
  const int max_evs = sizeof(evs) / sizeof(evs[0]);
  int n_completions = 0;
  int i;

  int n_ev = ef_eventq_poll(&(tx->vi), evs, max_evs);
  for( i = 0; i < n_ev; ++i )
    switch( EF_EVENT_TYPE(evs[i]) ) {
    case EF_EVENT_TYPE_TX_ALT:
      /* Indicates packet transmitted via TX-alt. */
      ++n_completions;
      break;
    case EF_EVENT_TYPE_TX:
      /* Indicates completion of packet fetches. */
      ef_vi_transmit_unbundle(&(tx->vi), &(evs[i]), ids);
      break;
    default:
      fprintf(stderr, "%s: ERROR: unexpected event type %d\n",
              __func__, (int) EF_EVENT_TYPE(evs[i]));
      RTT_TEST( 0 );
      break;
    }

  return n_completions;
}


static void efvi_ping_alt(struct rtt_endpoint* ep)
{
  struct efvi_endpoint* eep = EFVI_ENDPOINT(ep);

  unsigned alt_id = (eep->tx_alt_send)++ % N_TX_ALT;
  struct tx_alt* alt = &(eep->tx_alt[alt_id]);
  RTT_TRY( ef_vi_transmit_alt_go(&(eep->tx.vi), alt_id) );
  RTT_TEST( ! alt->busy );
  alt->busy = true;

  alt_id = (eep->tx_alt_prep)++ % N_TX_ALT;
  alt = &(eep->tx_alt[alt_id]);
  if( alt->busy ) {
    int i, rc;
    do
      rc = poll_tx_alt_completions(&(eep->tx));
    while( rc == 0 );
    RTT_TEST( rc <= N_TX_ALT );
    for( i = 0; i < rc; ++i )
      eep->tx_alt[(alt_id + i) % N_TX_ALT].busy = false;
  }

  RTT_TEST( ! alt->busy );
  RTT_TRY( ef_vi_transmit_alt_stop(&(eep->tx.vi), alt_id) );
  if( N_TX_ALT > 1 )
    RTT_TRY( ef_vi_transmit_alt_select(&(eep->tx.vi), alt_id) );
  RTT_TRY( ef_vi_transmit(&(eep->tx.vi), eep->tx_dma_addr, eep->tx_len, 1) );
}


static void efvi_pong(struct rtt_endpoint* ep)
{
  struct efvi_endpoint* eep = EFVI_ENDPOINT(ep);
  struct vi* rx = &(eep->rx);
  ef_event evs[EF_VI_EVENT_POLL_MIN_EVS];
  const int max_evs = sizeof(evs) / sizeof(evs[0]);
  int n_ev, i;

  if( rx->posted - rx->completed < rx->num_bufs ) {
    struct pkt_buf* pb = PKT_BUF(rx, rx->posted % rx->num_bufs);
    RTT_TRY( ef_vi_receive_post(&(rx->vi), pb->dma_addr, rx->posted) );
    ++(rx->posted);
  }

  bool seen_rx_ev = false;
  do {
    n_ev = ef_eventq_poll(&(rx->vi), evs, max_evs);
    for( i = 0; i < n_ev; ++i )
      switch( EF_EVENT_TYPE(evs[i]) ) {
      case EF_EVENT_TYPE_RX:
        ++(rx->completed);
        seen_rx_ev = true;
        break;
      default:
        RTT_TEST( 0 );
        break;
      }
  } while( ! seen_rx_ev );
}


static void init_packet(void* buf, size_t frame_len, bool mcast)
{
  uint8_t shost[] = { 0x02, 0xff, 0x01, 0x02, 0x03, 0x04 };
  uint8_t dhost_mc[] = { 0x01, 0x00, 0x5e, 0x01, 0x02, 0x03 };
  uint8_t dhost_bc[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  uint8_t* dhost = mcast ? dhost_mc : dhost_bc;

  ssize_t ip_len = frame_len - sizeof(struct ether_header);

  struct ether_header* eth = buf;
  struct iphdr* ip = (void*) (eth + 1);
  struct udphdr* udp = (void*) (ip + 1);

  memcpy(eth->ether_dhost, dhost, 6);
  memcpy(eth->ether_shost, shost, 6);
  eth->ether_type = htons(ETHERTYPE_IP);

  ip->ihl = sizeof(*ip) >> 2;
  ip->version = 4;
  ip->tos = 0;
  ip->tot_len = htons(ip_len);
  ip->id = 0;
  ip->frag_off = htons(IP_DF);
  ip->ttl = 1;
  ip->protocol = IPPROTO_UDP;
  ip->check = 0;
  ip->saddr = inet_addr(local_ip);
  ip->daddr = inet_addr(dest_ip(mcast));

  udp->source = htons(udp_port);
  udp->dest = htons(udp_port);
  udp->len = htons(ip_len - (ip->ihl << 2));
  udp->check = 0;
}


static void init_vi(struct vi* vi, const char* interface,
                    unsigned n_bufs, bool for_tx, bool tx_alt, bool tx_pio)
{
  vi->posted = 0;
  vi->completed = 0;

  unsigned vi_flags = 0;
  if( tx_alt )
    vi_flags |= EF_VI_TX_ALT;

  RTT_TRY( ef_driver_open(&(vi->dh)) );
  RTT_TRY( ef_pd_alloc_by_name(&(vi->pd), vi->dh, interface, 0) );
  RTT_TRY( ef_vi_alloc_from_pd(&(vi->vi), vi->dh, &(vi->pd), vi->dh,
                               -1, for_tx ? 0 : -1, for_tx ? -1 : 0,
                               NULL, -1, vi_flags) );
  if( tx_pio ) {
    #if EF_VI_CONFIG_PIO
      RTT_TRY( ef_pio_alloc(&(vi->pio), vi->dh, &(vi->pd), -1, vi->dh) );
      RTT_TRY( ef_pio_link_vi(&(vi->pio), vi->dh, &(vi->vi), vi->dh) );
    #else
      fprintf(stderr, "PIO not available on this CPU type\n");
      RTT_TEST( 0 );
    #endif
  }
  if( tx_alt )
    RTT_TRY( ef_vi_transmit_alt_alloc(&(vi->vi), vi->dh,
                                      N_TX_ALT, N_TX_ALT * BUF_SIZE) );

  size_t bytes = n_bufs * BUF_SIZE;
  void* p;
  RTT_TEST( posix_memalign(&p, 4096, bytes) == 0 );
  RTT_TRY( ef_memreg_alloc(&(vi->memreg), vi->dh, &vi->pd, vi->dh, p, bytes) );
  vi->bufs = p;
  vi->num_bufs = n_bufs;
  unsigned i;
  for( i = 0; i < n_bufs; ++i ) {
    struct pkt_buf* pb = PKT_BUF(vi, i);
    pb->dma_addr = ef_memreg_dma_addr(&(vi->memreg), pb->payload - vi->bufs);
  }
}


static void efvi_cleanup(struct rtt_endpoint* ep)
{
  struct efvi_endpoint* eep = EFVI_ENDPOINT(ep);
  if( eep->ep.ping == efvi_ping_alt ) {
    unsigned alt_id = (eep->tx_alt_send)++ % N_TX_ALT;
    RTT_TRY( ef_vi_transmit_alt_discard(&(eep->tx.vi), alt_id) );
  }
}


static void vi_filter_udp_full(struct vi* vi, bool mcast)
{
  ef_filter_spec fs;
  ef_filter_spec_init(&fs, EF_FILTER_FLAG_NONE);
  RTT_TRY( ef_filter_spec_set_ip4_full(&fs, IPPROTO_UDP,
                                    inet_addr(dest_ip(mcast)), htons(udp_port),
                                    inet_addr(local_ip), htons(udp_port)) );
  RTT_TRY( ef_vi_filter_add(&(vi->vi), vi->dh, &fs, NULL) );
}


static void rx_fill(struct vi* rx)
{
  unsigned i;
  for( i = 0; i < rx->num_bufs; ++i ) {
    struct pkt_buf* pb = PKT_BUF(rx, i);
    RTT_TRY( ef_vi_receive_post(&(rx->vi), pb->dma_addr, rx->posted) );
    ++rx->posted;
  }
}


bool match_prefix(const char* str, const char* prefix,
                  const char** suffix_out_opt)
{
  size_t prefix_len = strlen(prefix);
  if( strncmp(str, prefix, prefix_len) == 0 ) {
    if( suffix_out_opt != NULL )
      *suffix_out_opt = str + prefix_len;
    return true;
  }
  return false;
}


int rtt_efvi_build_endpoint(struct rtt_endpoint** ep_out,
                            const struct rtt_options* opts, unsigned dirs,
                            const char** args, int n_args)
{
  bool tx_pio = false, tx_alt = false;
  const char* interface = NULL;
  int n_rx_bufs = 504;
  char dummy;

  struct efvi_endpoint* eep = calloc(1, sizeof(*eep));
  eep->mcast = 0;
  eep->ep.cleanup = efvi_cleanup;

  int arg_i;
  for( arg_i = 0; arg_i < n_args; ++arg_i ) {
    const char* arg = args[arg_i];
    if( ! strcmp(arg, "tx=pio_nc") ) {
      eep->ep.ping = efvi_ping_pio_nc;
      tx_pio = true;
    }
    else if( ! strcmp(arg, "tx=pio") ) {
      eep->ep.ping = efvi_ping_pio;
      tx_pio = true;
    }
    else if( ! strcmp(arg, "tx=dma") ) {
      eep->ep.ping = efvi_ping_dma;
    }
    else if( ! strcmp(arg, "tx=alt") ) {
      eep->ep.ping = efvi_ping_alt;
      tx_alt = true;
    }
    else if( ! strcmp(arg, "mc") ) {
      eep->mcast = true;
    }
    else if( match_prefix(arg, "intf=", &interface) ) {
    }
    else if( sscanf(arg, "n_rx_bufs=%u%c", &n_rx_bufs, &dummy) == 1 ) {
    }
    else {
      return rtt_err("ERROR: bad arg: %s\n", arg);
    }
  }

  if( interface == NULL )
    return rtt_err("ERROR: no intf= given for efvi:\n");

  if( dirs & RTT_DIR_RX ) {
    eep->ep.pong = efvi_pong;
    init_vi(&(eep->rx), interface, n_rx_bufs, false, false, false);
    vi_filter_udp_full(&(eep->rx), eep->mcast);
    rx_fill(&(eep->rx));
  }

  if( dirs & RTT_DIR_TX ) {
    if( eep->ep.ping == NULL )
      return rtt_err("ERROR: TX mode not given (eg. tx=dma)\n");
    init_vi(&(eep->tx), interface, 1, true, tx_alt, tx_pio);

    struct pkt_buf* tx_buf = PKT_BUF(&(eep->tx), 0);
    eep->tx_buf = tx_buf->payload;
    eep->tx_len = opts->ping_frame_len;
    eep->tx_dma_addr = tx_buf->dma_addr;
    init_packet(eep->tx_buf, eep->tx_len, eep->mcast);
    if( tx_pio )
      RTT_TRY( ef_pio_memcpy(&(eep->tx.vi), eep->tx_buf, 0, eep->tx_len) );
  }

  if( tx_alt ) {
    int i;
    for( i = 0; i < N_TX_ALT; ++i ) {
      struct tx_alt* alt = &(eep->tx_alt[i]);
      alt->busy = false;
    }
    RTT_TRY( ef_vi_transmit_alt_select(&(eep->tx.vi), 0) );
    RTT_TRY( ef_vi_transmit_alt_stop(&(eep->tx.vi), 0) );
    RTT_TRY( ef_vi_transmit(&(eep->tx.vi), eep->tx_dma_addr, eep->tx_len, 13) );
    eep->tx_alt_send = 0;
    eep->tx_alt_prep = 1;
  }

  *ep_out = &(eep->ep);
  return 0;
}
