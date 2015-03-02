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


/* efforward
 *
 * Forward packets between two interfaces without modification.
 *
 * 2011 Solarflare Communications Inc.
 * Author: David Riddoch
 * Date: 2011/04/13
 */

#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>

#include "utils.h"

/* Hardware delivers at most ef_vi_receive_buffer_len() bytes to each
 * buffer (default 1792), and for best performance buffers should be
 * aligned on a 64-byte boundary.  Also, RX DMA will not cross a 4K
 * boundary.  The I/O address space may be discontiguous at 4K boundaries.
 * So easiest thing to do is to make buffers always be 2K in size.
 */
#define PKT_BUF_SIZE         2048

/* Align address where data is delivered onto EF_VI_DMA_ALIGN boundary,
 * because that gives best performance.
 */
#define RX_DMA_OFF           ROUND_UP(sizeof(struct pkt_buf), EF_VI_DMA_ALIGN)


struct pkt_buf {
  /* I/O address corresponding to the start of this pkt_buf struct.
   * The pkt_buf is mapped into both VIs so there are two sets of rx
   * and tx IO addresses. */
  ef_addr            rx_ef_addr[2];
  ef_addr            tx_ef_addr[2];

  /* pointer to where received packets start */
  void*              rx_ptr[2];

  /* id to help look up the buffer when polling the EVQ */
  int                id;

  struct pkt_buf*    next;
};


struct pkt_bufs {
  /* Memory for packet buffers */
  void*  mem;
  size_t mem_size;

  /* Number of packet buffers allocated */
  int    num;

  /* pool of free packet buffers (LIFO to minimise working set) */
  struct pkt_buf*    free_pool;
  int                free_pool_n;
};


struct vi {
  /* handle for accessing the driver */
  ef_driver_handle   dh;

  /* protection domain */
  ef_pd              pd;

  /* virtual interface (rxq + txq + evq) */
  ef_vi              vi;

  /* registered memory for DMA */
  ef_memreg          memreg;

  /* statistics */
  uint64_t           n_pkts;
};


static struct vi vis[2];
static struct pkt_bufs pbs;


/* Given a id to a packet buffer, look up the data structure.  The ids
 * are assigned in ascending order so this is simple to do. */
static inline struct pkt_buf* pkt_buf_from_id(int pkt_buf_i)
{
  assert((unsigned) pkt_buf_i < (unsigned) pbs.num);
  return (void*) ((char*) pbs.mem + (size_t) pkt_buf_i * PKT_BUF_SIZE);
}


/* Try to refill the RXQ on the given VI with at most
 * REFILL_BATCH_SIZE packets if it has enough space and we have
 * enough free buffers. */
static void vi_refill_rx_ring(int vi_i)
{
  ef_vi* vi = &vis[vi_i].vi;
#define REFILL_BATCH_SIZE  16
  struct pkt_buf* pkt_buf;
  int i;

  if( ef_vi_receive_space(vi) < REFILL_BATCH_SIZE ||
      pbs.free_pool_n < REFILL_BATCH_SIZE )
    return;

  for( i = 0; i < REFILL_BATCH_SIZE; ++i ) {
    pkt_buf = pbs.free_pool;
    pbs.free_pool = pbs.free_pool->next;
    --pbs.free_pool_n;
    ef_vi_receive_init(vi, pkt_buf->rx_ef_addr[vi_i], pkt_buf->id);
  }
  ef_vi_receive_push(vi);
}


/* Free buffer into free pool in LIFO order to minimize cache footprint. */
static inline void pkt_buf_free(struct pkt_buf* pkt_buf)
{
  pkt_buf->next = pbs.free_pool;
  pbs.free_pool = pkt_buf;
  ++pbs.free_pool_n;
}


/* Handle an RX event on a VI.  We forward the packet on the other VI. */
static void handle_rx(int rx_vi_i, int pkt_buf_i, int len)
{
  int rc;
  int tx_vi_i = 2 - 1 - rx_vi_i;
  struct vi* rx_vi = &vis[rx_vi_i];
  struct vi* tx_vi = &vis[tx_vi_i];
  struct pkt_buf* pkt_buf = pkt_buf_from_id(pkt_buf_i);

  ++rx_vi->n_pkts;
  rc = ef_vi_transmit(&tx_vi->vi, pkt_buf->tx_ef_addr[tx_vi_i], len,
                          pkt_buf->id);
  if( rc != 0 ) {
    assert(rc == -EAGAIN);
    /* TXQ is full.  A real app might consider implementing an overflow
     * queue in software.  We simply choose not to send.
     */
    pkt_buf_free(pkt_buf);
  }
}


static void handle_rx_discard(int pkt_buf_i, int discard_type)
{
  struct pkt_buf* pkt_buf = pkt_buf_from_id(pkt_buf_i);
  pkt_buf_free(pkt_buf);
}


static void complete_tx(int vi_i, int pkt_buf_i)
{
  struct pkt_buf* pkt_buf = pkt_buf_from_id(pkt_buf_i);
  pkt_buf_free(pkt_buf);
}


/* The main loop.  Poll each VI handling various types of events and
 * then try to refill them. */
static void main_loop(void)
{
  int i, j, k;

  while( 1 ) {
    for( i = 0; i < 2; ++i ) {
      ef_vi* vi = &vis[i].vi;
      ef_event evs[EF_VI_EVENT_POLL_MIN_EVS];
      int n_ev = ef_eventq_poll(vi, evs, sizeof(evs) / sizeof(evs[0]));
      for( j = 0; j < n_ev; ++j ) {
        switch( EF_EVENT_TYPE(evs[j]) ) {
        case EF_EVENT_TYPE_RX:
          /* This code does not handle jumbos. */
          assert(EF_EVENT_RX_SOP(evs[j]) != 0);
          assert(EF_EVENT_RX_CONT(evs[j]) == 0);
          handle_rx(i, EF_EVENT_RX_RQ_ID(evs[j]),
                    EF_EVENT_RX_BYTES(evs[j]) -
                    ef_vi_receive_prefix_len(vi));
          break;
        case EF_EVENT_TYPE_TX: {
          ef_request_id ids[EF_VI_TRANSMIT_BATCH];
          int ntx = ef_vi_transmit_unbundle(vi, &evs[j], ids);
          for( k = 0; k < ntx; ++k )
            complete_tx(i, ids[k]);
          break;
        }
        case EF_EVENT_TYPE_RX_DISCARD:
          handle_rx_discard(EF_EVENT_RX_DISCARD_RQ_ID(evs[j]),
                            EF_EVENT_RX_DISCARD_TYPE(evs[j]));
          break;
        default:
          LOGE("ERROR: unexpected event %d\n", (int) EF_EVENT_TYPE(evs[j]));
          break;
        }
      }
      vi_refill_rx_ring(i);
    }
  }
}


/* Print approx packet rate every second. */
static void* monitor_fn(void* dummy)
{
  struct timeval start, end;
  int prev_pkts[2], now_pkts[2];
  int pkt_rates[2];
  int ms, i;

  for( i = 0; i < 2; ++i )
    prev_pkts[i] = vis[i].n_pkts;
  gettimeofday(&start, NULL);

  printf("vi0-rx\tvi1-rx\n");
  while( 1 ) {
    sleep(1);
    for( i = 0; i < 2; ++i )
      now_pkts[i] = vis[i].n_pkts;
    gettimeofday(&end, NULL);
    ms = (end.tv_sec - start.tv_sec) * 1000;
    ms += (end.tv_usec - start.tv_usec) / 1000;

    for( i = 0; i < 2; ++i )
      pkt_rates[i] = (int64_t)(now_pkts[i] - prev_pkts[i]) * 1000 / ms;
    printf("%d\t%d\n", pkt_rates[0], pkt_rates[1]);
    fflush(stdout);
    for( i = 0; i < 2; ++i )
      prev_pkts[i] = now_pkts[i];
    start = end;
  }
  return NULL;
}


/* Allocate and initialize the packet buffers. */
static int init_pkts_memory(void)
{
  int i;

  /* Number of buffers is the worst case to fill up all the queues
   * assuming that you are going to allocate 2 VIs, both have a RXQ
   * and TXQ and both have default capacity of 512. */
  pbs.num = 4 * 512;
  pbs.mem_size = pbs.num * PKT_BUF_SIZE;
  pbs.mem_size = ROUND_UP(pbs.mem_size, huge_page_size);
  /* Allocate huge-page-aligned memory to give best chance of allocating
   * transparent huge-pages.
   */
  TEST(posix_memalign(&pbs.mem, huge_page_size, pbs.mem_size) == 0);

  for( i = 0; i < pbs.num; ++i ) {
    struct pkt_buf* pkt_buf = pkt_buf_from_id(i);
    pkt_buf->id = i;
    pkt_buf_free(pkt_buf);
  }
  return 0;
}


/* Allocate and initialize a VI. */
static int init(const char* intf, int vi_i)
{
  struct vi* vi = &vis[vi_i];
  int i;
  TRY(ef_driver_open(&vi->dh));
  TRY(ef_pd_alloc_by_name(&vi->pd, vi->dh, intf, EF_PD_DEFAULT));
  TRY(ef_vi_alloc_from_pd(&vi->vi, vi->dh, &vi->pd, vi->dh, -1, -1, -1, NULL,
                          -1, EF_VI_FLAGS_DEFAULT));

  /* Memory for pkt buffers has already been allocated.  Map it into
   * the VI. */
  TRY(ef_memreg_alloc(&vi->memreg, vi->dh, &vi->pd, vi->dh,
                      pbs.mem, pbs.mem_size));
  for( i = 0; i < pbs.num; ++i ) {
    struct pkt_buf* pkt_buf = pkt_buf_from_id(i);
    pkt_buf->rx_ef_addr[vi_i] =
      ef_memreg_dma_addr(&vi->memreg, i * PKT_BUF_SIZE) + RX_DMA_OFF;
    pkt_buf->tx_ef_addr[vi_i] =
      ef_memreg_dma_addr(&vi->memreg, i * PKT_BUF_SIZE) + RX_DMA_OFF +
      ef_vi_receive_prefix_len(&vi->vi);
    pkt_buf->rx_ptr[vi_i] = (char*) pkt_buf + RX_DMA_OFF +
      ef_vi_receive_prefix_len(&vi->vi);
  }

  /* Our pkt buffer allocation function makes assumptions on queue sizes */
  assert(ef_vi_receive_capacity(&vi->vi) == 511);
  assert(ef_vi_transmit_capacity(&vi->vi) == 511);

  while( ef_vi_receive_space(&vi->vi) > REFILL_BATCH_SIZE )
    vi_refill_rx_ring(vi_i);

  ef_filter_spec fs;
  ef_filter_spec_init(&fs, EF_FILTER_FLAG_NONE);
  TRY(ef_filter_spec_set_unicast_all(&fs));
  TRY(ef_vi_filter_add(&vi->vi, vi->dh, &fs, NULL));
  ef_filter_spec_init(&fs, EF_FILTER_FLAG_NONE);
  TRY(ef_filter_spec_set_multicast_all(&fs));
  TRY(ef_vi_filter_add(&vi->vi, vi->dh, &fs, NULL));
  return 0;
}


static void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  efforward <intf0> <intf1>\n");
  exit(1);
}


int main(int argc, char* argv[])
{
  pthread_t thread_id;
  if( argc != 3 )
    usage();

  TRY(init_pkts_memory());
  TRY(init(argv[1], 0));
  TRY(init(argv[2], 1));

  TEST(pthread_create(&thread_id, NULL, monitor_fn, NULL) == 0);
  main_loop();

  return 0;
}
