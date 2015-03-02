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


/* efsink
 *
 * Receive streams of packets on a single interface.
 *
 * 2011 Solarflare Communications Inc.
 * Author: David Riddoch
 * Date: 2011/04/28
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
  /* I/O address corresponding to the start of this pkt_buf struct */
  ef_addr            ef_addr;

  /* pointer to where received packets start */
  void*              rx_ptr;

  int                id;
  struct pkt_buf*    next;
};


struct resources {
  /* handle for accessing the driver */
  ef_driver_handle   dh;

  /* protection domain */
  struct ef_pd       pd;

  /* virtual interface (rxq + txq) */
  struct ef_vi       vi;
  int                rx_prefix_len;

  /* registered memory for DMA */
  void*              pkt_bufs;
  int                pkt_bufs_n;
  struct ef_memreg   memreg;

  /* pool of free packet buffers (LIFO to minimise working set) */
  struct pkt_buf*    free_pkt_bufs;
  int                free_pkt_bufs_n;

  /* statistics */
  uint64_t           n_rx_pkts;
  uint64_t           n_rx_bytes;
};


static int cfg_hexdump;
static int cfg_timestamping;
static int cfg_vport;
static int cfg_vlan_id = EF_PD_VLAN_NONE;
static int cfg_verbose;
static int cfg_monitor_vi_stats;


static inline
struct pkt_buf* pkt_buf_from_id(struct resources* res, int pkt_buf_i)
{
  assert((unsigned) pkt_buf_i < (unsigned) res->pkt_bufs_n);
  return (void*) ((char*) res->pkt_bufs + (size_t) pkt_buf_i * PKT_BUF_SIZE);
}


static inline void pkt_buf_free(struct resources* res, struct pkt_buf* pkt_buf)
{
  pkt_buf->next = res->free_pkt_bufs;
  res->free_pkt_bufs = pkt_buf;
  ++(res->free_pkt_bufs_n);
}


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


static inline int64_t timespec_diff_ns(struct timespec a, struct timespec b)
{
  assert(a.tv_nsec >= 0 && a.tv_nsec < 1000000000);
  assert(b.tv_nsec >= 0 && b.tv_nsec < 1000000000);
  return (a.tv_sec - b.tv_sec) * (int64_t) 1000000000
    + (a.tv_nsec - b.tv_nsec);
}


static void handle_rx(struct resources* res, int pkt_buf_i, int len)
{
  struct pkt_buf* pkt_buf;

  LOGV("PKT: received pkt=%d len=%d\n", pkt_buf_i, len);

  pkt_buf = pkt_buf_from_id(res, pkt_buf_i);

  if( cfg_timestamping ) {
    struct timespec hw_ts, sw_ts;
    unsigned ts_flags;
    TRY(clock_gettime(CLOCK_REALTIME, &sw_ts));
    void* dma_ptr = (char*) pkt_buf + RX_DMA_OFF;
    TRY(ef_vi_receive_get_timestamp_with_sync_flags(&res->vi, dma_ptr,
                                                    &hw_ts, &ts_flags));
    printf("HW_TSTAMP=%ld.%09ld  delta=%"PRId64"ns  %s %s\n",
           hw_ts.tv_sec, hw_ts.tv_nsec, timespec_diff_ns(sw_ts, hw_ts),
           (ts_flags & EF_VI_SYNC_FLAG_CLOCK_SET) ? "ClockSet" : "",
           (ts_flags & EF_VI_SYNC_FLAG_CLOCK_SET) ? "ClockInSync" : "");
  }

  /* Do something useful with packet contents here! */
  if( cfg_hexdump )
    hexdump(pkt_buf->rx_ptr, len);

  pkt_buf_free(res, pkt_buf);
  res->n_rx_pkts += 1;
  res->n_rx_bytes += len;
}


static void handle_rx_discard(struct resources* res,
                              int pkt_buf_i, int len, int discard_type)
{
  struct pkt_buf* pkt_buf;

  LOGE("ERROR: discard type=%d\n", discard_type);

  if( /* accept_discard_pkts */ 1 ) {
    handle_rx(res, pkt_buf_i, len);
  }
  else {
    pkt_buf = pkt_buf_from_id(res, pkt_buf_i);
    pkt_buf_free(res, pkt_buf);
  }
}


static void refill_rx_ring(struct resources* res)
{
#define REFILL_BATCH_SIZE  16
  struct pkt_buf* pkt_buf;
  int i;

  if( ef_vi_receive_space(&res->vi) < REFILL_BATCH_SIZE ||
      res->free_pkt_bufs_n < REFILL_BATCH_SIZE )
    return;

  for( i = 0; i < REFILL_BATCH_SIZE; ++i ) {
    pkt_buf = res->free_pkt_bufs;
    res->free_pkt_bufs = res->free_pkt_bufs->next;
    --(res->free_pkt_bufs_n);
    ef_vi_receive_init(&res->vi, pkt_buf->ef_addr + RX_DMA_OFF, pkt_buf->id);
  }
  ef_vi_receive_push(&res->vi);
}


static void thread_main_loop(struct resources* res)
{
  ef_event evs[32];
  int i, n_ev;

  while( 1 ) {
    n_ev = ef_eventq_poll(&res->vi, evs, sizeof(evs) / sizeof(evs[0]));
    if( n_ev <= 0 )
      continue;

    for( i = 0; i < n_ev; ++i ) {
      switch( EF_EVENT_TYPE(evs[i]) ) {
      case EF_EVENT_TYPE_RX:
        /* This code does not handle jumbos. */
        assert(EF_EVENT_RX_SOP(evs[i]) != 0);
        assert(EF_EVENT_RX_CONT(evs[i]) == 0);
        handle_rx(res, EF_EVENT_RX_RQ_ID(evs[i]),
                  EF_EVENT_RX_BYTES(evs[i]) - res->rx_prefix_len);
        break;
      case EF_EVENT_TYPE_RX_DISCARD:
        handle_rx_discard(res, EF_EVENT_RX_DISCARD_RQ_ID(evs[i]),
                        EF_EVENT_RX_DISCARD_BYTES(evs[i]) - res->rx_prefix_len,
                        EF_EVENT_RX_DISCARD_TYPE(evs[i]));
        break;
      default:
        LOGE("ERROR: unexpected event type=%d\n", (int) EF_EVENT_TYPE(evs[i]));
        break;
      }
    }
    refill_rx_ring(res);
  }
}

/**********************************************************************/

static void efvi_stats_header_print(struct resources* res,
                                    const ef_vi_stats_layout** vi_stats_layout)
{
  int i;

  TRY(ef_vi_stats_query_layout(&res->vi, vi_stats_layout));

  for( i = 0; i < (*vi_stats_layout)->evsl_fields_num; ++i)
    printf("  %s", (*vi_stats_layout)->evsl_fields[i].evsfl_name);
}


static void efvi_stats_print(struct resources* res, int reset_stats,
                             const ef_vi_stats_layout* vi_stats_layout)
{
  uint8_t* stats_data;
  int i;

  TEST((stats_data = malloc(vi_stats_layout->evsl_data_size)) != NULL);

  ef_vi_stats_query(&res->vi, res->dh, stats_data, reset_stats);
  for( i = 0; i < vi_stats_layout->evsl_fields_num; ++i ) {
    const ef_vi_stats_field_layout* f = &vi_stats_layout->evsl_fields[i];
    switch( f->evsfl_size ) {
      case sizeof(uint32_t):
        printf("%16d", *(uint32_t*)(stats_data + f->evsfl_offset));
        break;
      default:
        printf("%16s", ".");
    };
  }

  free(stats_data);
}


static void monitor(struct resources* res)
{
  /* Print approx packet rate and bandwidth every second.
   * When requested also print vi error statistics. */

  uint64_t now_bytes, prev_bytes;
  struct timeval start, end;
  int prev_pkts, now_pkts;
  int ms, pkt_rate, mbps;
  const ef_vi_stats_layout* vi_stats_layout;

  printf("# pkt-rate  bandwidth(Mbps)  pkts");
  if( cfg_monitor_vi_stats )
    efvi_stats_header_print(res, &vi_stats_layout);
  printf("\n");

  prev_pkts = res->n_rx_pkts;
  prev_bytes = res->n_rx_bytes;
  gettimeofday(&start, NULL);

  while( 1 ) {
    sleep(1);
    now_pkts = res->n_rx_pkts;
    now_bytes = res->n_rx_bytes;
    gettimeofday(&end, NULL);
    ms = (end.tv_sec - start.tv_sec) * 1000;
    ms += (end.tv_usec - start.tv_usec) / 1000;
    pkt_rate = (int) ((int64_t) (now_pkts - prev_pkts) * 1000 / ms);
    mbps = (int) ((now_bytes - prev_bytes) * 8 / 1000 / ms);
    printf("%10d %16d %16llu", pkt_rate, mbps, (unsigned long long) now_pkts);
    if( cfg_monitor_vi_stats )
      efvi_stats_print(res, 1, vi_stats_layout);
    printf("\n");
    fflush(stdout);
    prev_pkts = now_pkts;
    prev_bytes = now_bytes;
    start = end;
  }
}


static void* monitor_fn(void* arg)
{
  struct resources* res = arg;
  monitor(res);
  return NULL;
}


static void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  efsink <options> <interface> <filter-spec>...\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "filter-spec:\n");
  fprintf(stderr, "  {udp|tcp}:[mcastloop-rx,][vid=<vlan>,]<local-host>:"
          "<local-port>[,<remote-host>:<remote-port>]\n");
  fprintf(stderr, "  eth:[vid=<vlan>,]<local-mac>\n");
  fprintf(stderr, "  {unicast-all,multicast-all}\n");
  fprintf(stderr, "  {unicast-mis,multicast-mis}:[vid=<vlan>]\n");
  fprintf(stderr, "  {sniff}:[promisc|no-promisc]\n");
  fprintf(stderr, "  {tx-sniff}\n");
  fprintf(stderr, "  {block-kernel|block-kernel-unicast|"
          "block-kernel-multicast}\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -d     hexdump received packet\n");
  fprintf(stderr, "  -t     enable hardware timestamps\n");
  fprintf(stderr, "  -V     allocate a virtual port\n");
  fprintf(stderr, "  -v     enable verbose logging\n");
  fprintf(stderr, "  -m     monitor vi error statistics\n");
  exit(1);
}


int main(int argc, char* argv[])
{
  const char* interface;
  pthread_t thread_id;
  struct resources* res;
  unsigned vi_flags;
  int c;

  while( (c = getopt (argc, argv, "dtVL:vm")) != -1 )
    switch( c ) {
    case 'd':
      cfg_hexdump = 1;
      break;
    case 't':
      cfg_timestamping = 1;
      break;
    case 'V':
      cfg_vport = 1;
      break;
    case 'L':
      cfg_vlan_id = atoi(optarg);
      break;
    case 'v':
      cfg_verbose = 1;
      break;
    case 'm':
      cfg_monitor_vi_stats = 1;
      break;
    case '?':
      usage();
    default:
      TEST(0);
    }

  argc -= optind;
  argv += optind;
  if( argc < 2 )
    usage();
  interface = argv[0];
  ++argv; --argc;

  TEST((res = calloc(1, sizeof(*res))) != NULL);

  /* Open driver and allocate a VI. */
  TRY(ef_driver_open(&res->dh));
  if( cfg_vport )
    TRY(ef_pd_alloc_with_vport(&res->pd, res->dh, interface,
                               EF_PD_DEFAULT, cfg_vlan_id));
  else
    TRY(ef_pd_alloc_by_name(&res->pd, res->dh, interface, EF_PD_DEFAULT));
  vi_flags = EF_VI_FLAGS_DEFAULT;
  if( cfg_timestamping )
    vi_flags |= EF_VI_RX_TIMESTAMPS;
  TRY(ef_vi_alloc_from_pd(&res->vi, res->dh, &res->pd, res->dh,
                          -1, -1, 0, NULL, -1, vi_flags));
  res->rx_prefix_len = ef_vi_receive_prefix_len(&res->vi);

  LOGI("rxq_size=%d\n", ef_vi_receive_capacity(&res->vi));
  LOGI("evq_size=%d\n", ef_eventq_capacity(&res->vi));
  LOGI("rx_prefix_len=%d\n", res->rx_prefix_len);

  /* Allocate memory for DMA transfers. Try mmap() with MAP_HUGETLB to get huge
   * pages. If that fails, fall back to posix_memalign() and hope that we do
   * get them. */
  res->pkt_bufs_n = ef_vi_receive_capacity(&res->vi);
  size_t alloc_size = res->pkt_bufs_n * PKT_BUF_SIZE;
  alloc_size = ROUND_UP(alloc_size, huge_page_size);
  res->pkt_bufs = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
                       MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
  if( res->pkt_bufs == MAP_FAILED ) {
    LOGW("mmap() failed. Are huge pages configured?\n");

    /* Allocate huge-page-aligned memory to give best chance of allocating
     * transparent huge-pages.
     */
    TEST(posix_memalign(&res->pkt_bufs, huge_page_size, alloc_size) == 0);
  }
  int i;
  for( i = 0; i < res->pkt_bufs_n; ++i ) {
    struct pkt_buf* pkt_buf = pkt_buf_from_id(res, i);
    pkt_buf->rx_ptr = (char*) pkt_buf + RX_DMA_OFF + res->rx_prefix_len;
    pkt_buf->id = i;
    pkt_buf_free(res, pkt_buf);
  }

  /* Register the memory so that the adapter can access it. */
  TRY(ef_memreg_alloc(&res->memreg, res->dh, &res->pd, res->dh,
                      res->pkt_bufs, alloc_size));
  for( i = 0; i < res->pkt_bufs_n; ++i ) {
    struct pkt_buf* pkt_buf = pkt_buf_from_id(res, i);
    pkt_buf->ef_addr = ef_memreg_dma_addr(&res->memreg, i * PKT_BUF_SIZE);
  }

  /* Fill the RX ring. */
  while( ef_vi_receive_space(&res->vi) > REFILL_BATCH_SIZE )
    refill_rx_ring(res);

  /* Add filters so that adapter will send packets to this VI. */
  while( argc > 0 ) {
    ef_filter_spec filter_spec;
    if( filter_parse(&filter_spec, argv[0]) != 0 ) {
      LOGE("ERROR: Bad filter spec '%s'\n", argv[0]);
      exit(1);
    }
    TRY(ef_vi_filter_add(&res->vi, res->dh, &filter_spec, NULL));
    ++argv; --argc;
  }

  TEST(pthread_create(&thread_id, NULL, monitor_fn, res) == 0);
  thread_main_loop(res);
  return 0;
}
