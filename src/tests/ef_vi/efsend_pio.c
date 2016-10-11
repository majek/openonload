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
** Copyright 2005-2016  Solarflare Communications Inc.
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


/* efsend_pio
 *
 * Sample app that sends UDP packets on a specified interface.
 *
 * Packet data is copied to the NIC's PIO buffer before being sent,
 * which typically results in lower latency sends compared to accessing
 * packet data stored on the host via DMA, which is the method used by
 * the efsend sample app.
 *
 * The application sends a UDP packet, waits for transmission of the
 * packet to finish and then sends the next.
 *
 * The number of packets sent, the size of the packet, the amount of
 * time to wait between sends can be controlled.
 *
 * 2016 Solarflare Communications Inc.
 * Author: Richard Crowe
 * Date: 2016/05/13
 */

//#include "utils.h"
#include "efsend_common.h"

#include <etherfabric/pd.h>
#include <etherfabric/pio.h>

static int parse_opts(int argc, char* argv[]);

#define MAX_UDP_PAYLEN	(1500 - sizeof(ci_ip4_hdr) - sizeof(ci_udp_hdr))
#define N_BUFS          1
#define BUF_SIZE        2048

/* This gives a frame len of 70, which is the same as:
**   eth + ip + tcp + tso + 4 bytes payload
*/
#define DEFAULT_PAYLOAD_SIZE  28
#define LOCAL_PORT            12345

static ef_vi vi;
static ef_driver_handle dh;
static int tx_frame_len;
static int cfg_local_port = LOCAL_PORT;
static int cfg_payload_len = DEFAULT_PAYLOAD_SIZE;
static int cfg_iter = 10;
static int cfg_usleep = 0;
static int cfg_precopy = 1;
static int n_sent;
static int ifindex;


static int wait_for_some_completions(void)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event      evs[EF_VI_EVENT_POLL_MIN_EVS];
  int           n_ev, i, n_unbundled = 0;

  while( 1 ) {
    n_ev = ef_eventq_poll(&vi, evs, sizeof(evs) / sizeof(evs[0]));
    if( n_ev > 0 )
      for( i = 0; i < n_ev; ++i )
        switch( EF_EVENT_TYPE(evs[i]) ) {
        case EF_EVENT_TYPE_TX:
          /* One TX event can signal completion of multiple TXs */
          n_unbundled += ef_vi_transmit_unbundle(&vi, &evs[i], ids);
          /* We only ever have one packet in flight */
          assert(n_unbundled == 1);
          TEST(ids[0] == n_sent);
          ++n_sent;
          break;
        default:
          TEST(!"Unexpected event received");
        }
    if( n_unbundled > 0 )
      return n_unbundled;
  }
}


int main(int argc, char* argv[])
{
  ef_pd pd;
#if defined(__x86_64__) || defined(__PPC64__)
  ef_pio pio;
#endif
  int i;
  void* p;
  int can_use_pio = 1;

  TRY(parse_opts(argc, argv));

  /* Intialize and configure hardware resources */
  TRY(ef_driver_open(&dh));
  TRY(ef_pd_alloc(&pd, dh, ifindex, EF_PD_DEFAULT));
  /* In the following call, note that no rxq is allocated because this app
   * does not receive packets.
   */
  TRY(ef_vi_alloc_from_pd(&vi, dh, &pd, dh, -1, 0, -1, NULL, -1,
      EF_VI_FLAGS_DEFAULT));

#if defined(__x86_64__) || defined(__PPC64__)
  if(vi.nic_type.arch == EF_VI_ARCH_FALCON) {
    can_use_pio = 0;
  }
  else {
    /* Allocate a PIO region and link it to our vi */
    TRY(ef_pio_alloc(&pio, dh, &pd, -1, dh));
    TRY(ef_pio_link_vi(&pio, dh, &vi, dh));
  }
#else
  can_use_pio = 0;
#endif

  if (!can_use_pio) {
    fprintf(stderr, "ERROR: Cannot use PIO - NIC must be 7000 series or"
                    " higher, and OS type must be x86_64 or PPC64\n");
    abort();
  }

  printf("txq_size=%d\n", ef_vi_transmit_capacity(&vi));
  printf("evq_size=%d\n", ef_eventq_capacity(&vi));
  printf("pio_size=%d\n", ef_vi_get_pio_size(&vi));

  /* Allocate memory for packet buffers, note alignment */
  TEST(posix_memalign(&p, CI_PAGE_SIZE, BUF_SIZE) == 0);

  /* Prepare packet contents */
  tx_frame_len = init_udp_pkt(p, cfg_payload_len, &vi, dh);
  /* Copy packet data into the NIC's PIO region.  If the -c option was
   * specified on the command line, this step is skipped, as the copy will
   * be performed later as part of the send operation.
   */
  if (cfg_precopy)
    TRY(ef_pio_memcpy(&vi, p, 0, tx_frame_len));

  /* Start sending */
  for( i = 0; i < cfg_iter; ++i ) {
    /* Transmit packet contained in hardware PIO buffer */
    if (cfg_precopy) {
      TRY(ef_vi_transmit_pio(&vi, 0, tx_frame_len, n_sent));
    }
    else {
      /* Transmit packet after copying it to hardware PIO buffer */
      TRY(ef_vi_transmit_copy_pio(&vi, 0, p, tx_frame_len, n_sent));
    }

    wait_for_some_completions();
    if( cfg_usleep )
      usleep(cfg_usleep);
  }

  printf("Sent %d packets\n", cfg_iter);
  return 0;
}


/* Utilities */
void usage(void)
{
  common_usage();

  fprintf(stderr, "  -c                  - Copy packet to hardware PIO region "
                  "on critical path\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "e.g.:\n");
  fprintf(stderr, "  - Send pkts to 239.1.2.3:1234 from eth2:\n"
          "          efsend_pio eth2 239.1.2.3 1234\n");
  exit(1);
}


static int parse_opts(int argc, char*argv[])
{
  int c;

  while( (c = getopt(argc, argv, "n:m:s:l:c")) != -1 )
    switch( c ) {
    case 'n':
      cfg_iter = atoi(optarg);
      break;
    case 'm':
      cfg_payload_len = atoi(optarg);
      break;
    case 'l':
      cfg_local_port = atoi(optarg);
      break;
    case 's':
      cfg_usleep = atoi(optarg);
      break;
    case 'c':
      cfg_precopy = 0;
      break;
    case '?':
      usage();
      break;
    default:
      TEST(0);
    }

  argc -= optind;
  argv += optind;
  if( argc != 3 )
    usage();

  if( cfg_payload_len > MAX_UDP_PAYLEN ) {
    fprintf(stderr, "WARNING: UDP payload length %d is larger than standard "
            "MTU\n", cfg_payload_len);
  }

  /* Parse arguments after options */
  parse_args(argv, &ifindex, cfg_local_port);
  return 0;
}
