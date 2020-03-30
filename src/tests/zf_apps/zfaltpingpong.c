/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/*
 * TCPDirect sample application demonstrating the "TX alternatives"
 * mechanism and API for low-latency sends.
 *
 * This sample is based on the zftcppingpong sample.
 */
#include <etherfabric/ef_vi.h> /* for struct ef_vi_transmit_alt_overhead */
#include <zf/zf.h>
#include "zf_utils.h"

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <inttypes.h>


static void usage_msg(FILE* f)
{
  fprintf(f, "usage:\n");
  fprintf(f, "  zfaltpingpong [options] pong <this-host:port>\n");
  fprintf(f, "  zfaltpingpong [options] ping <remote-host:port>\n");
  fprintf(f, "\n");
  fprintf(f, "options:\n");
  fprintf(f, "  -s tcp payload in bytes\n");
  fprintf(f, "  -i number of iterations\n");
  fprintf(f, "\n");
}


static void usage_err(void)
{
  usage_msg(stderr);
  exit(1);
}


#define NUM_ALTS  2


struct rx_msg {
  /* The iovec used by zft_msg must be immediately afterwards */
  struct zft_msg msg;
  struct iovec iov[1];
};


struct cfg {
  int size;
  int itercount;
  bool ping;
};


static struct cfg cfg = {
  .size = 12,
  .itercount = 1000000,
};

static uint64_t alt_busy_count;


static int queue_message(struct zf_stack* stack, struct zft* zock,
                         zf_althandle alt, const void* buf, size_t len)
{
  struct iovec iov = { .iov_base = (void*) buf, .iov_len = len };
  int rc;
  int event_occurred = 0;
  while( rc = zft_alternatives_queue(zock, alt, &iov, 1, 0),
         rc == -EBUSY || rc == -EAGAIN ) {
    if( rc == -EBUSY )
      ++alt_busy_count;
    event_occurred |= zf_reactor_perform(stack);
  }
  return rc < 0 ? rc : event_occurred;
}


static void ping_pongs(struct zf_stack* stack, struct zft* zock,
                       zf_althandle* alts)
{
  char send_buf[cfg.size];
  struct rx_msg msg;
  const int max_iov = sizeof(msg.iov) / sizeof(msg.iov[0]);
  int sends_left = cfg.itercount;
  int recvs_left = cfg.itercount;
  bool zock_maybe_has_rx_data = false;
  int next_alt = 0;
  int rc;

  /* We expect the queuing to succeed without having to poll the stack, since
   * the alternative should not be busy and we have ample send space, so we
   * assert that queue_message() returns zero here. */
  rc = queue_message(stack, zock, alts[next_alt], send_buf, cfg.size);
  ZF_TRY(rc);
  ZF_TEST(rc == 0);

  if( cfg.ping ) {
    ZF_TRY(zf_alternatives_send(stack, alts[next_alt]));
    next_alt = (next_alt + 1) % NUM_ALTS;
    /* As above, queue_message() should return zero. */
    rc = queue_message(stack, zock, alts[next_alt], send_buf, cfg.size);
    ZF_TRY(rc);
    ZF_TEST(rc == 0);
    --sends_left;
  }

  do {
    size_t bytes_left = cfg.size;
    do {
      if( ! zock_maybe_has_rx_data )
        /* Poll the stack until something happens. */
        while( zf_reactor_perform(stack) == 0 )
          ;
      msg.msg.iovcnt = max_iov;
      zft_zc_recv(zock, &msg.msg, 0);
      if( msg.msg.iovcnt ) {
        /* NB. msg.iov[0].iov_len==0 indicates we're not going to get any
         * more data (ie. the other end has shutdown or connection has
         * died).  We don't check for that here...instead it will be
         * detected if zft_zc_recv_done()!=1.
         */
        ZF_TEST(msg.iov[0].iov_len <= bytes_left);
        bytes_left -= msg.iov[0].iov_len;
        if( bytes_left == 0 )
          /* Break out to do send before zft_zc_recv_done() to save a few
           * nanoseconds.
           */
          break;
        ZF_TEST(zft_zc_recv_done(zock, &msg.msg) == 1);
      }
      zock_maybe_has_rx_data = msg.msg.pkts_left != 0;
    } while( bytes_left );

    if( sends_left ) {
      ZF_TRY(zf_alternatives_send(stack, alts[next_alt]));
      next_alt = (next_alt + 1) % NUM_ALTS;
      rc = queue_message(stack, zock, alts[next_alt], send_buf, cfg.size);
      if( rc )
        zock_maybe_has_rx_data = true;
      ZF_TRY(rc);
      --sends_left;
    }
    ZF_TEST(zft_zc_recv_done(zock, &msg.msg) == 1);
    --recvs_left;
  } while( recvs_left );
}


static void pinger(struct zf_stack* stack, struct zft* zock,
                   zf_althandle* alts, double* rtt)
{
  struct timeval start, end;
  gettimeofday(&start, NULL);

  ping_pongs(stack, zock, alts);

  gettimeofday(&end, NULL);
  int usec = (end.tv_sec - start.tv_sec) * 1000000;
  usec += end.tv_usec - start.tv_usec;
  *rtt = (double) usec / cfg.itercount;
}


static void ponger(struct zf_stack* stack, struct zft* zock, zf_althandle* alts)
{
  ping_pongs(stack, zock, alts);
}


int main(int argc, char* argv[])
{
  int c;
  while( (c = getopt(argc, argv, "s:i:")) != -1 ) {
    switch( c ) {
    case 's':
      cfg.size = atoi(optarg);
      break;
    case 'i':
      cfg.itercount = atoi(optarg);
      break;
    case '?':
      usage_err();
      exit(1);
    default:
      ZF_TEST(0);
    }
  }

  argc -= optind;
  argv += optind;
  if( argc != 2 )
    usage_err();

  if( ! strcmp(argv[0], "ping") )
    cfg.ping = true;
  else if( ! strcmp(argv[0], "pong") )
    cfg.ping = false;
  else
    usage_err();

  struct addrinfo* ai;
  if( getaddrinfo_hostport(argv[1], NULL, &ai) != 0 ) {
    fprintf(stderr, "ERROR: failed to lookup address '%s'\n", argv[1]);
    exit(2);
  }

  /* Initialise the TCPDirect library and allocate a stack. */
  ZF_TRY(zf_init());

  struct zf_attr* attr;
  ZF_TRY(zf_attr_alloc(&attr));
  ZF_TRY(zf_attr_set_int(attr, "alt_count", NUM_ALTS));

  struct zf_stack* stack;
  ZF_TRY(zf_stack_alloc(attr, &stack));

  zf_althandle alts[NUM_ALTS];
  for( int i = 0; i < sizeof(alts) / sizeof(alts[0]); ++i )
    ZF_TRY(zf_alternatives_alloc(stack, attr, &alts[i]));

  struct zft* zock;

  if( cfg.ping ) {
    /* In 'ping' mode, connect to the specified remote address. */
    struct zft_handle* tcp_handle;
    ZF_TRY(zft_alloc(stack, attr, &tcp_handle));
    printf("Connecting to ponger\n");
    ZF_TRY(zft_connect(tcp_handle, ai->ai_addr, ai->ai_addrlen, &zock));
    /* The zft_connect() call is non-blocking, so the zocket is not yet
     * connected.  Wait until the connect completes or fails...
     */
    while( zft_state(zock) == TCP_SYN_SENT )
      zf_reactor_perform(stack);
    ZF_TEST( zft_state(zock) == TCP_ESTABLISHED );
  }
  else {
    /* In 'pong' mode, create a listening zocket and wait until we've
     * accepted a connection.
     */
    struct zftl* listener;
    int rc;
    ZF_TRY(zftl_listen(stack, ai->ai_addr, ai->ai_addrlen, attr, &listener));
    printf("Waiting for incoming connection\n");
    do {
      while( zf_reactor_perform(stack) == 0 );
    } while( (rc = zftl_accept(listener, &zock)) == -EAGAIN );
    ZF_TRY(rc);
    ZF_TRY(zftl_free(listener));
  }
  printf("Connection established\n");

  /* Verify that we have enough buffer space. */
  struct ef_vi_transmit_alt_overhead overhead;
  ZF_TRY( zf_alternatives_query_overhead_tcp(zock, &overhead) );
  int pkt_bytes = ef_vi_transmit_alt_usage(&overhead, cfg.size);
  int64_t buffer_space;
  ZF_TRY( zf_attr_get_int(attr, "alt_buf_size", &buffer_space) );
  ZF_TEST( pkt_bytes <= buffer_space );

  if( cfg.ping ) {
    double rtt;
    pinger(stack, zock, alts, &rtt);
    printf("mean round-trip time: %0.3f usec\n", rtt);
    printf("alt_busy_count: %"PRIu64"\n", alt_busy_count);
  }
  else {
    ponger(stack, zock, alts);
  }

  /* Do a clean shutdown and free all resources. */
  while( zft_shutdown_tx(zock) == -EAGAIN )
    zf_reactor_perform(stack);

  while( ! zf_stack_is_quiescent(stack) )
    zf_reactor_perform(stack);

  ZF_TRY(zft_free(zock));
  ZF_TRY(zf_stack_free(stack));
  ZF_TRY(zf_deinit());
  return 0;
}
