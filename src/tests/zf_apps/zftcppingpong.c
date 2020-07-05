/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/*
 * TCPDirect sample application demonstrating:
 *
 * - TCP active and passive open
 * - Low latency send and receive (using zero-copy interface)
 * - The multiplexer API
 */
#include <zf/zf.h>
#include "zf_utils.h"

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <netinet/tcp.h>


static void usage_msg(FILE* f)
{
  fprintf(f, "usage:\n");
  fprintf(f, "  zftcppingpong [options] pong <this-host:port>\n");
  fprintf(f, "  zftcppingpong [options] ping <remote-host:port>\n");
  fprintf(f, "\n");
  fprintf(f, "options:\n");
  fprintf(f, "  -s tcp payload in bytes\n");
  fprintf(f, "  -i number of iterations\n");
  fprintf(f, "  -m use multiplexer\n");
  fprintf(f, "  -t print timestamps (only if using multiplexer)\n");
  fprintf(f, "  -c enable overlapped reads and specify a time for the overlapped delay in nanoseconds.");
  fprintf(f, "\n");
}


static void usage_err(void)
{
  usage_msg(stderr);
  exit(1);
}


struct rx_msg {
  /* The iovec used by zft_msg must be immediately afterwards */
  struct zft_msg msg;
  struct iovec iov[1];
};


struct cfg {
  int size;
  int itercount;
  bool ping;
  bool muxer;
  bool timestamps;
  bool overlapped_mode;
  int overlapped_delay;
};


static struct cfg cfg = {
  .size = 12,
  .itercount = 1000000,
  .muxer = false,
};

static struct zf_muxer_set* muxer;


static void ping_pongs(struct zf_stack* stack, struct zft* zock)
{
  char send_buf[cfg.size];
  struct rx_msg msg;
  const int max_iov = sizeof(msg.iov) / sizeof(msg.iov[0]);
  int sends_left = cfg.itercount;
  int recvs_left = cfg.itercount;
  bool zock_has_rx_data = false;

  if( cfg.ping ) {
    ZF_TEST(zft_send_single(zock, send_buf, cfg.size, 0) == cfg.size);
    --sends_left;
  }

  do {
    size_t bytes_left = cfg.size;
    do {
      if( ! zock_has_rx_data )
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
      zock_has_rx_data = msg.msg.pkts_left != 0;
    } while( bytes_left );

    if( sends_left ) {
      ZF_TEST(zft_send_single(zock, send_buf, cfg.size, 0) == cfg.size);
      --sends_left;
    }
    ZF_TEST(zft_zc_recv_done(zock, &msg.msg) == 1);
    --recvs_left;
  } while( recvs_left );
}


static void muxer_ping_pongs(struct zf_stack* stack, struct zft* zock)
{
  char send_buf[cfg.size];
  struct rx_msg msg;
  const int max_iov = sizeof(msg.iov) / sizeof(msg.iov[0]);
  int sends_left = cfg.itercount;
  int recvs_left = cfg.itercount;
  size_t rx_bytes_left = cfg.size;
  size_t ts_bytes_left = 0;
  bool zock_has_rx_data = false;
  bool zock_has_ts_data = false;

  if( cfg.ping ) {
    ZF_TEST(zft_send_single(zock, send_buf, cfg.size, 0) == cfg.size);
    --sends_left;
    ts_bytes_left = cfg.timestamps ? cfg.size : 0;
  }

  do {
    if( ! (zock_has_rx_data || zock_has_ts_data) ) {
      /* zf_muxer_wait() polls the stack until one of the zockets becomes
       * 'ready'.  Note that muxers are edge-triggered, which is why we
       * must be careful to block only if we've drained all data from the
       * zocket.
       */
      struct epoll_event ev;
      ZF_TEST(zf_muxer_wait(muxer, &ev, 1, -1) == 1);
      ZF_TEST(ev.events & (EPOLLIN | EPOLLERR));
      zock_has_rx_data = ev.events & EPOLLIN;
      zock_has_ts_data = ev.events & EPOLLERR;
    }

    if( zock_has_rx_data ) {
      msg.msg.iovcnt = max_iov;
      zft_zc_recv(zock, &msg.msg, 0);
      ZF_TEST(msg.msg.iovcnt == 1);
      ZF_TEST(msg.iov[0].iov_len <= rx_bytes_left);
      rx_bytes_left -= msg.iov[0].iov_len;
      zock_has_rx_data = msg.msg.pkts_left != 0;

      if( recvs_left ) {
        if( cfg.timestamps ) {
          struct timespec ts;
          unsigned flags;
          ZF_TRY(zft_pkt_get_timestamp(zock, &msg.msg, &ts, 0, &flags));
          fprintf(stderr, "TIME RECV  %ld.%09ld bytes %lu flags %x\n",
                  ts.tv_sec, ts.tv_nsec, msg.iov[0].iov_len, flags);
        }
        ZF_TEST(zft_zc_recv_done(zock, &msg.msg) == 1);
      }
      else {
        ZF_TEST(zft_zc_recv_done(zock, &msg.msg) == 0);
      }
    }

    if( zock_has_ts_data ) {
      struct zf_pkt_report report;
      int count = 1;
      ZF_TRY(zft_get_tx_timestamps(zock, &report, &count));
      zock_has_ts_data = count != 0;

      if( zock_has_ts_data ) {
        ZF_TEST(count == 1);
        fprintf(stderr, "TIME SENT  %ld.%09ld bytes %u left %lu flags %x\n",
                report.timestamp.tv_sec,
                report.timestamp.tv_nsec,
                report.bytes,
                ts_bytes_left,
                report.flags);
        /* Ignore a report about a retransmitted packet.  Should check
         * report.start and report.bytes in case there were some new
         * bytes transmitted in this packet */
        if( !(report.flags & ZF_PKT_REPORT_TCP_RETRANS)) {
          ZF_TEST(report.bytes <= ts_bytes_left);
          ts_bytes_left -= report.bytes;
        }
      }
    }

    if( rx_bytes_left == 0 && ts_bytes_left == 0 ) {
      if( recvs_left ) {
        --recvs_left;
        rx_bytes_left = recvs_left ? cfg.size : 0;
      }
      if( sends_left ) {
        ZF_TEST(zft_send_single(zock, send_buf, cfg.size, 0) == cfg.size);
        --sends_left;
        ts_bytes_left = cfg.timestamps ? cfg.size : 0;
      }
    }
  } while( rx_bytes_left || ts_bytes_left );
}

static void pftf_ping_pong(struct zf_stack *stack, struct zft *zock)
{
  char send_buf[cfg.size];
  struct rx_msg msg;
  const int max_iov = sizeof(msg.iov) / sizeof(msg.iov[0]);
  int sends_left = cfg.itercount;
  int recvs_left = cfg.itercount;
  size_t rx_bytes_left = cfg.size;
  size_t ts_bytes_left = 0;

  if( cfg.ping ) {
    ZF_TEST(zft_send_single(zock, send_buf, cfg.size, 0) == cfg.size);
    --sends_left;
    ts_bytes_left = cfg.timestamps ? cfg.size : 0;
  }

  do {
    struct epoll_event ev;
    ZF_TEST(zf_muxer_wait(muxer, &ev, 1, -1) == 1);
    /* ZF_EPOLLIN_OVERLAPPED event should not occur with any other event. */
    ZF_TEST( !(ev.events & (EPOLLIN | EPOLLERR )) || !(ev.events & ZF_EPOLLIN_OVERLAPPED) );

    if ( ev.events & EPOLLIN ) {
      /* zf_muxer_wait() polls the stack until one of the zockets becomes
       * 'ready'.  Note that muxers are edge-triggered, which is why we
       * must be careful to block only if we've drained all data from the
       * zocket.
       */
        do {
          msg.msg.iovcnt = max_iov;
          zft_zc_recv(zock, &msg.msg, 0);
          ZF_TEST(msg.msg.iovcnt == 1);
          ZF_TEST(msg.iov[0].iov_len <= rx_bytes_left);
          rx_bytes_left -= msg.iov[0].iov_len;
          if ( cfg.timestamps ) {
            struct timespec ts;
            unsigned flags;
            ZF_TRY(zft_pkt_get_timestamp(zock, &msg.msg, &ts, 0, &flags));
            fprintf(stderr, "TIME RECV  %ld.%09ld bytes %lu flags %x\n",
                    ts.tv_sec, ts.tv_nsec, msg.iov[0].iov_len, flags);
          }
          /* Receive is done, simulate some market processing for that data. */
          nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 1000}, NULL);
          ZF_TEST(zft_zc_recv_done(zock, &msg.msg) == 1 || (recvs_left <= 1 && rx_bytes_left == 0));
        } while ( msg.msg.pkts_left != 0 );
    }
    else if (ev.events & ZF_EPOLLIN_OVERLAPPED) {
      msg.msg.iovcnt = max_iov;
      msg.iov[0].iov_len = cfg.size;
  
      zft_zc_recv(zock, &msg.msg, ZF_OVERLAPPED_WAIT);
      if (msg.msg.iovcnt == 0)
        /* overlapped wait has been abandoned */
        continue;

      if( cfg.overlapped_delay > 0 && rx_bytes_left == msg.iov[0].iov_len )
        /* Simulate some heavy cpu processing for the given packet */
        nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = cfg.overlapped_delay}, NULL);

      
      /* wait for packet completion and verification */
      zft_zc_recv(zock, &msg.msg, ZF_OVERLAPPED_COMPLETE);
      if( msg.msg.iovcnt == 0 )
        /* packet did not pass verification */
        continue;

      rx_bytes_left -= msg.iov[0].iov_len;

      if ( cfg.timestamps ) {
        struct timespec ts;
        unsigned flags;
        ZF_TRY(zft_pkt_get_timestamp(zock, &msg.msg, &ts, 0, &flags));
        fprintf(stderr, "TIME RECV  %ld.%09ld bytes %lu flags %x\n",
                ts.tv_sec, ts.tv_nsec, msg.iov[0].iov_len, flags);
      }
      ZF_TEST(zft_zc_recv_done(zock, &msg.msg) == 1 || (recvs_left <= 1 && rx_bytes_left == 0));
    }


    if( ev.events & EPOLLERR ) {
      /* zf_muxer_wait() polls the stack until one of the zockets becomes
       * 'ready'.  Note that muxers are edge-triggered, which is why we
       * must be careful to block only if we've drained all data from the
       * zocket.
       */
      int count = 1;
      do {
        struct zf_pkt_report report;
        int count = 1;
        ZF_TRY(zft_get_tx_timestamps(zock, &report, &count));

        if( count != 0 ) {
          ZF_TEST(count == 1);
          fprintf(stderr, "TIME SENT  %ld.%09ld bytes %u left %lu flags %x\n",
                  report.timestamp.tv_sec,
                  report.timestamp.tv_nsec,
                  report.bytes,
                  ts_bytes_left,
                  report.flags);
          /* Ignore a report about a retransmitted packet.  Should check
          * report.start and report.bytes in case there were some new
          * bytes transmitted in this packet */
          if( !(report.flags & ZF_PKT_REPORT_TCP_RETRANS) ) {
            ZF_TEST(report.bytes <= ts_bytes_left);
            ts_bytes_left -= report.bytes;
          }
        } 
      } while( count != 0 );
    }


    if( rx_bytes_left == 0 && ts_bytes_left == 0 ) {
      if( recvs_left ) {
          --recvs_left;
          rx_bytes_left = recvs_left ? cfg.size : 0;
      }
      if( sends_left ) {
        ZF_TEST(zft_send_single(zock, send_buf, cfg.size, 0) == cfg.size);
        --sends_left;
        ts_bytes_left = cfg.timestamps ? cfg.size : 0;
      }
    }
  } while( rx_bytes_left || ts_bytes_left );
}


static void pinger(struct zf_stack* stack, struct zft* zock,
                   void (*ping_pongs_fn)(struct zf_stack*, struct zft*),
                   double* rtt)
{
  struct timeval start, end;
  gettimeofday(&start, NULL);

  ping_pongs_fn(stack, zock);

  gettimeofday(&end, NULL);
  int usec = (end.tv_sec - start.tv_sec) * 1000000;
  usec += end.tv_usec - start.tv_usec;
  *rtt = (double) usec / cfg.itercount;
}


static void ponger(struct zf_stack* stack, struct zft* zock,
                   void (*ping_pongs_fn)(struct zf_stack*, struct zft*))
{
  ping_pongs_fn(stack, zock);
}


int main(int argc, char* argv[])
{
  int c;
  while( (c = getopt(argc, argv, "s:i:c:mt")) != -1 )
    switch (c) {
    case 's':
      cfg.size = atoi(optarg);
      break;
    case 'i':
      cfg.itercount = atoi(optarg);
      break;
    case 'm':
      cfg.muxer = true;
      break;
    case 't':
      cfg.timestamps = true;
      break;
    case 'c':
      cfg.overlapped_mode = true;
      cfg.overlapped_delay = atoi(optarg);
      break;
    case '?':
      exit(1);
    default:
      ZF_TEST(0);
    }

  if( cfg.timestamps && ! cfg.muxer ) {
    fprintf(stderr, "Timestamp reporting (-t) requires multiplexer (-m)\n");
    usage_err();
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

  if( cfg.timestamps ) {
    zf_attr_set_int(attr, "rx_timestamping", 1);
    zf_attr_set_int(attr, "tx_timestamping", 1);
  }

  struct zf_stack* stack;
  ZF_TRY(zf_stack_alloc(attr, &stack));

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

  void (*ping_pongs_fn)(struct zf_stack*, struct zft*) = ping_pongs;

  if (cfg.muxer) {
    ZF_TRY(zf_muxer_alloc(stack, &muxer));
    if (cfg.overlapped_mode) {
      struct epoll_event event = {.events = EPOLLIN | EPOLLERR | ZF_EPOLLIN_OVERLAPPED};
      ZF_TRY(zf_muxer_add(muxer, zft_to_waitable(zock), &event));
      ping_pongs_fn = pftf_ping_pong;
    }
    else {
      struct epoll_event event = {.events = EPOLLIN | EPOLLERR};
      ZF_TRY(zf_muxer_add(muxer, zft_to_waitable(zock), &event));
      ping_pongs_fn = muxer_ping_pongs;
    }
  }

  if( cfg.ping ) {
    double rtt;
    pinger(stack, zock, ping_pongs_fn, &rtt);
    printf("mean round-trip time: %0.3f usec\n", rtt);
  }
  else {
    ponger(stack, zock, ping_pongs_fn);
  }

  /* Do a clean shutdown and free all resources. */
  while( zft_shutdown_tx(zock) == -EAGAIN )
    zf_reactor_perform(stack);

  while( ! zf_stack_is_quiescent(stack) )
    zf_reactor_perform(stack);

  if( cfg.muxer ) {
    zf_muxer_del(zft_to_waitable(zock));
    zf_muxer_free(muxer);
  }

  ZF_TRY(zft_free(zock));
  ZF_TRY(zf_stack_free(stack));
  ZF_TRY(zf_deinit());
  return 0;
}
