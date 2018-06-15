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

/*
 * TCPDirect sample application to act as a client - remote system should run
 * efdelegated_server
 *
 */
#include <zf/zf.h>
#include "zf_utils.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MTU                   1500
#define MAX_ETH_HEADERS       (14/*ETH*/ + 4/*802.1Q*/)
#define MAX_IP_TCP_HEADERS    (20/*IP*/ + 20/*TCP*/ + 12/*TCP options*/)
#define MAX_PACKET            (MTU + MAX_ETH_HEADERS)
#define MAX_MESSAGE           (MTU - MAX_IP_TCP_HEADERS)

static inline int getaddrinfo_hostport2(const char* host,
                                        const char* port,
                                        struct addrinfo** res)
{
  if( host == NULL )
    return -EINVAL;
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  int rc = getaddrinfo(host, port, &hints, res);
  return rc;
}


int mk_socket(int family, int socktype,
              int op(int sockfd, const struct sockaddr *addr,
                     socklen_t addrlen),
              const char* host, const char* port)
{
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = family;
  hints.ai_socktype = socktype;
  struct addrinfo* ai;
  int rc = getaddrinfo(host, port, &hints, &ai);
  if( rc != 0 ) {
    fprintf(stderr, "ERROR: could not resolve '%s:%s' (%s)\n",
            (host) ? host : "", (port) ? port : "", gai_strerror(rc));
    return -1;
  }
  int sock;
  if( (sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0 ) {
    fprintf(stderr, "ERROR: socket(%d, %d, %d) failed (%s)\n",
            ai->ai_family, ai->ai_socktype, ai->ai_protocol, strerror(errno));
    return -1;
  }
  if( op != NULL && op(sock, ai->ai_addr, ai->ai_addrlen) < 0 ) {
    fprintf(stderr, "ERROR: op(%s, %s) failed (%s)\n",
            host, port, strerror(errno));
    close(sock);
    return -1;
  }
  freeaddrinfo(ai);
  return sock;
}


static void usage_msg(FILE* f)
{
  fprintf(f, "usage:\n");
  fprintf(f, "  zfdelegated_client [options] <multicast interface> "
          "<server-ip>\n");
  fprintf(f, "\n");
  fprintf(f, "options:\n");
  fprintf(f, "  -s tcp payload in bytes\n");
  fprintf(f, "  -r udp payload size in bytes\n");
  fprintf(f, "  -p port number\n");
  fprintf(f, "  -u use UDP socket to receive multicast (for comparison with "
          "efdelegated_client)\n");
  fprintf(f, "\n");
  fprintf(f, "use efdelegated_server to provide remote system\n");
}


static void usage_err(void)
{
  usage_msg(stderr);
  exit(1);
}


struct cfg {
  int tx_size;
  int rx_size;
  char* mcast_addr;
  char* port;
  int udp_socket;
};

struct stats {
  unsigned int normal_sends;
};

struct client_state {
  int                          udp_sock;
  char*                        msg_buf;
  int                          msg_len;
  char                         pkt_buf[MAX_PACKET];
  char                         recv_buf[MTU];
};

static struct cfg cfg = {
  .tx_size = 200,
  .rx_size = 300,
  /* match default address/port of efdelegated_server: */
  .mcast_addr = "224.1.2.3",
  .port = "8122",
  /* Default to using TCPDirect for UDP receive too */
  .udp_socket = 0,
};

static struct stats stats;

static void init(struct client_state* cs, const char* mcast_intf,
                 const char* mcast_addr, const char* port)
{
  cs->msg_len = cfg.tx_size;
  cs->msg_buf = cs->pkt_buf + MAX_ETH_HEADERS + MAX_IP_TCP_HEADERS;

  /* Create UDP socket, bind, join multicast group. */
  ZF_TRY( cs->udp_sock = mk_socket(0, SOCK_DGRAM, bind,
                                   mcast_addr, port) );
  if( mcast_intf != NULL ) {
    struct ip_mreqn mreqn;
    ZF_TEST( inet_aton(mcast_addr, &mreqn.imr_multiaddr) );
    mreqn.imr_address.s_addr = htonl(INADDR_ANY);
    ZF_TEST( (mreqn.imr_ifindex = if_nametoindex(mcast_intf)) != 0 );
    ZF_TRY( setsockopt(cs->udp_sock, SOL_IP, IP_ADD_MEMBERSHIP,
                       &mreqn, sizeof(mreqn)) );
  }
}

static int poll_udp_rx(struct client_state* cs)
{
  int rc = recv(cs->udp_sock, cs->recv_buf,
                sizeof(cs->recv_buf) - 1, MSG_DONTWAIT);
  if( rc >= 0 ) {
    cs->recv_buf[rc] = '\0';
    return strncmp(cs->recv_buf, "hit me", 6) == 0;
  }
  else if( rc == -1 && errno == EAGAIN )
    return -1;
  else
    ZF_TEST(0);
}

static void do_loop(struct zf_stack* stack, struct zft* zock, struct zfur* ur,
                    struct client_state* cs)
{
  char send_buf[2048];
  struct {
    struct zfur_msg msg;
    struct iovec iov[2]; /* must allocate space for IOVECs */
  } ur_msg;
  const int max_ur_iov = sizeof(ur_msg.iov) / sizeof(ur_msg.iov[0]);
  struct {
    struct zft_msg msg;
    struct iovec iov[1]; /* must allocate space for IOVECs */
  } tr_msg;
  const int max_tr_iov = sizeof(tr_msg.iov) / sizeof(tr_msg.iov[0]);


  ZF_TEST( cfg.tx_size <= sizeof(send_buf) );

  strncpy(send_buf, "As you command...", cfg.tx_size);

  while( 1 ) {
    /* Spend most of our time polling the UDP socket, since that is the
     * latency sensitive path.
     */
    if( ! cfg.udp_socket ) {
      /* Using TCPDirect for UDP receive */
      int i;
      for( i = 0; i < 100; ++i ) { /* weighted 100:1 in favor of polling UDP */
        if( zf_reactor_perform(stack) > 0 ) {
          do {
            ur_msg.msg.iovcnt = max_ur_iov;
            zfur_zc_recv(ur, &ur_msg.msg, 0);
            if( ur_msg.msg.iovcnt == 0 )
              continue;
            if( strncmp(ur_msg.iov[0].iov_base, "hit me", 6) == 0 ) {
              ZF_TEST( zft_send_single(zock, send_buf, cfg.tx_size, 0)
                       == cfg.tx_size );
              ++stats.normal_sends;
            }
            /* The current implementation of TCPDirect always returns a single
             * buffer for each datagram.  Future implementations may return
             * multiple buffers for large (jumbo) or fragmented datagrams.
             */
            ZF_TEST(ur_msg.msg.iovcnt == 1);
            zfur_zc_recv_done(ur, &ur_msg.msg);
            /* Occasionally might have multiple datagrams queued on the zocket
             * If needed, loop to fully drain
             */
          } while( ur_msg.msg.dgrams_left );
        }
      }
    }
    else {
      /* using conventional socket for UDP receive */
      int i;
      for( i = 0; i < 100; ++i ) { /* weighted 100:1 in favor of polling UDP */
        if( poll_udp_rx(cs) > 0 ) {
          ZF_TEST( zft_send_single(zock, send_buf, cfg.tx_size, 0)
                   == cfg.tx_size );
          ++stats.normal_sends;
        }
      }
      if( zf_stack_has_pending_work(stack) )
        zf_reactor_perform(stack);
    }

    /* less frequently read any TCP replies */
    do {
      tr_msg.msg.iovcnt = max_tr_iov;
      zft_zc_recv(zock, &tr_msg.msg, 0);
      if( tr_msg.msg.iovcnt ) {
        /* Detect connection shutdown if zft_zc_recv_done()!=1 */
        if( zft_zc_recv_done(zock, &tr_msg.msg) != 1 ) return;
      }
    } while( tr_msg.msg.pkts_left );
  }
}


void zock_put_int(struct zft* zock, int i)
{
  i = htonl(i);
  ZF_TEST( zft_send_single(zock, &i, sizeof(i), 0) == sizeof(i) );
}


int main(int argc, char* argv[])
{
  int c;
  while( (c = getopt(argc, argv, "s:r:p:u")) != -1 )
    switch( c ) {
    case 's':
      cfg.tx_size = atoi(optarg);
      break;
    case 'r':
      cfg.rx_size = atoi(optarg);
      break;
    case 'p':
      cfg.port = optarg;
      break;
    case 'u':
      cfg.udp_socket = 1;
      break;
    case '?':
      exit(1);
    default:
      ZF_TEST(0);
    }

  argc -= optind;
  argv += optind;
  if( argc != 2 )
    usage_err();

  struct addrinfo* ai;
  if( getaddrinfo_hostport2(argv[1], cfg.port, &ai) != 0 ) {
    fprintf(stderr, "ERROR: failed to lookup address '%s'\n", argv[1]);
    exit(2);
  }
  char* mcast_intf = argv[0];

  /* Initialise the TCPDirect library and allocate a stack. */
  ZF_TRY(zf_init());

  struct zf_attr* attr;
  ZF_TRY(zf_attr_alloc(&attr));
  ZF_TRY(zf_attr_set_str(attr, "interface", mcast_intf));

  struct zf_stack* stack;
  ZF_TRY(zf_stack_alloc(attr, &stack));

  struct zft* zock;

  /* Connect to the specified remote address. */
  struct zft_handle* tcp_handle;
  ZF_TRY(zft_alloc(stack, attr, &tcp_handle));
  printf("Connecting to server\n");
  ZF_TRY(zft_connect(tcp_handle, ai->ai_addr, ai->ai_addrlen, &zock));
  /* The zft_connect() call is non-blocking, so the zocket is not yet
   * connected.  Wait until the connect completes or fails...
   */
  while( zft_state(zock) == TCP_SYN_SENT )
    zf_reactor_perform(stack);
  ZF_TEST( zft_state(zock) == TCP_ESTABLISHED );
  printf("Connection established\n");

  /* send configured packet sizes to the server */
  zock_put_int(zock, cfg.tx_size);
  zock_put_int(zock, cfg.rx_size);

  struct zfur* ur;
  if( ! cfg.udp_socket ) {
    /* Allocate UDP zocket and bind to the given address. */
    struct addrinfo* ai_mcast;
    if( getaddrinfo_hostport2(cfg.mcast_addr, cfg.port, &ai_mcast) != 0 ) {
      fprintf(stderr, "ERROR: failed to lookup multicast address '%s'\n",
              cfg.mcast_addr);
      exit(2);
    }
    ZF_TRY(zfur_alloc(&ur, stack, attr));
    ZF_TRY(zfur_addr_bind(ur, ai_mcast->ai_addr, ai_mcast->ai_addrlen,
                          NULL, 0, 0));

    /* main loop */
    do_loop(stack, zock, ur, NULL);
  }
  else {
    /* Allocate UDP socket and bind to the given address. */
    struct client_state* cs = calloc(1, sizeof(*cs));
    init(cs, mcast_intf, cfg.mcast_addr, cfg.port);
    fprintf(stderr, "Using standard UDP socket to receive multicast\n");

    /* main loop */
    do_loop(stack, zock, NULL, cs);
  }

  /* print stats */
  fprintf(stderr, "\n");
  fprintf(stderr, "TCPDirect sends: %u\n", stats.normal_sends);
  fprintf(stderr, "\n");

  /* Do a clean shutdown and free all resources. */
  while( zft_shutdown_tx(zock) == -EAGAIN )
    zf_reactor_perform(stack);

  while( ! zf_stack_is_quiescent(stack) )
    zf_reactor_perform(stack);

  if( ! cfg.udp_socket ) {
    ZF_TRY(zfur_free(ur));
  }

  ZF_TRY(zft_free(zock));
  ZF_TRY(zf_stack_free(stack));
  ZF_TRY(zf_deinit());
  return 0;
}
