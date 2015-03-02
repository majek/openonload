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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  ab
**  \brief  Example for RX timestamping sockets API
**   \date  2014/04/03
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  

/* Example application to demonstrate use of the timestamping API
 *
 * This application will receive packets, and display their 
 * hardware timestamps.
 *
 * Invoke with "--help" to see the options it supports.
 *
 * Example:
 * (host1)$ rx_timestamping
 * UDP socket created, listening on port 9000
 * Selecting software timestamping mode.
 * (host2)$ echo payload | nc -u host1 9000
 * Packet 0 - 8 bytes timestamp 1395768726.443243000
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

/* Use the kernel definitions if possible -
 * But if not, use our own local definitions, and Onload will allow it.
 * - Though you still need a reasonably recent kernel to get hardware
 *   timestamping.
 */
#ifdef NO_KERNEL_TS_INCLUDE
  #include <time.h>
  struct hwtstamp_config {
      int flags;           /* no flags defined right now, must be zero */
      int tx_type;         /* HWTSTAMP_TX_* */
      int rx_filter;       /* HWTSTAMP_FILTER_* */
  };
  enum {
        SOF_TIMESTAMPING_TX_HARDWARE = (1<<0),
        SOF_TIMESTAMPING_TX_SOFTWARE = (1<<1),
        SOF_TIMESTAMPING_RX_HARDWARE = (1<<2),
        SOF_TIMESTAMPING_RX_SOFTWARE = (1<<3),
        SOF_TIMESTAMPING_SOFTWARE = (1<<4),
        SOF_TIMESTAMPING_SYS_HARDWARE = (1<<5),
        SOF_TIMESTAMPING_RAW_HARDWARE = (1<<6),
        SOF_TIMESTAMPING_MASK =
        (SOF_TIMESTAMPING_RAW_HARDWARE - 1) |
        SOF_TIMESTAMPING_RAW_HARDWARE
  };
#else
  #include <linux/net_tstamp.h>
  #include <linux/sockios.h>
#endif

/* These are defined in socket.h, but older versions might not have all 3 */
#ifndef SO_TIMESTAMP
  #define SO_TIMESTAMP            29
#endif
#ifndef SO_TIMESTAMPNS
  #define SO_TIMESTAMPNS          35
#endif
#ifndef SO_TIMESTAMPING
  #define SO_TIMESTAMPING         37
#endif

/* Seconds.nanoseconds format */
#define TIME_FMT "%" PRIu64 ".%.9" PRIu64 " "

/* Assert-like macros */
#define TEST(x)                                                 \
  do {                                                          \
    if( ! (x) ) {                                               \
      fprintf(stderr, "ERROR: '%s' failed\n", #x);              \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )

#define TRY(x)                                                          \
  do {                                                                  \
    int __rc = (x);                                                     \
      if( __rc < 0 ) {                                                  \
        fprintf(stderr, "ERROR: TRY(%s) failed\n", #x);                 \
        fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);       \
        fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",                 \
                __rc, errno, strerror(errno));                          \
        exit(1);                                                        \
      }                                                                 \
  } while( 0 )

struct configuration {
  char const*    cfg_ioctl;     /* e.g. eth6  - calls the ts enable ioctl */
  unsigned short cfg_port;      /* listen port */
};

/* Commandline options, configuration etc. */

void print_help(void)
{
  printf("Usage:\n"
         "\t--ioctl\t<ethX>\tDevice to send timestamping enable ioctl.  "
           "Default: None\n"
         "\t--port\t<num>\tPort to listen on.  "
           "Default: 9000\n"
        );
  exit(-1);
}


static void parse_options( int argc, char** argv, struct configuration* cfg )
{
  int option_index = 0;
  int opt;
  static struct option long_options[] = {
    { "ioctl", required_argument, 0, 'i' },
    { "port", required_argument, 0, 'p' },
    { 0, no_argument, 0, 0 }
  };
  char const* optstring = "ip";

  /* Defaults */
  bzero(cfg, sizeof(struct configuration));
  cfg->cfg_port = 9000;

  opt = getopt_long(argc, argv, optstring, long_options, &option_index);
  while( opt != -1 ) {
    switch( opt ) {
      case 'i':
        cfg->cfg_ioctl = optarg;
        break;
      case 'p':
        cfg->cfg_port = atoi(optarg);
        break;
      default:
        print_help();
        break;
    }
    opt = getopt_long(argc, argv, optstring, long_options, &option_index);
  }
}


/* Connection */
static void make_address(unsigned short port, struct sockaddr_in* host_address)
{
  bzero(host_address, sizeof(struct sockaddr_in));

  host_address->sin_family = AF_INET;
  host_address->sin_port = htons(port);
  host_address->sin_addr.s_addr = INADDR_ANY;
}


/* This requires a bit of explanation.
 * Typically, you have to enable hardware timestamping on an interface.
 * Any application can do it, and then it's available to everyone.
 * The easiest way to do this, is just to run sfptpd.
 *
 * But in case you need to do it manually; here is the code, but
 * that's only supported on reasonably recent versions
 *
 * Option: --ioctl ethX
 *
 * NOTE:
 * Usage of the ioctl call is discouraged. A better method, if using
 * hardware timestamping, would be to use sfptpd as it will effectively
 * make the ioctl call for you.
 *
 */
static void do_ioctl(struct configuration* cfg, int sock)
{
#ifdef SIOCSHWTSTAMP
  struct ifreq ifr;
  struct hwtstamp_config hwc;
#endif

  if( cfg->cfg_ioctl == NULL )
    return;

#ifdef SIOCSHWTSTAMP
  bzero(&ifr, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", cfg->cfg_ioctl);

  /* Standard kernel ioctl options */
  hwc.flags = 0;
  hwc.tx_type = 0;
  hwc.rx_filter = HWTSTAMP_FILTER_ALL;

  ifr.ifr_data = (char*)&hwc;

  TRY( ioctl(sock, SIOCSHWTSTAMP, &ifr) );
  return;
#else
  (void) sock;
  printf("SIOCHWTSTAMP ioctl not supported on this kernel.\n");
  exit(-ENOTSUP);
  return;
#endif
}


/* This routine selects the correct socket option to enable timestamping. */
static void do_ts_sockopt(int sock)
{
  int enable = 1;

  printf("Selecting hardware timestamping mode.\n");
  enable = SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE
            | SOF_TIMESTAMPING_SYS_HARDWARE | SOF_TIMESTAMPING_SOFTWARE;
  TRY(setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING, &enable, sizeof(int)));
}

static int add_udp(unsigned short port)
{
  int s;
  struct sockaddr_in host_address;

  make_address(port, &host_address);

  s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  TEST(s >= 0);

  TRY(bind(s, (struct sockaddr*)&host_address, sizeof(host_address)) );

  printf("UDP socket created, listening on port %d\n", port );

  return s;
}


/* Processing */
static void print_time(struct timespec* ts)
{
  if( ts != NULL ) {
    /* Hardware timestamping provides three timestamps -
     *   system (software)
     *   transformed (hw converted to sw)
     *   raw (hardware)
     * in that order - though depending on socket option, you may have 0 in
     * some of them.
     */
    printf("timestamps " TIME_FMT TIME_FMT TIME_FMT "\n",
      (uint64_t)ts[0].tv_sec, (uint64_t)ts[0].tv_nsec,
      (uint64_t)ts[1].tv_sec, (uint64_t)ts[1].tv_nsec,
      (uint64_t)ts[2].tv_sec, (uint64_t)ts[2].tv_nsec );
  } else
  {
    printf( "no timestamp\n" );
  }
}


/* Given a packet, extract the timestamp(s) */
static void handle_time(struct msghdr* msg)
{
  struct timespec* ts = NULL;
  struct cmsghdr* cmsg;

  for( cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg,cmsg) ) {
    if( cmsg->cmsg_level != SOL_SOCKET )
      continue;

    switch( cmsg->cmsg_type ) {
    case SO_TIMESTAMPNS:
      ts = (struct timespec*) CMSG_DATA(cmsg);
      break;
    case SO_TIMESTAMPING:
      ts = (struct timespec*) CMSG_DATA(cmsg);
      break;
    default:
      /* Ignore other cmsg options */
      break;
    }
  }

  print_time(ts);
}

/* Receive a packet, and print out the timestamps from it */
void do_recv(int sock, unsigned int pkt_num)
{
  struct msghdr msg;
  struct iovec iov;
  struct sockaddr_in host_address;
  char buffer[2048];
  char control[1024];
  int got;

  /* recvmsg header structure */
  make_address(0, &host_address);
  iov.iov_base = buffer;
  iov.iov_len = 2048;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_name = &host_address;
  msg.msg_namelen = sizeof(struct sockaddr_in);
  msg.msg_control = control;
  msg.msg_controllen = 1024;

  /* block for message */
  got = recvmsg(sock, &msg, 0);
  TEST(got >= 0);

  printf("Packet %d - %d bytes\t", pkt_num, got);
  handle_time(&msg);
  return;
};


int main(int argc, char** argv)
{
  struct configuration cfg;
  int sock;
  unsigned int pkt_num = 0;

  parse_options(argc, argv, &cfg);

  /* Initialise */
  sock = add_udp(cfg.cfg_port);
  do_ioctl(&cfg, sock);
  do_ts_sockopt(sock);

  /* Run forever */
  while( 1 ) {
    pkt_num ++;
    do_recv(sock, pkt_num);
  }

  close(sock);
  return 0;
}
