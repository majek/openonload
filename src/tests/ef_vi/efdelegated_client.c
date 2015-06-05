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


/* efdelegated_client
 *
 * Copyright 2009-2015 Solarflare Communications Inc.
 * Author: Akhi Singhania
 * Date: 2015/1/20
 *
 * Refer to efdelegated_server.c for a description.
 */

#define _GNU_SOURCE 1

#include "utils.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>


static unsigned  cfg_payload_len = 200;
static int       cfg_iter        = 100000;
static int       cfg_warm        = 1000;

static int tcp_sock;
static int udp_sock;


static void tx_send(int len)
{
  char buf[len];
  TEST( send(udp_sock, buf, len, 0) == len );
}


static void rx_wait(void)
{
  char buf[cfg_payload_len];
  TEST( recv(tcp_sock, buf, cfg_payload_len, MSG_WAITALL) == cfg_payload_len );
}


static void loop(void)
{
  struct timeval start, end;
  int i, usec;

  for( i = 0; i < cfg_warm; ++i ) {
    tx_send(1);
    rx_wait();
  }

  gettimeofday(&start, NULL);
  for( i = 0; i < cfg_iter; ++i ) {
    tx_send(1);
    rx_wait();
  }
  gettimeofday(&end, NULL);

  tx_send(0);  /* tell other end to exit */

  usec = (end.tv_sec - start.tv_sec) * 1000000;
  usec += end.tv_usec - start.tv_usec;
  printf("round-trip time: %0.3f usec\n", (double) usec / cfg_iter);
}


/**********************************************************************/

static int my_getaddrinfo(const char* host, const char* port,
                          struct addrinfo** ai_out)
{
  struct addrinfo hints;
  hints.ai_flags = 0;
  hints.ai_family = AF_INET;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;
  return getaddrinfo(host, port, &hints, ai_out);
}


static int parse_host(const char* s, struct in_addr* ip_out)
{
  const struct sockaddr_in* sa;
  struct addrinfo* ai;
  int rc;
  if( (rc = my_getaddrinfo(s, 0, &ai)) < 0 )
    return rc;
  sa = (const struct sockaddr_in*) ai->ai_addr;
  *ip_out = sa->sin_addr;
  return 0;
}


static int my_connect(int sock, const char* ipaddr, int port)
{
  struct sockaddr_in sa;
  sa.sin_family = AF_INET;
  TRY( parse_host(ipaddr, &sa.sin_addr) );
  sa.sin_port = htons(port);
  return connect(sock, (struct sockaddr*) &sa, sizeof(sa));
}


static int my_bind(int sock, int port)
{
  struct sockaddr_in sa;
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  sa.sin_port = htons(port);
  return bind(sock, (struct sockaddr*)&sa, sizeof(sa));
}


static void init(const char* srv_ip, int port)
{
  TRY( udp_sock = socket(AF_INET, SOCK_DGRAM, 0) );
  TRY( my_bind(udp_sock, port) );
  TRY( my_connect(udp_sock, srv_ip, port) );
  TRY( tcp_sock = socket(AF_INET, SOCK_STREAM, 0) );
  TRY( my_connect(tcp_sock, srv_ip, port) );
}


/**********************************************************************/

static void usage_msg(FILE* f)
{
  fprintf(f, "\nusage:\n");
  fprintf(f, "  efdelegated_client [options] <server-host> <port>\n");
  fprintf(f, "\noptions:\n");
  fprintf(f, "  -w <iterations>   - set number of warmup iterations\n");
  fprintf(f, "  -n <iterations>   - set number of iterations\n");
  fprintf(f, "  -s <msg-size>     - set payload size\n");
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
  const char* srv_ip;
  int port;

  while( (c = getopt(argc, argv, "hn:s:w:")) != -1 )
    switch( c ) {
    case 'h':
      usage_msg(stdout);
      exit(0);
      break;
    case 'n':
      cfg_iter = atoi(optarg);
      break;
    case 'w':
      cfg_warm = atoi(optarg);
      break;
    case 's':
      cfg_payload_len = atoi(optarg);
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

  srv_ip = argv[0];
  port = atoi(argv[1]);
  init(srv_ip, port);
  loop();
  return 0;
}

/*! \cidoxg_end */
