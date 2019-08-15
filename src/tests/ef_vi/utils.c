/*
** Copyright 2005-2019  Solarflare Communications Inc.
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
** Copyright 2005-2019  Solarflare Communications Inc.
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


#define _GNU_SOURCE 1

#include <etherfabric/vi.h>
#include "utils.h"

#include <net/if.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <stddef.h>


static int hostport_parse(struct addrinfo* addr, const char* s_in)
{
  struct addrinfo hints;
  struct addrinfo* ai;
  const char* host;
  const char* port;
  char *s, *p;
  int rc = -EINVAL;

  /* Split the host:port string on the final colon */
  host = s = strdup(s_in);
  p = strrchr(host, ':');
  if( p == NULL )
    goto out;
  port = p + 1;
  /* There must be something after the final colon */
  if( *port == '\0' )
    goto out;
  /* Terminate the host string */
  *p = '\0';

  hints.ai_flags = AI_NUMERICSERV;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;
  rc = getaddrinfo(host, port, &hints, &ai);
  if( rc == 0 ) {
    memcpy(addr, ai, sizeof(struct addrinfo));
  } else {
    fprintf(stderr, "ERROR: getaddrinfo(\"%s\", \"%s\") returned %d %s\n",
            host, port, rc, gai_strerror(rc));
    rc = -EINVAL;
  }
 out:
  free(s);
  return rc;
}


/* Parses a parameter of the form "param=val,", advancing *arg beyond the comma
 * and returning the integer value of val.  If nothing follows the comma, or
 * the argument is otherwise invalid, *arg will be NULL on return.  N.B.: This
 * function resets the strtok() state, and the portion of *arg that is consumed
 * will be altered. */
static int consume_parameter(char **arg)
{
  int val;
  char *param = strtok(*arg, ",");
  param = strchr(param, '=');
  ++param;
  if( ! strlen(param) ) {
    /* Nothing after the comma, so return an error.  The return value itself is
     * insignificant. */
    *arg = NULL;
    return 0;
  }
  val = atoi(param);

  *arg = strtok(NULL, "");

  return val;
}


int filter_parse(ef_filter_spec* fs, const char* s_in)
{
  struct addrinfo laddr, raddr;
  const char* type;
  const char* hostport;
  char* vlan;
  char* remainder;
  char *s;
  int rc = -EINVAL;
  int protocol;
  int i;

  ef_filter_spec_init(fs, EF_FILTER_FLAG_NONE);

  s = strdup(s_in);

  if( (type = strtok(s, ":")) == NULL )
    goto out;

  if( ! strcmp("udp", type) || ! strcmp("tcp", type) ) {
    protocol = strcasecmp(type, "tcp") ? IPPROTO_UDP : IPPROTO_TCP;

    remainder = strtok(NULL, "");
    if( remainder == NULL )
      goto out;

    if( ! strncmp("mcastloop-rx,", remainder, strlen("mcastloop-rx,")) ) {
      ef_filter_spec_init(fs, EF_FILTER_FLAG_MCAST_LOOP_RECEIVE);
      strtok(remainder, ",");
      remainder = strtok(NULL, "");
      if( remainder == NULL )
        goto out;
    }
    if( ! strncmp("vid=", remainder, strlen("vid=")) ) {
      int vlan_id = consume_parameter(&remainder);
      if( remainder == NULL )
        goto out;
      TRY(ef_filter_spec_set_vlan(fs, vlan_id));
    }

    if( strchr(remainder, ',') ) {
      hostport = strtok(remainder, ",");
      remainder = strtok(NULL, "");
      TRY(hostport_parse(&laddr, hostport));
      TRY(hostport_parse(&raddr, remainder));
      if( laddr.ai_family == AF_INET && raddr.ai_family == AF_INET ) {
        struct sockaddr_in *lsin, *rsin;
        lsin = (struct sockaddr_in *)laddr.ai_addr;
        rsin = (struct sockaddr_in *)raddr.ai_addr;
        TRY(ef_filter_spec_set_ip4_full(fs, protocol, lsin->sin_addr.s_addr,
                                        lsin->sin_port, rsin->sin_addr.s_addr,
                                        rsin->sin_port));
      } else if( laddr.ai_family == AF_INET6 && raddr.ai_family == AF_INET6 ) {
        struct sockaddr_in6 *lsin6, *rsin6;
        lsin6 = (struct sockaddr_in6 *)laddr.ai_addr;
        rsin6 = (struct sockaddr_in6 *)raddr.ai_addr;
        TRY(ef_filter_spec_set_ip6_full(fs, protocol, &lsin6->sin6_addr,
                                        lsin6->sin6_port, &rsin6->sin6_addr,
                                        rsin6->sin6_port));
      } else {
        fprintf(stderr, "ERROR: invalid families in local/remote hosts\n");
        goto out;
      }
      rc = 0;
    }
    else {
      TRY(hostport_parse(&laddr, strtok(remainder, ",")));
      if( laddr.ai_family == AF_INET ) {
        struct sockaddr_in *lsin = (struct sockaddr_in *)laddr.ai_addr;
        TRY(ef_filter_spec_set_ip4_local(fs, protocol, lsin->sin_addr.s_addr,
                                         lsin->sin_port));
      } else if( laddr.ai_family == AF_INET6 ) {
        struct sockaddr_in6 *lsin6 = (struct sockaddr_in6 *)laddr.ai_addr;
        TRY(ef_filter_spec_set_ip6_local(fs, protocol, &lsin6->sin6_addr,
                                         lsin6->sin6_port));
      } else {
        fprintf(stderr, "ERROR: invalid family in local host\n");
        goto out;
      }
      rc = 0;
    }
  }

  else if( ! strcmp("eth", type) ) {
    uint8_t mac[6];
    int vlan_id = EF_FILTER_VLAN_ID_ANY;

    remainder = strtok(NULL, "");
    if( remainder == NULL )
      goto out;

    if( ! strncmp("vid=", remainder, strlen("vid=")) ) {
      vlan_id = consume_parameter(&remainder);
      if( remainder == NULL )
        goto out;
    }

    if( ! strncmp("ethertype=", remainder, strlen("ethertype=")) ) {
      uint16_t ethertype = htons(consume_parameter(&remainder));
      if( remainder == NULL )
        goto out;
      TRY(ef_filter_spec_set_eth_type(fs, ethertype));
    }
    else if( ! strncmp("ipproto=", remainder, strlen("ipproto=")) ) {
      uint8_t ipproto = consume_parameter(&remainder);
      if( remainder == NULL )
        goto out;
      TRY(ef_filter_spec_set_ip_proto(fs, ipproto));
    }

    for( i = 0; i < 6; ++i ) {
      mac[i] = strtol(remainder, &remainder, 16);
      if( i != 5 ) {
        if( *remainder != ':' )
          goto out;
        ++remainder;
        if( ! strlen(remainder) )
          goto out;
      }
    }
    if( strlen(remainder) )
      goto out;
    TRY(ef_filter_spec_set_eth_local(fs, vlan_id, mac));
    rc = 0;
  }

  else if( ! strcmp("ethertype", type) ) {
    uint16_t ethertype;

    remainder = strtok(NULL, "");
    if( remainder == NULL )
      goto out;

    if( ! strncmp("vid=", remainder, strlen("vid=")) ) {
      int vlan_id = consume_parameter(&remainder);
      if( remainder == NULL )
        goto out;
      TRY(ef_filter_spec_set_vlan(fs, vlan_id));
    }

    ethertype = htons(strtol(remainder, &remainder, 10));
    if( strlen(remainder) )
      goto out;

    TRY(ef_filter_spec_set_eth_type(fs, ethertype));
    rc = 0;
  }

  else if( ! strcmp("ipproto", type) ) {
    uint8_t ipproto;

    remainder = strtok(NULL, "");
    if( remainder == NULL )
      goto out;

    if( ! strncmp("vid=", remainder, strlen("vid=")) ) {
      int vlan_id = consume_parameter(&remainder);
      if( remainder == NULL )
        goto out;
      TRY(ef_filter_spec_set_vlan(fs, vlan_id));
    }

    ipproto = strtol(remainder, &remainder, 10);
    if( strlen(remainder) )
      goto out;

    TRY(ef_filter_spec_set_ip_proto(fs, ipproto));
    rc = 0;
  }

  else if( ! strcmp("multicast-all", type) ) {
    if( strlen(type) != strlen(s_in) )
      goto out;
    TRY(ef_filter_spec_set_multicast_all(fs));
    rc = 0;
  }

  else if( ! strcmp("unicast-all", type) ) {
    if( strlen(type) != strlen(s_in) )
      goto out;
    TRY(ef_filter_spec_set_unicast_all(fs));
    rc = 0;
  }

  else if( ! strcmp("multicast-mis", type) ) {
    TRY(ef_filter_spec_set_multicast_mismatch(fs));
    if( strlen(type) != strlen(s_in) ) {
      remainder = strtok(NULL, "");
      if( remainder == NULL || strncmp("vid=", remainder, strlen("vid=")) )
        goto out;
      vlan = strchr(remainder, '=');
      ++vlan;
      if( ! strlen(vlan) )
        goto out;
      TRY(ef_filter_spec_set_vlan(fs, atoi(vlan)));
    }
    rc = 0;
  }

  else if( ! strcmp("unicast-mis", type) ) {
    TRY(ef_filter_spec_set_unicast_mismatch(fs));
    if( strlen(type) != strlen(s_in) ) {
      remainder = strtok(NULL, "");
      if( remainder == NULL || strncmp("vid=", remainder, strlen("vid=")) )
        goto out;
      vlan = strchr(remainder, '=');
      ++vlan;
      if( ! strlen(vlan) )
        goto out;
      TRY(ef_filter_spec_set_vlan(fs, atoi(vlan)));
    }
    rc = 0;
  }

  else if( ! strcmp("sniff", type) ) {
    if( strlen(type) == strlen(s_in) ) {
      TRY(ef_filter_spec_set_port_sniff(fs, 1));
    }
    else {
      remainder = strtok(NULL, "");
      if( remainder == NULL )
        goto out;
      if( ! strcmp("promisc", remainder) )
        TRY(ef_filter_spec_set_port_sniff(fs, 1));
      else if( ! strcmp("no-promisc", remainder) )
        TRY(ef_filter_spec_set_port_sniff(fs, 0));
      else
        goto out;
    }
    rc = 0;
  }

  else if( ! strcmp("tx-sniff", type) ) {
    TRY(ef_filter_spec_set_tx_port_sniff(fs));
    rc = 0;
  }

  else if( ! strcmp("block-kernel", type) ) {
    TRY(ef_filter_spec_set_block_kernel(fs));
    rc = 0;
  }

  else if( ! strcmp("block-kernel-unicast", type) ) {
    TRY(ef_filter_spec_set_block_kernel_unicast(fs));
    rc = 0;
  }

  else if( ! strcmp("block-kernel-multicast", type) ) {
    TRY(ef_filter_spec_set_block_kernel_multicast(fs));
    rc = 0;
  }

 out:
  free(s);
  return rc;
}


void sock_put_int(int sock, int i)
{
  i = htonl(i);
  TEST( send(sock, &i, sizeof(i), 0) == sizeof(i) );
}


int sock_get_int(int sock)
{
  int i;
  TEST( recv(sock, &i, sizeof(i), MSG_WAITALL) == sizeof(i) );
  return ntohl(i);
}


int sock_get_ifindex(int sock, int* ifindex_out)
{
  int rc = -1;

  struct sockaddr_storage sas;
  socklen_t len = sizeof(sas);
  TRY( getsockname(sock, (void*) &sas, &len) );

  int addr_off, addr_len;
  switch( sas.ss_family ) {
  case AF_INET:;
    addr_off = offsetof(struct sockaddr_in, sin_addr);
    addr_len = sizeof(((struct sockaddr_in*) 0)->sin_addr);
    break;
  case AF_INET6:
    addr_off = offsetof(struct sockaddr_in6, sin6_addr);
    addr_len = sizeof(((struct sockaddr_in6*) 0)->sin6_addr);
    break;
  default:
    return -1;
  }

  struct ifaddrs *addrs, *iap;
  TRY( getifaddrs(&addrs) );
  for( iap = addrs; iap != NULL; iap = iap->ifa_next )
    if( (iap->ifa_flags & IFF_UP) && iap->ifa_addr &&
        iap->ifa_addr->sa_family == sas.ss_family &&
        memcmp((char*) &sas + addr_off,
               (char*) iap->ifa_addr + addr_off, addr_len) == 0 ) {
      TEST( (*ifindex_out = if_nametoindex(iap->ifa_name)) != 0 );
      rc = 0;
      break;
    }

  freeifaddrs(addrs);
  return rc;
}


int getaddrinfo_storage(int family, const char* host, const char* port,
                        struct sockaddr_storage* sas)
{
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = family;
  struct addrinfo* ai;
  int rc = getaddrinfo(host, port, &hints, &ai);
  if( rc != 0 ) {
    fprintf(stderr, "ERROR: could not resolve '%s:%s' (%s)\n",
            host ? host : "", port, gai_strerror(rc));
    return -1;
  }
  TEST( ai->ai_addrlen <= sizeof(*sas) );
  memcpy(sas, ai->ai_addr, ai->ai_addrlen);
  return 0;
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


void get_ipaddr_of_intf(const char* intf, char** ipaddr_out)
{
  struct ifaddrs *ifaddrs, *ifa;
  char* ipaddr = calloc(NI_MAXHOST, sizeof(char));
  TEST(ipaddr);
  TRY(getifaddrs(&ifaddrs));
  for( ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next ) {
    if( ifa->ifa_addr == NULL )
      continue;
    if( strcmp(ifa->ifa_name, intf) != 0 )
      continue;
    if( ifa->ifa_addr->sa_family != AF_INET )
      continue;
    TRY(getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), ipaddr,
                    NI_MAXHOST, NULL, 0, NI_NUMERICHOST));
    break;
  }
  freeifaddrs(ifaddrs);
  *ipaddr_out = ipaddr;
}


/* Handles both vlan and non-vlan interfaces, set vlan negative to skip vlan */
void get_ipaddr_of_vlan_intf(const char* intf, int vlan, char** ipaddr_out)
{
  char full_intf[NI_MAXHOST];
  if ( vlan < 0 ) {
    get_ipaddr_of_intf(intf, ipaddr_out);
  }
  else {
    TRY(snprintf(full_intf, NI_MAXHOST, "%s.%d", intf, vlan));
    get_ipaddr_of_intf(full_intf, ipaddr_out);
  }
}

int my_getaddrinfo(const char* host, const char* port,
                          struct addrinfo**ai_out)
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


int parse_host(const char* s, struct in_addr* ip_out)
{
  const struct sockaddr_in* sin;
  struct addrinfo* ai;
  if( my_getaddrinfo(s, 0, &ai) < 0 )
    return 0;
  sin = (const struct sockaddr_in*) ai->ai_addr;
  *ip_out = sin->sin_addr;
  return 1;
}


int parse_interface(const char* s, int* ifindex_out)
{
  char dummy;
  if( (*ifindex_out = if_nametoindex(s)) == 0 )
    if( sscanf(s, "%d%c", ifindex_out, &dummy) != 1 )
      return 0;
  return 1;
}
