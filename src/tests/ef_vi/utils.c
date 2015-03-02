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

/**********************************************************************/


static int hostport_parse(struct sockaddr_in* sin, const char* s_in)
{
  struct addrinfo hints;
  struct addrinfo* ai;
  const char* host;
  const char* port;
  char *s, *p;
  int rc = -EINVAL;

  p = s = strdup(s_in);
  host = strtok(p, ":");
  port = strtok(NULL, "");
  if( host == NULL || port == NULL )
    goto out;

  hints.ai_flags = AI_NUMERICSERV;
  hints.ai_family = AF_INET;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;
  rc = getaddrinfo(host, port, &hints, &ai);
  if( rc == 0 ) {
    TEST(ai->ai_addrlen == sizeof(*sin));
    memcpy(sin, ai->ai_addr, ai->ai_addrlen);
  }
  else {
    fprintf(stderr, "ERROR: getaddrinfo(\"%s\", \"%s\") returned %d %s\n",
            host, port, rc, gai_strerror(rc));
    rc = -EINVAL;
  }
 out:
  free(s);
  return rc;
}


int filter_parse(ef_filter_spec* fs, const char* s_in)
{
  struct sockaddr_in lsin, rsin;
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
      vlan = strtok(remainder, ",");
      vlan = strchr(vlan, '=');
      ++vlan;
      if( ! strlen(vlan) )
        goto out;
      TRY(ef_filter_spec_set_vlan(fs, atoi(vlan)));

      remainder = strtok(NULL, "");
      if( remainder == NULL )
        goto out;
    }

    if( strchr(remainder, ',') ) {
      hostport = strtok(remainder, ",");
      remainder = strtok(NULL, "");
      TRY(hostport_parse(&lsin, hostport));
      TRY(hostport_parse(&rsin, remainder));
      TRY(ef_filter_spec_set_ip4_full(fs, protocol, lsin.sin_addr.s_addr,
                                      lsin.sin_port, rsin.sin_addr.s_addr,
                                      rsin.sin_port));
      rc = 0;
    }
    else {
      TRY(hostport_parse(&lsin, strtok(remainder, ",")));
      TRY(ef_filter_spec_set_ip4_local(fs, protocol, lsin.sin_addr.s_addr,
                                       lsin.sin_port));
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
      vlan = strtok(remainder, ",");
      vlan = strchr(vlan, '=');
      ++vlan;
      if( ! strlen(vlan) )
        goto out;
      vlan_id = atoi(vlan);

      remainder = strtok(NULL, "");
      if( remainder == NULL )
        goto out;
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
