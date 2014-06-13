/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
** Copyright 2005-2014  Solarflare Communications Inc.
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

#include "efvi_sfw.h"

#include <net/if.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>


struct pkt_buf* pkt_buf_from_id(struct vi* vi, int pkt_buf_i)
{
  assert((unsigned) pkt_buf_i < (unsigned) vi->pkt_bufs_n);
  return (void*) ((char*) vi->pkt_bufs + pkt_buf_i * PKT_BUF_SIZE);
}


void pkt_buf_free(struct pkt_buf* pkt_buf)
{
  struct vi* vi = pkt_buf->vi_owner;
  assert(pkt_buf->n_refs == 0);
  pkt_buf->next = vi->free_pkt_bufs;
  vi->free_pkt_bufs = pkt_buf;
  ++vi->free_pkt_bufs_n;
}


void pkt_buf_release(struct pkt_buf* pkt_buf)
{
  assert(pkt_buf->n_refs > 0);
  if( --pkt_buf->n_refs == 0 )
    pkt_buf_free(pkt_buf);
}


static void pkt_buf_init(struct vi* vi, int pkt_buf_i)
{
  struct pkt_buf* pkt_buf;
  pkt_buf = pkt_buf_from_id(vi, pkt_buf_i);
  pkt_buf->vi_owner = vi;
  pkt_buf->addr[vi->net_if->id] =
    ef_memreg_dma_addr(&vi->memreg, pkt_buf_i * PKT_BUF_SIZE);
  pkt_buf->id = pkt_buf_i;
  pkt_buf->n_refs = 0;
  pkt_buf_free(pkt_buf);
}


void vi_refill_rx_ring(struct vi* vi)
{
#define REFILL_BATCH_SIZE  16
  struct pkt_buf* pkt_buf;
  int i;

  if( ef_vi_receive_space(&vi->vi) >= REFILL_BATCH_SIZE &&
      vi->free_pkt_bufs_n >= REFILL_BATCH_SIZE ) {
    for( i = 0; i < REFILL_BATCH_SIZE; ++i ) {
      pkt_buf = vi->free_pkt_bufs;
      vi->free_pkt_bufs = vi->free_pkt_bufs->next;
      --vi->free_pkt_bufs_n;
      assert(pkt_buf->n_refs == 0);
      pkt_buf->n_refs = 1;
      ef_vi_receive_init(&vi->vi, pkt_buf->addr[vi->net_if->id] + RX_DMA_OFF,
                         pkt_buf->id);
    }
    ef_vi_receive_push(&vi->vi);
  }
}


static void vi_init_pktbufs(struct vi* vi)
{
  /* Allocate memory for packet buffers -- enough to fill the RX ring.
   * Round-up to multiple of 2M and allocate 2M aligned memory to give best
   * chance of getting huge pages on systems with transparent hugepage
   * support.
   */
  int _2meg = (1 << 21);
  int i, pbuf_size = ef_vi_receive_capacity(&vi->vi) * PKT_BUF_SIZE;
  pbuf_size = ROUND_UP(pbuf_size, _2meg);
  TEST(posix_memalign(&vi->pkt_bufs, _2meg, pbuf_size) == 0);
  vi->pkt_bufs_n = pbuf_size / PKT_BUF_SIZE;

  /* Register memory for DMA, and initialise the meta-data. */
  TRY(ef_memreg_alloc(&vi->memreg, vi->dh, &vi->net_if->pd, vi->net_if->dh,
                      vi->pkt_bufs, pbuf_size));
  vi->free_pkt_bufs_n = 0;
  for( i = 0; i < vi->pkt_bufs_n; ++i )
    pkt_buf_init(vi, i);
}


static void vi_init_layout(struct vi* vi, enum ef_vi_flags flags)
{
  const ef_vi_layout_entry* layout;
  int len, i, found_minor_ticks_offset = 0, found_frame_offset = 0;

  TRY(ef_vi_receive_query_layout(&vi->vi, &layout, &len));
  for( i = 0; i < len; ++i ) {
    if( layout[i].evle_type == EF_VI_LAYOUT_FRAME ) {
      vi->frame_off = layout[i].evle_offset;
      ++found_frame_offset;
    }
    if( layout[i].evle_type == EF_VI_LAYOUT_MINOR_TICKS ) {
      vi->minor_ticks_off = layout[i].evle_offset;
      ++found_minor_ticks_offset;
    }
  }

  if( (found_minor_ticks_offset == 0) &&
      ((flags & EF_VI_RX_TIMESTAMPS) != 0) ) {
    fprintf(stderr,
            "Didn't find minor ticks offset in ef_vi_receive_query_layout.\n");
    exit(1);
  }
  if( (found_frame_offset == 0) ) {
    fprintf(stderr,
            "Didn't find frame offset in ef_vi_receive_query_layout.\n");
    exit(1);
  }

}


static struct vi* __vi_alloc(int vi_id, struct net_if* net_if,
                             int vi_set_instance, enum ef_vi_flags flags)
{
  struct vi* vi;

  vi = malloc(sizeof(*vi));
  vi->id = vi_id;
  vi->net_if = net_if;

  TRY(ef_driver_open(&vi->dh));
  if( vi_set_instance < 0 ) {
    TRY(ef_vi_alloc_from_pd(&vi->vi, vi->dh, &net_if->pd, net_if->dh,
                            -1, -1, -1, NULL, -1, flags));
  }
  else {
    TEST(net_if->vi_set_size > 0);
    TEST(vi_set_instance < net_if->vi_set_size);
    TRY(ef_vi_alloc_from_set(&vi->vi, vi->dh, &net_if->vi_set, net_if->dh,
                             vi_set_instance, -1, -1, -1, NULL, -1, flags));
  }
  vi_init_pktbufs(vi);
  vi_init_layout(vi, flags);
  vi_refill_rx_ring(vi);

  return vi;
}


struct vi* vi_alloc(int vi_id, struct net_if* net_if, enum ef_vi_flags flags)
{
  return __vi_alloc(vi_id, net_if, -1, flags);
}


struct vi* vi_alloc_from_set(int vi_id, struct net_if* net_if,
                             int vi_set_instance)
{
  return __vi_alloc(vi_id, net_if, vi_set_instance, 0);
}


int vi_send(struct vi* vi, struct pkt_buf* pkt_buf, int off, int len)
{
  int rc;
  rc = ef_vi_transmit(&vi->vi, pkt_buf->addr[vi->net_if->id] + off, len,
                      MK_TX_RQ_ID(pkt_buf->vi_owner->id, pkt_buf->id));
  if( rc == 0 )
    ++pkt_buf->n_refs;
  return rc;
}

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
    if( ! strncmp("mcastloop-rx,", remainder, strlen("mcastloop-rx,")) ) {
      ef_filter_spec_init(fs, EF_FILTER_FLAG_MCAST_LOOP_RECEIVE);
      strtok(remainder, ",");
      remainder = strtok(NULL, "");
    }
    if( ! strncmp("vid=", remainder, strlen("vid=")) ) {
      vlan = strtok(remainder, ",");
      remainder = strtok(NULL, "");
      if( ! vlan )
        goto out;
      vlan = strchr(vlan, '=');
      ++vlan;
      TRY(ef_filter_spec_set_vlan(fs, atoi(vlan)));
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
    vlan = strtok(NULL, ",");
    remainder = strtok(NULL, "");
    if( remainder == '\0' ) /* No vlan */
      remainder = vlan;
    else {
      if( strncmp("vid=", vlan, strlen("vid=")) )
        goto out;
      vlan = strchr(vlan, '=');
      ++vlan;
      vlan_id = atoi(vlan);
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
    TRY(ef_filter_spec_set_multicast_all(fs));
    if( strlen(type) != strlen(s_in) ) {
      remainder = strtok(NULL, "");
      if( ! (vlan = strchr(remainder, '=')) )
        goto out;
      ++vlan;
      TRY(ef_filter_spec_set_vlan(fs, atoi(vlan)));
    }
    rc = 0;
  }

  else if( ! strcmp("unicast-all", type) ) {
    TRY(ef_filter_spec_set_unicast_all(fs));
    if( strlen(type) != strlen(s_in) ) {
      remainder = strtok(NULL, "");
      if( ! (vlan = strchr(remainder, '=')) )
        goto out;
      ++vlan;
      TRY(ef_filter_spec_set_vlan(fs, atoi(vlan)));
    }
    rc = 0;
  }

  else if( ! strcmp("multicast-mis", type) ) {
    TRY(ef_filter_spec_set_multicast_mismatch(fs));
    if( strlen(type) != strlen(s_in) ) {
      remainder = strtok(NULL, "");
      if( ! (vlan = strchr(remainder, '=')) )
        goto out;
      ++vlan;
      TRY(ef_filter_spec_set_vlan(fs, atoi(vlan)));
    }
    rc = 0;
  }

  else if( ! strcmp("unicast-mis", type) ) {
    TRY(ef_filter_spec_set_unicast_mismatch(fs));
    if( strlen(type) != strlen(s_in) ) {
      remainder = strtok(NULL, "");
      if( ! (vlan = strchr(remainder, '=')) )
        goto out;
      ++vlan;
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
      if( ! strcmp("promisc", remainder) )
        TRY(ef_filter_spec_set_port_sniff(fs, 1));
      else if( ! strcmp("no-promisc", remainder) )
        TRY(ef_filter_spec_set_port_sniff(fs, 0));
      else
        TRY(-EINVAL);
    }
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


struct net_if* net_if_alloc(int net_if_id, const char* name, int rss_set_size)
{
  struct net_if* net_if = malloc(sizeof(*net_if));
  int ifindex;
  char dummy;

  if( (ifindex = if_nametoindex(name)) == 0 )
    if( sscanf(name, "%u%c", &ifindex, &dummy) != 1 )
      return NULL;
  net_if->name = strdup(name);
  TEST(net_if_id >= 0 && net_if_id < MAX_NET_IFS);
  net_if->id = net_if_id;
  net_if->ifindex = ifindex;
  if( ef_driver_open(&net_if->dh) < 0 )
    goto fail1;
  if( ef_pd_alloc(&net_if->pd, net_if->dh, net_if->ifindex, EF_PD_DEFAULT) < 0 )
    goto fail2;
  net_if->vi_set_size = rss_set_size;
  if( rss_set_size > 0 )
    TRY(ef_vi_set_alloc_from_pd(&net_if->vi_set, net_if->dh,
                                &net_if->pd, net_if->dh, rss_set_size));
  return net_if;

 fail2:
  ef_driver_close(net_if->dh);
 fail1:
  free(net_if);
  return NULL;
}


void net_if_map_vi_pool(struct net_if* net_if, struct vi* vi)
{
  struct pkt_buf* pkt_buf;
  ef_memreg memreg;
  int i;

  /* If this fails it means you've tried to map buffers into a protection
   * domain that has already mapped those buffers.
   */
  TEST(vi->net_if != net_if);

  TRY(ef_memreg_alloc(&memreg, net_if->dh, &net_if->pd, net_if->dh,
                      vi->pkt_bufs, vi->pkt_bufs_n * PKT_BUF_SIZE));
  for( i = 0; i < vi->pkt_bufs_n; ++i ) {
    pkt_buf = pkt_buf_from_id(vi, i);
    pkt_buf->addr[net_if->id] = ef_memreg_dma_addr(&memreg, i * PKT_BUF_SIZE);
  }
}
