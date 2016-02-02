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

#ifndef __TCP_HELPER_RESOURCE_H__
#define __TCP_HELPER_RESOURCE_H__

struct vi_allocate_info {
  int try_rx_ts;
  int try_tx_ts;
  int retry_without_rx_ts;
  int retry_without_tx_ts;
  int wakeup_cpu_core;

  struct efrm_client *client;
  struct efrm_vi_set *vi_set;
  struct efrm_pd *pd;
  struct efrm_vf* vf;
  const char *name;
  unsigned ef_vi_flags;
  unsigned efhw_flags;
  unsigned oo_vi_flags;
  int evq_capacity;
  int txq_capacity;
  int rxq_capacity;
  int wakeup_channel;
  struct efrm_vi **virs;
  tcp_helper_cluster_t* cluster;
  unsigned vi_mem_mmap_bytes;
  unsigned vi_io_mmap_bytes;

  int release_pd;
  int log_resource_warnings;
  int intf_i;
};

#endif  /* __TCP_HELPER_RESOURCE_H__ */
