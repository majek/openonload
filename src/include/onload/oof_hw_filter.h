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

#ifndef __ONLOAD_OOF_HW_FILTER_H__
#define __ONLOAD_OOF_HW_FILTER_H__


struct tcp_helper_resource_s;
struct tcp_helper_cluster_s;


struct oo_hw_filter {
  struct tcp_helper_resource_s* trs;
  struct tcp_helper_cluster_s*  thc;
  unsigned dlfilter_handle;
  int filter_id[CI_CFG_MAX_REGISTER_INTERFACES];
};


#endif  /* __ONLOAD_OOF_HW_FILTER_H__ */
