/*
** Copyright 2005-2012  Solarflare Communications Inc.
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

#ifndef __ONLOAD_HW_FILTER_H__
#define __ONLOAD_HW_FILTER_H__


struct tcp_helper_resource_s;

#define OO_HW_PORT_ALL ((unsigned) -1)

extern void oo_hw_filter_clear(struct oo_hw_filter* oofilter);
extern void oo_hw_filter_init(struct oo_hw_filter* oofilter);
extern int oo_hw_filter_set(struct oo_hw_filter* oofilter,
                            struct tcp_helper_resource_s* trs, int,
                            unsigned saddr, int sport,
                            unsigned daddr, int dport,
                            unsigned hwport_mask);
extern void oo_hw_filter_move(struct oo_hw_filter* oofilter,
                              struct tcp_helper_resource_s* new_stack);


#endif  /* __ONLOAD_HW_FILTER_H__ */
