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

#ifndef __OOF_TPROXY_IPPROTO_H__
#define __OOF_TPROXY_IPPROTO_H__


static const ci_uint8 oof_tproxy_ipprotos[] ={IPPROTO_ICMP, IPPROTO_IGMP,
                                              IPPROTO_UDP};
#define OOF_TPROXY_IPPROTO_FILTER_COUNT (sizeof(oof_tproxy_ipprotos) /       \
                                         sizeof(oof_tproxy_ipprotos[0]))

#define OOF_TPROXY_GLOBAL_FILTER_COUNT OOF_TPROXY_IPPROTO_FILTER_COUNT


#endif  /* __TPROXY_IPPROTO_IMPL_H__ */
