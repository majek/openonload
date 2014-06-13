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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author djr
**  \brief Helpers for filter code.
**   \date 20090317
**    \cop (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __TCP_FILTERS_INTERNAL_H__
#define __TCP_FILTERS_INTERNAL_H__


#define FMT_PROTOCOL(p)    ((p) == IPPROTO_TCP ? "TCP":         \
                            (p) == IPPROTO_UDP ? "UDP" : "???")

#define FMT_PORT(p)        ((int) CI_BSWAP_BE16(p))

#define IP_FMT             CI_IP_PRINTF_FORMAT
#define IP_ARG(ip)         CI_IP_PRINTF_ARGS(&(ip))

#define IPPORT_FMT         IP_FMT":%d"
#define IPPORT_ARG(ip,p)   IP_ARG(ip), FMT_PORT(p)


#endif  /* __TCP_FILTERS_INTERNAL_H__ */
