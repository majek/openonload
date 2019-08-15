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

#ifndef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_EXTRA_H__
#define __CI_INTERNAL_TRANSPORT_CONFIG_OPT_EXTRA_H__

/* Define default build-time profile */

/* Custom overlay encapsulation off (bug69716). */
#define CI_CFG_L3XUDP 0

/* TCP TOA option support off (bug76883). */
#define CI_CFG_TCP_TOA 0

/* Decluster on unpostponed signal (bug79148). */
#define CI_CFG_DECLUSTER 0

#endif /* __CI_INTERNAL_TRANSPORT_CONFIG_OPT_EXTRA_H__ */
