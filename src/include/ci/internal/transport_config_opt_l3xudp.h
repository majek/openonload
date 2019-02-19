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

/* Changes to the CI_CFG_* options needed to support the L3XUDP and
 * related features with diagnostics
 */

#ifndef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_L3XUDP_H__
#define __CI_INTERNAL_TRANSPORT_CONFIG_OPT_L3XUDP_H__

/* This build profile is based on the 'l3xudp-nodiag' profile
 */
#include <ci/internal/transport_config_opt_l3xudp-nodiag.h>


/* Turn on TCP metrics */
#undef CI_CFG_TCP_METRICS
#define CI_CFG_TCP_METRICS 1


#endif /* __CI_INTERNAL_TRANSPORT_CONFIG_OPT_L3XUDP_H__ */
