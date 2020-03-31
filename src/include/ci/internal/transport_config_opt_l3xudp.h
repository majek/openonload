/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* Changes to the CI_CFG_* options needed to support the L3XUDP and
 * related features with diagnostics
 */

#ifndef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_L3XUDP_H__
#define __CI_INTERNAL_TRANSPORT_CONFIG_OPT_L3XUDP_H__

/* Use default values for the most of options: */
#include <ci/internal/transport_config_opt_extra.h>

/* Enable IPv6 */
#undef CI_CFG_IPV6
#define CI_CFG_IPV6 1

/* Support for custom overlay encapsulation.  See task69716.
 */
#undef CI_CFG_L3XUDP
#define CI_CFG_L3XUDP                     1



/* TCP TOA option support, default to off */
#undef CI_CFG_TCP_TOA
#define CI_CFG_TCP_TOA 1

/* Decluster on unpostponed signal (task79148). */
#undef CI_CFG_DECLUSTER
#define CI_CFG_DECLUSTER 1


#endif /* __CI_INTERNAL_TRANSPORT_CONFIG_OPT_L3XUDP_H__ */
