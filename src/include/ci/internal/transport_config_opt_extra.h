/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_EXTRA_H__
#define __CI_INTERNAL_TRANSPORT_CONFIG_OPT_EXTRA_H__

/* Define default build-time profile */

/* Custom overlay encapsulation off (bug69716). */
#define CI_CFG_L3XUDP 0

/* TCP TOA option support off (bug76883). */
#define CI_CFG_TCP_TOA 0

/* Decluster on unpostponed signal (bug79148). */
#define CI_CFG_DECLUSTER 0

/* Disable IPv6 by default */
#undef CI_CFG_IPV6
#define CI_CFG_IPV6 0

/* Disable Berkeley Packet Filter program functionality
 * with Onload embedded implementation */
#define CI_CFG_BPF 0
#define CI_CFG_BPF_USERSPACE 0


#endif /* __CI_INTERNAL_TRANSPORT_CONFIG_OPT_EXTRA_H__ */
