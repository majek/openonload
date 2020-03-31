/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  dar
**  \brief  Helper function to print startup banner
**   \date  2019/08/05
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <ci/internal/ip.h>
#include <onload/version.h>

#ifndef __KERNEL__
static inline void ci_netif_log_startup_banner(ci_netif* ni, const char* verb,
                                               int check_expiry) {
  char license_msg[CP_STRING_LEN + 16] = "";
  char renewal_msg[CP_STRING_LEN + 16] = "";

  if( strlen(ni->cplane->mib->act_licensee->value) > 0 ) {
    snprintf(license_msg, sizeof(license_msg), ", licensed to %s",
             ni->cplane->mib->act_licensee->value);
  }

  if( strlen(ni->cplane->mib->act_renewal->value) > 0 ) {
    snprintf(renewal_msg, sizeof(renewal_msg), ", renewal date %s",
             ni->cplane->mib->act_renewal->value);
  }

  NI_LOG(ni, BANNER, "%s %s %s%s%s [%s]",
         verb,
         ni->cplane->mib->act_sku->value,
         ONLOAD_VERSION,
         license_msg,
         renewal_msg,
         ni->state->pretty_name);
  NI_LOG(ni, BANNER, ONLOAD_COPYRIGHT);

  if( check_expiry ) {
    if( *ni->cplane->mib->expired_activation_flags & CP_ACTIVATION_FLAG_ONLOAD )
      NI_LOG(ni, USAGE_WARNINGS,
             "The activation key has expired.  Please contact your sales "
             "representative to renew the activation file.");
  }
}
#endif
