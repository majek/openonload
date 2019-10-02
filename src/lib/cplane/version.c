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

#include <cplane/cplane.h>

#include "cp_intf_ver.h"

#ifdef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_H__
#error "don't include ci/internal/transport_config_opt.h from binary-only code"
#endif


/* This will be statically linked into the cplane server */
oo_cp_version_check_t oo_cplane_api_version = {
  .in_cp_intf_ver = OO_CP_INTF_VER
};

#ifdef __KERNEL__
int oo_cp_check_version(struct ci_private_s* priv, void* arg)
{
  oo_cp_version_check_t* vc = arg;
  (void)vc;
  (void)priv;

  if( strnlen(vc->in_cp_intf_ver, CP_CHSUM_STR_LEN + 1) > CP_CHSUM_STR_LEN )
    return -EINVAL;

  if( strncmp(vc->in_cp_intf_ver, OO_CP_INTF_VER, CP_CHSUM_STR_LEN + 1) ) {
    ci_log("ERROR: user/driver cplane interface mismatch");
    ci_log("  user-interface: %s", vc->in_cp_intf_ver);
    ci_log("  driver-interface: %s", OO_CP_INTF_VER);
    return -ELIBACC;
  }

  return 0;
}
#endif
