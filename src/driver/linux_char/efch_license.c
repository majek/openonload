/*
** Copyright 2005-2014  Solarflare Communications Inc.
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

#include "efch.h"
#include <ci/efch/op_types.h>
#include <ci/efhw/efhw_types.h>
#include "linux_char_internal.h"
#include "char_internal.h"
#include <ci/efrm/resource.h>
#include <ci/efrm/licensing.h>

int
efch_license_challenge(ci_resource_table_t* rt,
                       struct ci_license_challenge_op_s* op, int* copy_out
                       CI_BLOCKING_CTX_ARG(ci_blocking_ctx_t bc))
{
  int rc;
  struct efrm_resource *rs;
  struct efrm_license_challenge_s s;

  rc = efch_lookup_rs(op->fd, op->pd_id, EFRM_RESOURCE_PD, &rs);
  if( rc < 0 ) {
    EFCH_ERR("%s: ERROR: hwm=%d id="EFCH_RESOURCE_ID_FMT" rc=%d",
             __FUNCTION__, rt->resource_table_highwater,
             EFCH_RESOURCE_ID_PRI_ARG(op->pd_id), rc);
    goto done_no_ref;
  }

  EFCH_TRACE("%s: id="EFCH_RESOURCE_ID_FMT,
             __FUNCTION__, EFCH_RESOURCE_ID_PRI_ARG(op->pd_id));

  // Make sure that the API buffer lengths match
  if((CI_LCOP_CHALLENGE_CHALLENGE_LEN != EFRM_LICENSE_CHALLENGE_CHALLENGE_LEN) ||
     (CI_LCOP_CHALLENGE_SIGNATURE_LEN != EFRM_LICENSE_CHALLENGE_SIGNATURE_LEN)) {
    EFCH_ERR("%s: id="EFCH_RESOURCE_ID_FMT" mismatched challenge/sig "
             "lcop_chal=%d efhw_chal=%d lcop_sig=%d rfhw_sig=%d",
             __FUNCTION__, EFCH_RESOURCE_ID_PRI_ARG(op->pd_id),
             CI_LCOP_CHALLENGE_CHALLENGE_LEN,
             EFRM_LICENSE_CHALLENGE_CHALLENGE_LEN,
             CI_LCOP_CHALLENGE_SIGNATURE_LEN,
             EFRM_LICENSE_CHALLENGE_SIGNATURE_LEN);

    efrm_resource_release(rs);
    return -EFAULT;
  }

  s.feature = op->feature;
  memcpy(s.challenge, op->challenge,
         EFRM_LICENSE_CHALLENGE_CHALLENGE_LEN);

  rc = efrm_license_challenge(rs, &s);

  if(!rc) {
    op->expiry = s.expiry;
    memcpy(op->signature, s.signature,
           EFRM_LICENSE_CHALLENGE_SIGNATURE_LEN);
  }
  EFCH_TRACE("%s: id="EFCH_RESOURCE_ID_FMT" rc=%d",
             __FUNCTION__, EFCH_RESOURCE_ID_PRI_ARG(op->pd_id), rc);
  *copy_out = 1;

  efrm_resource_release(rs);
done_no_ref:
  return rc;
}
