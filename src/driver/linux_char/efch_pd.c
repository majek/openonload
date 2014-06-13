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

#include <ci/efrm/efrm_client.h>
#include <ci/efrm/vf_resource.h>
#include "efch.h"
#include <ci/efch/op_types.h>
#include <ci/efrm/pd.h>
#include "char_internal.h"


static int
pd_rm_alloc(ci_resource_alloc_t* alloc_, ci_resource_table_t* priv_opt,
            efch_resource_t* ch_rs, int intf_ver_id)
{
  struct efch_pd_alloc *alloc = &alloc_->u.pd;
  struct efrm_client *client = NULL;
  struct efrm_vf *vf = NULL;
  struct efrm_pd *pd_rs;
  int rc, phys_mode;

  if ((rc = efrm_client_get(alloc->in_ifindex, NULL, NULL, &client)) < 0) {
    EFCH_ERR("%s: ERROR: ifindex=%d rc=%d", __FUNCTION__,
             alloc->in_ifindex, rc);
    goto out;
  }
  if (alloc->in_flags & (EFCH_PD_FLAG_VF | EFCH_PD_FLAG_VF_OPTIONAL)) {
    if ((rc = efrm_vf_resource_alloc(client, NULL, &vf)) < 0 &&
        !(alloc->in_flags & EFCH_PD_FLAG_VF_OPTIONAL)) {
      EFCH_NOTICE("%s: could not allocate VF", __FUNCTION__);
      goto out;
    }
  }
  if ((alloc->in_flags & EFCH_PD_FLAG_PHYS_ADDR) && vf == NULL &&
      ci_geteuid() != 0) {
    EFCH_ERR("%s: ERROR: not permitted to use phys mode", __FUNCTION__);
    rc = -EPERM;
    goto out;
  }
  phys_mode = (alloc->in_flags & EFCH_PD_FLAG_PHYS_ADDR) != 0;

  rc = efrm_pd_alloc(&pd_rs, client, vf, phys_mode);
 out:
  if (client != NULL)
    efrm_client_put(client);
  if (vf != NULL)
    efrm_vf_resource_release(vf);
  if (rc == 0)
    ch_rs->rs_base = efrm_pd_to_resource(pd_rs);
  return rc;
}


efch_resource_ops efch_pd_ops = {
  .rm_alloc = pd_rm_alloc,
  .rm_free = NULL,
  .rm_mmap = NULL,
  .rm_nopage = NULL,
  .rm_dump = NULL,
  .rm_rsops = NULL,
  .rm_mmap_bytes = NULL,
};
