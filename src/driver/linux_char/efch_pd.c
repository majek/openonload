/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/vf_resource.h>
#include "efch.h"
#include <ci/efch/op_types.h>
#include <ci/efrm/pd.h>
#include "char_internal.h"
#include <ci/efhw/efhw_types.h>


static int
pd_rm_alloc(ci_resource_alloc_t* alloc_, ci_resource_table_t* priv_opt,
            efch_resource_t* ch_rs, int intf_ver_id)
{
  struct efch_pd_alloc *alloc = &alloc_->u.pd;
  struct efrm_client *client = NULL;
  struct efhw_nic* nic;
  struct efrm_vf *vf = NULL;
  struct efrm_pd *pd_rs;
  int rc, phys_mode, hw_loopback;

  if ((rc = efrm_client_get(alloc->in_ifindex, NULL, NULL, &client)) < 0) {
    EFCH_ERR("%s: ERROR: ifindex=%d rc=%d", __FUNCTION__,
             alloc->in_ifindex, rc);
    goto out;
  }

  nic = efrm_client_get_nic(client);
  if ((alloc->in_flags & EFCH_PD_FLAG_RX_PACKED_STREAM) &&
      !(nic->flags & NIC_FLAG_PACKED_STREAM)) {
    EFCH_TRACE("%s: ERROR: Packed stream mode not available on ifindex=%d",
                __FUNCTION__, alloc->in_ifindex);
    rc = -EOPNOTSUPP;
    goto out;
  }

  /* Support for SRIOV VF was removed (see bug 84927). */
  if (alloc->in_flags & EFCH_PD_FLAG_VF) {
    EFCH_NOTICE("%s: VF requested, but there is no support for this", __FUNCTION__);
    rc = -ENODEV;
    goto out;
  }

  phys_mode = (alloc->in_flags & EFCH_PD_FLAG_PHYS_ADDR) != 0;
  if (phys_mode && vf == NULL &&
      (phys_mode_gid == -2 || (phys_mode_gid != -1 &&
			       ci_getgid() != phys_mode_gid))) {
    EFCH_ERR("%s: ERROR: not permitted to use phys mode", __FUNCTION__);
    rc = -EPERM;
    goto out;
  }

  hw_loopback = (alloc->in_flags & EFCH_PD_FLAG_MCAST_LOOP) != 0;
  rc = efrm_pd_alloc(&pd_rs, client, vf,
                     (phys_mode ? EFRM_PD_ALLOC_FLAG_PHYS_ADDR_MODE : 0) |
                     (hw_loopback ? EFRM_PD_ALLOC_FLAG_HW_LOOPBACK : 0) );
  if (rc < 0)
    goto out;

  if (alloc->in_flags & EFCH_PD_FLAG_VPORT) {
    if ((rc = efrm_pd_vport_alloc(pd_rs, alloc->in_vlan_id)) < 0) {
      EFCH_ERR("%s: ERROR: failed to allocate vport on ifindex=%d",
               __FUNCTION__, alloc->in_ifindex);
      efrm_pd_release(pd_rs);
      goto out;
    }
  }

 out:
  if (client != NULL)
    efrm_client_put(client);
  if (rc == 0) {
    if ((alloc->in_flags & EFCH_PD_FLAG_RX_PACKED_STREAM) != 0)
      efrm_pd_set_min_align(pd_rs, EFRM_PD_RX_PACKED_STREAM_MEMORY_ALIGNMENT);
    ch_rs->rs_base = efrm_pd_to_resource(pd_rs);
  }
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
