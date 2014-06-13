/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
#include "efch.h"
#include <ci/efrm/vi_set.h>
#include <ci/efrm/vi_allocation.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/efrm_port_sniff.h>
#include <ci/efrm/efrm_filter.h>
#include <ci/efch/op_types.h>
#include "char_internal.h"
#include "filter_list.h"

#include <driver/linux_net/driverlink_api.h>


static int
vi_set_rm_alloc(ci_resource_alloc_t* alloc_,
                ci_resource_table_t* priv_opt,
                efch_resource_t* rs, int intf_ver_id)
{
  struct efch_vi_set_alloc* alloc = &alloc_->u.vi_set;
  struct efrm_client *client;
  struct efrm_vi_set* vi_set;
  struct efrm_pd* pd;
  unsigned vi_props;
  int rc;

  if( intf_ver_id >= 1 && alloc->in_pd_fd >= 0 ) {
    struct efrm_resource* rs;
    rc = efch_lookup_rs(alloc->in_pd_fd, alloc->in_pd_rs_id,
                        EFRM_RESOURCE_PD, &rs);
    if( rc < 0 ) {
      EFCH_ERR("%s: ERROR: could not find PD fd=%d id="EFCH_RESOURCE_ID_FMT
               " rc=%d", __FUNCTION__, alloc->in_pd_fd,
               EFCH_RESOURCE_ID_PRI_ARG(alloc->in_pd_rs_id), rc);
      goto fail1;
    }
    pd = efrm_pd_from_resource(rs);
    client = rs->rs_client;
    efrm_client_add_ref(client);
  }
  else {
    rc = efrm_client_get(alloc->in_ifindex, NULL, NULL, &client);
    if( rc != 0 ) {
      EFCH_ERR("%s: ERROR: ifindex=%d not found rc=%d",
               __FUNCTION__, alloc->in_ifindex, rc);
      goto fail1;
    }
    rc = efrm_pd_alloc(&pd, client, NULL/*vf_opt*/, 0/*phys_addr_mode*/);
    if( rc != 0 ) {
      EFCH_ERR("%s: ERROR: efrm_pd_alloc(ifindex=%d) failed (rc=%d)",
               __FUNCTION__, alloc->in_ifindex, rc);
      goto fail2;
    }
  }

  vi_props = 0;
  rc = efrm_vi_set_alloc(pd, alloc->in_min_n_vis, vi_props, &vi_set);
  if( rc != 0 )
    goto fail3;

  efrm_client_put(client);
  efrm_pd_release(pd);
  efch_filter_list_init(&rs->vi_set.fl);
  rs->rs_base = efrm_vi_set_to_resource(vi_set);
  return 0;


 fail3:
  efrm_pd_release(pd);
 fail2:
  efrm_client_put(client);
 fail1:
  return rc;
}


static void vi_set_rm_free(efch_resource_t *rs)
{
  struct efrm_vi_set *vi_set = efrm_vi_set_from_resource(rs->rs_base);

  efch_filter_list_free(rs->rs_base, &rs->vi_set.fl);
  /* Remove any sniff config we may have set up. */
  efrm_port_sniff(rs->rs_base, 0, 0, efrm_vi_set_get_rss_context(vi_set));
}


static int
vi_set_mmap_not_supported(struct efrm_resource* ors, unsigned long* bytes,
                          void* opaque, int* map_num, unsigned long* offset,
                          int index)
{
  return -EINVAL;
}


static void
vi_set_rm_dump(struct efrm_resource* ors, ci_resource_table_t *priv_opt,
               const char *line_prefix)
{
}


static int
vi_set_rm_rsops(efch_resource_t* rs, ci_resource_table_t* priv_opt,
                ci_resource_op_t* op, int* copy_out
                CI_BLOCKING_CTX_ARG(ci_blocking_ctx_t bc))
{
  unsigned flags = 0;
  struct efrm_vi_set *vi_set = efrm_vi_set_from_resource(rs->rs_base);
  int rss = efrm_vi_set_num_vis(vi_set) > 1;
  int rss_context = efrm_vi_set_get_rss_context(vi_set);

  int rc;
  switch(op->op) {
    case CI_RSOP_PT_SNIFF:
      rc = efrm_port_sniff(rs->rs_base, op->u.pt_sniff.enable,
                           op->u.pt_sniff.promiscuous, rss_context);
      break;
    case CI_RSOP_FILTER_DEL:
      rc = efch_filter_list_op_del(rs->rs_base, &rs->vi_set.fl, op);
      break;
    case CI_RSOP_FILTER_BLOCK_KERNEL:
      rc = efch_filter_list_op_block(rs->rs_base, &rs->vi_set.fl, op);
      break;
    default:
      if( rss )
        flags |= (unsigned) EFX_FILTER_FLAG_RX_RSS;
      rc = efch_filter_list_op_add(rs->rs_base, &rs->vi_set.fl, op, copy_out,
                                  flags, rss_context == -1 ?
                                  EFX_FILTER_RSS_CONTEXT_DEFAULT : rss_context);
  }

  return rc;
}


efch_resource_ops efch_vi_set_ops = {
  .rm_alloc  = vi_set_rm_alloc,
  .rm_free   = vi_set_rm_free,
  .rm_mmap   = vi_set_mmap_not_supported,
  .rm_nopage = NULL,
  .rm_dump   = vi_set_rm_dump,
  .rm_rsops  = vi_set_rm_rsops,
};


