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


#include <ci/efrm/resource.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/efrm_filter.h>
#include "efch.h"
#include <ci/efch/op_types.h>
#include <ci/driver/resource/linux_efhw_nic.h>
#include "filter_list.h"
#include <driver/linux_resource/linux_resource_internal.h>

struct filter {
  ci_dllink  link;
  int        filter_id;
};


void efch_filter_list_init(struct efch_filter_list *fl)
{
  spin_lock_init(&fl->lock);
  ci_dllist_init(&fl->filters);
}



static void __efch_filter_list_del(struct efrm_resource *rs, struct filter *f)
{
  struct efhw_nic* nic;
  ci_dllist_remove(&f->link);
  nic = efrm_client_get_nic(rs->rs_client);
  efx_dl_filter_remove(linux_efhw_nic(nic)->dl_device, f->filter_id);
  ci_free(f);
}


void efch_filter_list_free(struct efrm_resource *rs,
                                  struct efch_filter_list *fl)
{
  struct filter *f;
  while (ci_dllist_not_empty(&fl->filters)) {
    f = container_of(ci_dllist_head(&fl->filters), struct filter, link);
    __efch_filter_list_del(rs, f);
  }
}


static int efch_filter_list_add(struct efrm_resource *rs,
                                struct efch_filter_list *fl,
                                struct efx_filter_spec *spec,
                                ci_resource_op_t* op, bool replace)
{
  struct efhw_nic* nic;
  struct filter* f;
  int rc;

  if( op->u.filter_add.replace )
    replace = true;

  if( (f = ci_alloc(sizeof(*f))) == NULL )
    return -ENOMEM;
  nic = efrm_client_get_nic(rs->rs_client);
 
  rc = efrm_filter_insert (linux_efhw_nic(nic)->dl_device, spec, replace);
  if( rc < 0 ) {
    ci_free(f);
    return rc;
  }
  f->filter_id = rc;
  spin_lock(&fl->lock);
  ci_dllist_put(&fl->filters, &f->link);
  spin_unlock(&fl->lock);
  op->u.filter_add.out_filter_id = rc;
  return 0;
}


int efch_filter_list_add_ip4(struct efrm_resource *rs,
                             struct efch_filter_list *fl,
                             ci_resource_op_t* op, unsigned efx_filter_flags)
{
  struct efx_filter_spec spec;
  int rc;

  efx_filter_init_rx(&spec, EFX_FILTER_PRI_REQUIRED,
                     EFX_FILTER_FLAG_RX_SCATTER | efx_filter_flags,
                     rs->rs_instance);
  if( op->u.filter_add.ip4.rhost_be32 )
    rc = efx_filter_set_ipv4_full(&spec, op->u.filter_add.ip4.protocol,
                                  op->u.filter_add.ip4.host_be32,
                                  op->u.filter_add.ip4.port_be16,
                                  op->u.filter_add.ip4.rhost_be32,
                                  op->u.filter_add.ip4.rport_be16);
  else
    rc = efx_filter_set_ipv4_local(&spec, op->u.filter_add.ip4.protocol,
                                   op->u.filter_add.ip4.host_be32,
                                   op->u.filter_add.ip4.port_be16);
  return (rc < 0) ? rc : efch_filter_list_add(rs, fl, &spec, op, false);
}


int efch_filter_list_add_mac(struct efrm_resource *rs,
                             struct efch_filter_list *fl,
                             ci_resource_op_t* op, unsigned efx_filter_flags)
{
  int vlan = op->u.filter_add.mac.vlan_id;
  struct efx_filter_spec spec;
  int rc;

  efx_filter_init_rx(&spec, EFX_FILTER_PRI_REQUIRED,
                     EFX_FILTER_FLAG_RX_SCATTER | efx_filter_flags,
                     rs->rs_instance);
  if( vlan < 0 )
    vlan = EFX_FILTER_VID_UNSPEC;
  rc = efx_filter_set_eth_local(&spec, vlan, op->u.filter_add.mac.mac);
  return (rc < 0) ? rc : efch_filter_list_add(rs, fl, &spec, op, false);
}


int efch_filter_list_add_all_unicast(struct efrm_resource *rs,
                                     struct efch_filter_list *fl,
                                     ci_resource_op_t* op,
                                     unsigned efx_filter_flags)
{
  struct efx_filter_spec spec;
  int rc;

  efx_filter_init_rx(&spec, EFX_FILTER_PRI_REQUIRED,
                     EFX_FILTER_FLAG_RX_SCATTER | efx_filter_flags,
                     rs->rs_instance);
#if EFX_DRIVERLINK_API_VERSION >= 5
  rc = capable(CAP_NET_ADMIN) ? efx_filter_set_uc_def(&spec) : -EPERM;
#else
  ci_log("%s: Unicast-default filter not supported by this sfc driver",
         __FUNCTION__);
  rc = ENOPROTOOPT;
#endif
  return (rc < 0) ? rc : efch_filter_list_add(rs, fl, &spec, op, true);
}


int efch_filter_list_add_all_multicast(struct efrm_resource *rs,
                                       struct efch_filter_list *fl,
                                       ci_resource_op_t* op,
                                       unsigned efx_filter_flags)
{
  struct efx_filter_spec spec;
  int rc;

  efx_filter_init_rx(&spec, EFX_FILTER_PRI_REQUIRED,
                     EFX_FILTER_FLAG_RX_SCATTER | efx_filter_flags,
                     rs->rs_instance);
#if EFX_DRIVERLINK_API_VERSION >= 5
  rc = capable(CAP_NET_ADMIN) ? efx_filter_set_mc_def(&spec) : -EPERM;
#else
  ci_log("%s: Multicast-default filter not supported by this sfc driver",
         __FUNCTION__);
  rc = ENOPROTOOPT;
#endif
  return (rc < 0) ? rc : efch_filter_list_add(rs, fl, &spec, op, true);
}


int efch_filter_list_del(struct efrm_resource *rs,
                         struct efch_filter_list *fl,
                         int filter_id)
{
  struct filter* f;
  int rc = -EINVAL;

  spin_lock(&fl->lock);
  CI_DLLIST_FOR_EACH2(struct filter, f, link, &fl->filters)
    if( f->filter_id == filter_id ) {
      __efch_filter_list_del(rs, f);
      rc = 0;
      break;
    }
  spin_unlock(&fl->lock);
  return rc;
}


int efch_filter_list_op(struct efrm_resource *rs, struct efch_filter_list *fl,
                        ci_resource_op_t *op, int *copy_out,
                        unsigned efx_filter_flags)
{
  int rc;
  switch(op->op) {
  case CI_RSOP_FILTER_ADD_IP4:
    rc = efch_filter_list_add_ip4(rs, fl, op, efx_filter_flags);
    *copy_out = 1;
    break;
  case CI_RSOP_FILTER_ADD_MAC:
    rc = efch_filter_list_add_mac(rs, fl, op, efx_filter_flags);
    *copy_out = 1;
    break;
  case CI_RSOP_FILTER_ADD_ALL_UNICAST:
    rc = efch_filter_list_add_all_unicast(rs, fl, op, efx_filter_flags);
    *copy_out = 1;
    break;
  case CI_RSOP_FILTER_ADD_ALL_MULTICAST:
    rc = efch_filter_list_add_all_multicast(rs, fl, op, efx_filter_flags);
    *copy_out = 1;
    break;
  case CI_RSOP_FILTER_DEL:
    rc = efch_filter_list_del(rs, fl, op->u.filter_del.filter_id);
    break;
  default:
    rc = -EOPNOTSUPP;
    break;
  }
  return rc;
}
