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
  /* Special value for filter_id that marks this entry as a
   * block-kernel (and nothing else) filter,
   * This is only for legacy CI_RSOP_FILTER_BLOCK_KERNEL op, which does not
   * carry filter_id */
#define FILTER_ID_INDEPENDENT_BLOCK (-1)
#define FILTER_ID_WRAP INT_MAX
  int        filter_id;
  int        efrm_filter_id;
#define FILTER_FLAGS_BLOCK_UNICAST 1
#define FILTER_FLAGS_BLOCK_MULTICAST 2
#define FILTER_FLAGS_BLOCK_MASK \
        (FILTER_FLAGS_BLOCK_UNICAST | FILTER_FLAGS_BLOCK_MULTICAST)
#define FILTER_FLAGS_BLOCK_ALL \
        (FILTER_FLAGS_BLOCK_UNICAST | FILTER_FLAGS_BLOCK_MULTICAST)
#define FILTER_FLAGS_USES_EFRM_FILTER 4
  int        flags;
};


void efch_filter_list_init(struct efch_filter_list *fl)
{
  spin_lock_init(&fl->lock);
  ci_dllist_init(&fl->filters);
  fl->next_id = 1;
  fl->wrapped = 0;
}


static int efch_filter_flags_to_efrm(int flags)
{
  return
    ((flags & FILTER_FLAGS_BLOCK_UNICAST) ? EFRM_FILTER_BLOCK_UNICAST : 0) |
    ((flags & FILTER_FLAGS_BLOCK_MULTICAST) ? EFRM_FILTER_BLOCK_MULTICAST : 0);
}


static void efch_filter_destruct(struct efrm_resource *rs,
                                 struct filter *f)
{
    if( f->flags & FILTER_FLAGS_BLOCK_MASK )
      efrm_filter_block_kernel(rs->rs_client,
                               efch_filter_flags_to_efrm(f->flags), false);
    if( f->flags & FILTER_FLAGS_USES_EFRM_FILTER )
      efrm_filter_remove(rs->rs_client, f->efrm_filter_id);
}


static void efch_filter_delete(struct efrm_resource *rs,
                                 struct filter *f)
{
  efch_filter_destruct(rs, f);
  ci_free(f);
}


void efch_filter_list_free(struct efrm_resource *rs,
                                  struct efch_filter_list *fl)
{
  struct filter *f;

  /* Can't call efrm_filter_remove with spinlock held. */
  ci_assert( ! spin_is_locked(&fl->lock) );

  while (ci_dllist_not_empty(&fl->filters)) {
    f = container_of(ci_dllist_head(&fl->filters), struct filter, link);
    ci_dllist_remove(&f->link);
    efch_filter_delete(rs, f);
  }
}


static int efch_filter_list_add_block(struct efrm_resource *rs,
                                      struct efch_filter_list *fl)
{
  struct filter* f;
  int rc;
  if( (f = ci_alloc(sizeof(*f))) == NULL )
    return -ENOMEM;

  rc = efrm_filter_block_kernel(rs->rs_client, EFRM_FILTER_BLOCK_ALL, true);
  if( rc < 0 ) {
      efch_filter_delete(rs, f);
      return rc;
  }
  f->flags = EFRM_FILTER_BLOCK_ALL;
  f->filter_id = FILTER_ID_INDEPENDENT_BLOCK;

  spin_lock(&fl->lock);
  ci_dllist_put(&fl->filters, &f->link);
  spin_unlock(&fl->lock);

  return 0;
}


static int is_op_block_kernel_only(int op)
{
  return op == CI_RSOP_FILTER_ADD_BLOCK_KERNEL ||
         op == CI_RSOP_FILTER_ADD_BLOCK_KERNEL_UNICAST ||
         op == CI_RSOP_FILTER_ADD_BLOCK_KERNEL_MULTICAST;
}


int efch_filter_list_gen_id(struct efch_filter_list *fl)
{
  int filter_id;
  int initial_id;
  if( fl->next_id == FILTER_ID_WRAP ) {
    fl->next_id = 1;
    fl->wrapped = 1;
  }
  initial_id = filter_id = fl->next_id++;
  while( fl->wrapped ) {
    /* filter_id have once wrapped, 
     * and now every new id needs to be checked against collision */
    int is_id_free = 1;
    struct filter* f;
    CI_DLLIST_FOR_EACH2(struct filter, f, link, &fl->filters)
      if( filter_id == f->filter_id ) {
        is_id_free = 0;
        break;
      }
    if( is_id_free )
      break;
    if( fl->next_id == FILTER_ID_WRAP )
      fl->next_id = 1;
    filter_id = fl->next_id++;
    if( filter_id == initial_id )
      return -ENOENT;
  }
  return filter_id;
}


static int efch_filter_list_add(struct efrm_resource *rs,
                                struct efch_filter_list *fl,
                                struct efx_filter_spec *spec,
                                ci_resource_op_t* op, bool replace)
{
  struct filter* f;
  int rc;
  int block_flags = 0;

  if( op->u.filter_add.flags & CI_RSOP_FILTER_ADD_FLAG_REPLACE )
    replace = true;

  if( (f = ci_alloc(sizeof(*f))) == NULL )
    return -ENOMEM;

  f->flags = 0;

  if( ! is_op_block_kernel_only(op->op) ) {
    rc = efrm_filter_insert(rs->rs_client, spec, replace);
    if( rc < 0 ) {
      efch_filter_delete(rs, f);
      return rc;
    }
    f->efrm_filter_id = rc;
    f->flags |= FILTER_FLAGS_USES_EFRM_FILTER;
  }

  if( op->op == CI_RSOP_FILTER_ADD_BLOCK_KERNEL )
    block_flags = FILTER_FLAGS_BLOCK_ALL;
  else if( op->op == CI_RSOP_FILTER_ADD_ALL_UNICAST ||
           op->op == CI_RSOP_FILTER_ADD_ALL_UNICAST_VLAN ||
           op->op == CI_RSOP_FILTER_ADD_BLOCK_KERNEL_UNICAST )
    block_flags = FILTER_FLAGS_BLOCK_UNICAST;
  else if( op->op == CI_RSOP_FILTER_ADD_ALL_MULTICAST ||
           op->op == CI_RSOP_FILTER_ADD_ALL_MULTICAST_VLAN ||
           op->op == CI_RSOP_FILTER_ADD_BLOCK_KERNEL_MULTICAST )
    block_flags = FILTER_FLAGS_BLOCK_MULTICAST;

  if( block_flags ) {
    rc = efrm_filter_block_kernel(rs->rs_client,
                                  efch_filter_flags_to_efrm(block_flags),
                                  true);
    /* EOPNOTSUPP is OK because that means we're on a driver version
     * that doesn't need block feature to get correct unicast-all
     * multicast-all semantics */
    if( rc >= 0 )
        f->flags |= block_flags;
    else if( rc != -EOPNOTSUPP ) {
      efch_filter_delete(rs, f);
      return rc;
    }
  }

  spin_lock(&fl->lock);
  rc = efch_filter_list_gen_id(fl);
  if( rc >= 0 ) {
    f->filter_id = rc;
    ci_dllist_put(&fl->filters, &f->link);
  }
  spin_unlock(&fl->lock);

  if( rc < 0 ) {
    efch_filter_delete(rs, f);
    return rc;
  }

  op->u.filter_add.out_filter_id = f->filter_id;
  return 0;
}


int efch_filter_list_set_ip4(struct efx_filter_spec* spec,
                             ci_resource_op_t* op, int* replace_out)
{
  int rc;
  *replace_out = false;

  if( op->u.filter_add.ip4.rhost_be32 )
    rc = efx_filter_set_ipv4_full(spec, op->u.filter_add.ip4.protocol,
                                  op->u.filter_add.ip4.host_be32,
                                  op->u.filter_add.ip4.port_be16,
                                  op->u.filter_add.ip4.rhost_be32,
                                  op->u.filter_add.ip4.rport_be16);
  else
    rc = efx_filter_set_ipv4_local(spec, op->u.filter_add.ip4.protocol,
                                   op->u.filter_add.ip4.host_be32,
                                   op->u.filter_add.ip4.port_be16);
  return rc;
}


int efch_filter_list_set_ip4_vlan(struct efx_filter_spec* spec,
				  ci_resource_op_t* op, int* replace_out)
{
  int rc = efch_filter_list_set_ip4(spec, op, replace_out);
  if( rc < 0 )
    return rc;

  return efx_filter_set_eth_local(spec, op->u.filter_add.mac.vlan_id, NULL);
}


int efch_filter_list_set_mac(struct efx_filter_spec* spec,
                             ci_resource_op_t* op, int *replace_out)
{
  int vlan = op->u.filter_add.mac.vlan_id;
  *replace_out = false;

  if( vlan < 0 )
    vlan = EFX_FILTER_VID_UNSPEC;
  return efx_filter_set_eth_local(spec, vlan, op->u.filter_add.mac.mac);
}


int efch_filter_list_set_misc(struct efx_filter_spec* spec,
                              ci_resource_op_t* op,
                              int (*set_fn)(struct efx_filter_spec*),
                              int vlan_opt, int *replace_out)
{
  int rc;

#if EFX_DRIVERLINK_API_VERSION >= 5
  *replace_out = true;
  if( ! capable(CAP_NET_ADMIN) )
    return -EPERM;
  if( (rc = set_fn(spec)) < 0 )
    return rc;
  if( vlan_opt >= 0 )
    rc = efx_filter_set_eth_local(spec, vlan_opt, NULL);
  return rc;
#else
  ci_log("%s: Multicast-default filter not supported by this sfc driver",
         __FUNCTION__);
  return -ENOPROTOOPT;
#endif
}


int efch_filter_list_del(struct efrm_resource *rs,
                         struct efch_filter_list *fl,
                         int filter_id)
{
  struct filter* f;
  int rc = -EINVAL;

  /* Need spinlock to manipulate filter list */
  spin_lock(&fl->lock);
  CI_DLLIST_FOR_EACH2(struct filter, f, link, &fl->filters)
    if( f->filter_id == filter_id ) {
      ci_dllist_remove(&f->link);
      rc = 0;
      break;
    }
  spin_unlock(&fl->lock);

  /* Now spinlock is released can call potentially blocking filter remove */
  if( rc == 0 )
    efch_filter_delete(rs, f);

  return rc;
}


int efch_filter_list_op_add(struct efrm_resource *rs,
                            struct efch_filter_list *fl, ci_resource_op_t *op,
                            int *copy_out, unsigned efx_filter_flags,
                            int rss_context)
{
  int rc;
  int replace;
  struct efx_filter_spec spec;
  int need_spec = ! is_op_block_kernel_only(op->op);

  if( op->u.filter_add.flags & CI_RSOP_FILTER_ADD_FLAG_MCAST_LOOP_RECEIVE )
    efx_filter_flags |= EFX_FILTER_FLAG_TX;

  if( need_spec ) {
    efx_filter_init_rx(&spec, EFX_FILTER_PRI_REQUIRED,
                       EFX_FILTER_FLAG_RX_SCATTER | efx_filter_flags,
                       rs->rs_instance);

    if( efx_filter_flags & EFX_FILTER_FLAG_RX_RSS )
      spec.rss_context = rss_context;
  }

  *copy_out = 1;

  switch(op->op) {
  case CI_RSOP_FILTER_ADD_IP4:
    rc = efch_filter_list_set_ip4(&spec, op, &replace);
    break;
  case CI_RSOP_FILTER_ADD_IP4_VLAN:
    rc = efch_filter_list_set_ip4_vlan(&spec, op, &replace);
    break;
  case CI_RSOP_FILTER_ADD_MAC:
    rc = efch_filter_list_set_mac(&spec, op, &replace);
    break;
  case CI_RSOP_FILTER_ADD_ALL_UNICAST:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_uc_def, -1,
                                   &replace);
    break;
  case CI_RSOP_FILTER_ADD_ALL_UNICAST_VLAN:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_uc_def,
                                   op->u.filter_add.mac.vlan_id, &replace);
    break;
  case CI_RSOP_FILTER_ADD_ALL_MULTICAST:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_mc_def, -1,
                                   &replace);
    break;
  case CI_RSOP_FILTER_ADD_ALL_MULTICAST_VLAN:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_mc_def,
                                   op->u.filter_add.mac.vlan_id, &replace);
    break;
#if EFX_DRIVERLINK_API_VERSION == 10
  case CI_RSOP_FILTER_ADD_MISMATCH_UNICAST:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_uc_mismatch, -1,
                                   &replace);
    break;
  case CI_RSOP_FILTER_ADD_MISMATCH_UNICAST_VLAN:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_uc_mismatch,
                                   op->u.filter_add.mac.vlan_id, &replace);
    break;
  case CI_RSOP_FILTER_ADD_MISMATCH_MULTICAST:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_mc_mismatch, -1,
                                   &replace);
    break;
  case CI_RSOP_FILTER_ADD_MISMATCH_MULTICAST_VLAN:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_mc_mismatch,
                                   op->u.filter_add.mac.vlan_id, &replace);
    break;
#else
  case CI_RSOP_FILTER_ADD_MISMATCH_UNICAST:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_uc_def, -1,
                                   &replace);
    break;
  case CI_RSOP_FILTER_ADD_MISMATCH_UNICAST_VLAN:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_uc_def,
                                   op->u.filter_add.mac.vlan_id, &replace);
    break;
  case CI_RSOP_FILTER_ADD_MISMATCH_MULTICAST:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_mc_def, -1,
                                   &replace);
    break;
  case CI_RSOP_FILTER_ADD_MISMATCH_MULTICAST_VLAN:
    rc = efch_filter_list_set_misc(&spec, op, efx_filter_set_mc_def,
                                   op->u.filter_add.mac.vlan_id, &replace);
  case CI_RSOP_FILTER_ADD_BLOCK_KERNEL:
  case CI_RSOP_FILTER_ADD_BLOCK_KERNEL_UNICAST:
  case CI_RSOP_FILTER_ADD_BLOCK_KERNEL_MULTICAST:
    if( ! capable(CAP_NET_ADMIN) )
      rc = -EPERM;
    else
      rc = 0;
    break;
#endif
  default:
    rc = -EOPNOTSUPP;
    break;
  }

  if( rc >= 0 )
    rc = efch_filter_list_add(rs, fl, &spec, op, replace);

  return rc;
}

int efch_filter_list_op_del(struct efrm_resource *rs,
                            struct efch_filter_list *fl, ci_resource_op_t *op)
{
    return efch_filter_list_del(rs, fl, op->u.filter_del.filter_id);
}


int efch_filter_list_op_block(struct efrm_resource *rs,
                                     struct efch_filter_list *fl,
                                     ci_resource_op_t *op)
{
  if( ! capable(CAP_NET_ADMIN) )
    return -EPERM;
  if( op->u.block_kernel.block)
    return efch_filter_list_add_block(rs, fl);
  else
    return efch_filter_list_del(rs, fl, FILTER_ID_INDEPENDENT_BLOCK);
}
