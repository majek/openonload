/*
** Copyright 2005-2015  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

/**************************************************************************\
 *//*! \file
   ** <L5_PRIVATE L5_SOURCE>
   ** \author  
   **  \brief  
   **   \date  
   **    \cop  (c) Level 5 Networks Limited.
   ** </L5_PRIVATE>
   *//*
       \**************************************************************************/
  
/*! \cidoxg_lib_ef */
#include <etherfabric/vi.h>
#include "ef_vi_internal.h"
#include "driver_access.h"
#include "logging.h"


enum ef_filter_type {
  EF_FILTER_MAC                 = 0x1,
  EF_FILTER_IP4                 = 0x2,
  EF_FILTER_ALL_UNICAST         = 0x4,
  EF_FILTER_ALL_MULTICAST       = 0x8,
  EF_FILTER_VLAN                = 0x10,
  EF_FILTER_MISMATCH_UNICAST    = 0x20,
  EF_FILTER_MISMATCH_MULTICAST  = 0x40,
  EF_FILTER_PORT_SNIFF          = 0x80,
  EF_FILTER_BLOCK_KERNEL        = 0x100,
  EF_FILTER_BLOCK_KERNEL_UNICAST  = 0x200,
  EF_FILTER_BLOCK_KERNEL_MULTICAST  = 0x400,
  EF_FILTER_TX_PORT_SNIFF       = 0x800,
};


/**********************************************************************
 * Initialise filter specs.
 */

void ef_filter_spec_init(ef_filter_spec *fs,
			 enum ef_filter_flags flags)
{
  fs->type = 0;
  fs->flags = flags;
}


int ef_filter_spec_set_ip4_local(ef_filter_spec *fs, int protocol,
				 unsigned host_be32, int port_be16)
{
  if (fs->type != 0 && fs->type != EF_FILTER_VLAN)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_IP4;
  fs->data[0] = protocol;
  fs->data[1] = host_be32;
  fs->data[2] = port_be16;
  fs->data[3] = 0;
  fs->data[4] = 0;
  return 0;
}


int ef_filter_spec_set_ip4_full(ef_filter_spec *fs, int protocol,
				unsigned host_be32, int port_be16,
				unsigned rhost_be32, int rport_be16)
{
  if (fs->type != 0 && fs->type != EF_FILTER_VLAN)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_IP4;
  fs->data[0] = protocol;
  fs->data[1] = host_be32;
  fs->data[2] = port_be16;
  fs->data[3] = rhost_be32;
  fs->data[4] = rport_be16;
  return 0;
}


int ef_filter_spec_set_vlan(ef_filter_spec *fs, int vlan_id)
{
  if (fs->type != 0 && fs->type != EF_FILTER_IP4 &&
      fs->type != EF_FILTER_MISMATCH_MULTICAST &&
      fs->type != EF_FILTER_MISMATCH_UNICAST)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_VLAN;
  fs->data[5] = vlan_id;
  return 0;
}


int ef_filter_spec_set_eth_local(ef_filter_spec *fs, int vlan_id,
				 const void *mac)
{
  if (fs->type != 0)
    return -EPROTONOSUPPORT;
  fs->type = EF_FILTER_MAC;
  fs->data[0] = vlan_id;
  memcpy(&fs->data[1], mac, 6);
  return 0;
}


int ef_filter_spec_set_unicast_all(ef_filter_spec *fs)
{
  if (fs->type != 0 )
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_ALL_UNICAST;
  return 0;
}


int ef_filter_spec_set_multicast_all(ef_filter_spec *fs)
{
  if (fs->type != 0 )
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_ALL_MULTICAST;
  return 0;
}


int ef_filter_spec_set_unicast_mismatch(ef_filter_spec *fs)
{
  if (fs->type != 0 && fs->type != EF_FILTER_VLAN)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_MISMATCH_UNICAST;
  return 0;
}


int ef_filter_spec_set_multicast_mismatch(ef_filter_spec *fs)
{
  if (fs->type != 0 && fs->type != EF_FILTER_VLAN)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_MISMATCH_MULTICAST;
  return 0;
}


int ef_filter_spec_set_port_sniff(ef_filter_spec *fs, int promiscuous)
{
  if (fs->type != 0)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_PORT_SNIFF;
  fs->data[0] = promiscuous;
  return 0;
}


int ef_filter_spec_set_tx_port_sniff(ef_filter_spec *fs)
{
  if (fs->type != 0)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_TX_PORT_SNIFF;
  return 0;
}


int ef_filter_spec_set_block_kernel(ef_filter_spec *fs)
{
  if (fs->type != 0)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_BLOCK_KERNEL;
  return 0;
}


int ef_filter_spec_set_block_kernel_multicast(ef_filter_spec *fs)
{
  if (fs->type != 0)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_BLOCK_KERNEL_MULTICAST;
  return 0;
}


int ef_filter_spec_set_block_kernel_unicast(ef_filter_spec *fs)
{
  if (fs->type != 0)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_BLOCK_KERNEL_UNICAST;
  return 0;
}


/**********************************************************************
 * Add and remove filters.
 */

static int ef_filter_add(ef_driver_handle dh, int resource_id,
			 const ef_filter_spec *fs,
			 ef_filter_cookie *filter_cookie_out)
{
  ci_resource_op_t op;
  int rc;

  op.id = efch_make_resource_id(resource_id);
  op.u.filter_add.flags =
    ( (fs->flags & EF_FILTER_FLAG_MCAST_LOOP_RECEIVE) ?
      CI_RSOP_FILTER_ADD_FLAG_MCAST_LOOP_RECEIVE : 0);
  switch (fs->type) {
  case EF_FILTER_IP4 | EF_FILTER_VLAN:
    op.op = CI_RSOP_FILTER_ADD_IP4_VLAN;
    op.u.filter_add.ip4.protocol = fs->data[0];
    op.u.filter_add.ip4.host_be32 = fs->data[1];
    op.u.filter_add.ip4.port_be16 = fs->data[2];
    op.u.filter_add.ip4.rhost_be32 = fs->data[3];
    op.u.filter_add.ip4.rport_be16 = fs->data[4];
    op.u.filter_add.mac.vlan_id = fs->data[5];
    break;
  case EF_FILTER_IP4:
    op.op = CI_RSOP_FILTER_ADD_IP4;
    op.u.filter_add.ip4.protocol = fs->data[0];
    op.u.filter_add.ip4.host_be32 = fs->data[1];
    op.u.filter_add.ip4.port_be16 = fs->data[2];
    op.u.filter_add.ip4.rhost_be32 = fs->data[3];
    op.u.filter_add.ip4.rport_be16 = fs->data[4];
    break;
  case EF_FILTER_MAC:
    op.op = CI_RSOP_FILTER_ADD_MAC;
    op.u.filter_add.mac.vlan_id = fs->data[0];
    memcpy(op.u.filter_add.mac.mac, &fs->data[1], 6);
    break;
  case EF_FILTER_ALL_UNICAST:
    op.op = CI_RSOP_FILTER_ADD_ALL_UNICAST;
    break;
  case EF_FILTER_ALL_MULTICAST:
    op.op = CI_RSOP_FILTER_ADD_ALL_MULTICAST;
    break;
  case EF_FILTER_MISMATCH_UNICAST | EF_FILTER_VLAN:
    op.op = CI_RSOP_FILTER_ADD_MISMATCH_UNICAST_VLAN;
    op.u.filter_add.mac.vlan_id = fs->data[5];
    break;
  case EF_FILTER_MISMATCH_UNICAST:
    op.op = CI_RSOP_FILTER_ADD_MISMATCH_UNICAST;
    break;
  case EF_FILTER_MISMATCH_MULTICAST | EF_FILTER_VLAN:
    op.op = CI_RSOP_FILTER_ADD_MISMATCH_MULTICAST_VLAN;
    op.u.filter_add.mac.vlan_id = fs->data[5];
    break;
  case EF_FILTER_MISMATCH_MULTICAST:
    op.op = CI_RSOP_FILTER_ADD_MISMATCH_MULTICAST;
    break;
  case EF_FILTER_PORT_SNIFF:
    op.op = CI_RSOP_PT_SNIFF;
    op.u.pt_sniff.enable = 1;
    op.u.pt_sniff.promiscuous = fs->data[0];
    break;
  case EF_FILTER_TX_PORT_SNIFF:
    op.op = CI_RSOP_TX_PT_SNIFF;
    op.u.tx_pt_sniff.enable = 1;
    break;
  case EF_FILTER_BLOCK_KERNEL:
    op.op = CI_RSOP_FILTER_ADD_BLOCK_KERNEL;
    break;
  case EF_FILTER_BLOCK_KERNEL_UNICAST:
    op.op = CI_RSOP_FILTER_ADD_BLOCK_KERNEL_UNICAST;
    break;
  case EF_FILTER_BLOCK_KERNEL_MULTICAST:
    op.op = CI_RSOP_FILTER_ADD_BLOCK_KERNEL_MULTICAST;
    break;
  default:
    return -EINVAL;
  }
  rc = ci_resource_op(dh, &op);
  if( rc == 0 && filter_cookie_out != NULL ) {
    /* SNIFF does not return an ID.  The
     * filter_id field is ignored when removing,
     * but let's set it to something that will not be
     * confused with a real ID
     */
    if( fs->type == EF_FILTER_PORT_SNIFF ||
        fs->type == EF_FILTER_TX_PORT_SNIFF )
      filter_cookie_out->filter_id = -1;
    else
      filter_cookie_out->filter_id = 
        op.u.filter_add.out_filter_id;
    filter_cookie_out->filter_type = fs->type;
  }
  return rc;
}


static int ef_filter_del(ef_driver_handle dh, int resource_id,
			 ef_filter_cookie *filter_cookie)
{
  ci_resource_op_t op;

  if( filter_cookie->filter_type == EF_FILTER_PORT_SNIFF ) {
    op.op = CI_RSOP_PT_SNIFF;
    op.id = efch_make_resource_id(resource_id);
    op.u.pt_sniff.enable = 0;
  }
  if( filter_cookie->filter_type == EF_FILTER_TX_PORT_SNIFF ) {
    op.op = CI_RSOP_TX_PT_SNIFF;
    op.id = efch_make_resource_id(resource_id);
    op.u.tx_pt_sniff.enable = 0;
  }
  else {
    op.op = CI_RSOP_FILTER_DEL;
    op.id = efch_make_resource_id(resource_id);
    op.u.filter_del.filter_id = filter_cookie->filter_id;
  }
  return ci_resource_op(dh, &op);
}


int ef_vi_filter_add(ef_vi *vi, ef_driver_handle dh, const ef_filter_spec *fs,
		     ef_filter_cookie *filter_cookie_out)
{
  if( ! vi->vi_clustered )
    return ef_filter_add(dh, vi->vi_resource_id,
                         fs, filter_cookie_out);
  ef_log("%s: WARNING: Ignored attempt to set a filter on a cluster",
         __FUNCTION__);
  return 0;
}


int ef_vi_filter_del(ef_vi *vi, ef_driver_handle dh,
		     ef_filter_cookie *filter_cookie)
{
  if( ! vi->vi_clustered )
    return ef_filter_del(dh, vi->vi_resource_id, filter_cookie);
  return 0;
}


int ef_vi_set_filter_add(ef_vi_set* vi_set, ef_driver_handle dh,
			 const ef_filter_spec* fs,
			 ef_filter_cookie *filter_cookie_out)
{
  return ef_filter_add(dh, vi_set->vis_res_id, fs, filter_cookie_out);
}


int ef_vi_set_filter_del(ef_vi_set* vi_set, ef_driver_handle dh,
			 ef_filter_cookie *filter_cookie)
{
  return ef_filter_del(dh, vi_set->vis_res_id, filter_cookie);
}
