/*
** Copyright 2005-2015  Solarflare Communications Inc.
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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  cgg
**  \brief  Control Plane operation definitions
**   \date  2005/07/07
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal_cplane_ops */

#ifndef __CI_INTERNAL_CPLANE_OPS2_H__
#define __CI_INTERNAL_CPLANE_OPS2_H__

#include <onload/verlock.h>


#if CI_CFG_TEAMING

#define CICP_HASH_STATE_FLAGS_IS_IP      0x1
#define CICP_HASH_STATE_FLAGS_IS_TCP_UDP 0x2
#define CICP_HASH_STATE_FLAGS_IS_FRAG    0x4

struct cicp_hash_state {
  int flags;
  ci_mac_addr_t src_mac;
  ci_mac_addr_t dst_mac;
  ci_ip_addr_t src_addr_be32;
  ci_ip_addr_t dst_addr_be32;
  ci_uint16 src_port_be16;
  ci_uint16 dst_port_be16;
};

ci_inline void cicp_layer2_hash(const cicp_bond_row_t *row,
                                struct cicp_hash_state *hs,
                                int *out_hash)
{
  *out_hash = (hs->src_mac[5] ^ hs->dst_mac[5]) % row->master.n_active_slaves;
}


ci_inline void cicp_layer23_hash(const cicp_bond_row_t *row,
                                 struct cicp_hash_state *hs,
                                 int *out_hash)
{
  /* TODO do we ever call this with non-IP traffic */
  if( hs->flags & CICP_HASH_STATE_FLAGS_IS_IP ) {
    *out_hash = 
      ((CI_BSWAP_BE32(hs->src_addr_be32 ^ hs->dst_addr_be32) & 0xffff) ^ 
       (hs->src_mac[5] ^ hs->dst_mac[5])) % row->master.n_active_slaves;
  }
  else
    cicp_layer2_hash(row, hs, out_hash);
}


ci_inline void cicp_layer34_hash(const cicp_bond_row_t *row,
                                 struct cicp_hash_state *hs,
                                 int *out_hash)
{
  /* TODO do we ever call this with non-IP traffic */
  if( hs->flags & CICP_HASH_STATE_FLAGS_IS_IP ) {
    if( !(hs->flags & CICP_HASH_STATE_FLAGS_IS_FRAG) &&
        (hs->flags & CICP_HASH_STATE_FLAGS_IS_TCP_UDP) ) {
      *out_hash = 
        (CI_BSWAP_BE16(hs->src_port_be16 ^ hs->dst_port_be16) ^
         (CI_BSWAP_BE32(hs->src_addr_be32 ^ hs->dst_addr_be32) & 0xffff))
        % row->master.n_active_slaves;
    } else
      *out_hash = (CI_BSWAP_BE32(hs->src_addr_be32 ^ hs->dst_addr_be32) & 0xffff)
        % row->master.n_active_slaves;
  }
  else
    cicp_layer2_hash(row, hs, out_hash);
}

#endif


#if CI_CFG_TEAMING
extern ci_hwport_id_t ci_hwport_bond_get(cicp_handle_t* cplane,
                                         int cplane_locked,
                                         const cicp_encap_t *encap, 
                                         ci_int16 id,
                                         struct cicp_hash_state *hs);
extern int ci_bond_get_hwport_list(cicp_handle_t* cplane, ci_ifid_t ifindex,
                               ci_int8 hwports[]);
#endif


ci_inline int ci_hwport_check_onload(ci_hwport_id_t hwport,
                                     const cicp_encap_t *encap)
{
  return ((hwport != CI_HWPORT_ID_BAD) ||
          (encap->type & CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT));
}

ci_inline void
cicp_mac_row_free(cicp_mac_row_t *row)
{   ci_verlock_write_start(&row->version);
}


ci_inline void
cicp_mac_row_allocate(cicp_mac_row_t *row)
{   ci_verlock_write_stop(&row->version);
}


ci_inline int /* bool */
cicp_mac_row_enter_requested(const cicp_mac_row_t *row)
{   return 0 != (row->use_enter & 0x8000);
}


ci_inline void
cicp_mac_row_enter_request(cicp_mac_row_t *row, int /* bool */see_me)
{   if (see_me)
        row->use_enter |= 0x8000;
    else
        row->use_enter &= 0x7FFF;
}


ci_inline ci_uint16
cicp_mac_row_usecount(const cicp_mac_row_t *row)
{   return row->use_enter & 0x7FFF;
}


ci_inline void
cicp_mac_row_usecount_inc(cicp_mac_row_t *row)
{   if ((row->use_enter & 0x7FFF) != 0x7FFF)
        row->use_enter++;
}


ci_inline void
cicp_mac_row_usecount_dec(cicp_mac_row_t *row)
{   row->use_enter--; /* must not be called when count is zero */
}


/*! the following should not be used unless a write lock has been
 *  obtained and no rows are being updated.
 */
ci_inline int /* bool */
cicp_mac_row_allocated(const cicp_mac_row_t *row)
{   return !ci_verlock_updating(&row->version);
}


ci_inline int
cicp_mac_mib_rows(const cicp_mac_mib_t *mact)
{   return (1 << mact->rows_ln2);
}


/* constant-preserving macro for determining size of kernel MAC MIB */ 
#define CICP_MAC_MIB_SIZE(_mact, _n) \
        (sizeof(*(_mact))+((_n)-1)*sizeof((_mact)->ipmac[0]))


ci_inline int /* bool */
cicp_fwd_row_hasnic(const cicp_ul_mibs_t* user, const cicp_fwd_row_t *row)
{
  return row->hwport != CI_HWPORT_ID_BAD;
}


ci_inline void
cicp_fwd_row_free(cicp_fwd_row_t *row)
{   row->destnet_ipset = CI_IP_ADDRSET_BAD;
}


ci_inline int /* bool */
cicp_fwd_row_allocated(const cicp_fwd_row_t *row)
{   return (row->destnet_ipset != CI_IP_ADDRSET_BAD);
}


ci_inline ci_ifid_t
cicp_fwd_hwport_to_base_ifindex(const cicp_ul_mibs_t* user,
                                ci_hwport_id_t hwport)
{
  return user->fwdinfo_utable->hwport_to_base_ifindex[hwport];
}


ci_inline void
cicp_bond_row_free(cicp_bond_row_t *row)
{
  row->type = CICP_BOND_ROW_TYPE_FREE;
}


ci_inline int /* bool */
cicp_bond_row_allocated(const cicp_bond_row_t *row)
{
  return (row->type != CICP_BOND_ROW_TYPE_FREE);
}



#endif  /* __CI_INTERNAL_CPLANE_OPS2_H__ */
