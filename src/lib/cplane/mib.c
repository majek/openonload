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

#include <ci/tools.h>

#include <onload/hash_ipv6.h>
#include <cplane/mib.h>

size_t cp_init_mibs(void* romem, struct cp_mibs* mibs)
{
  uintptr_t ptr = (uintptr_t)romem;
  int i;

  ptr += sizeof(struct cp_tables_dim);
  mibs->version = (void*)ptr;
  ptr += sizeof(cp_version_t);
  mibs->dump_version = (void*)ptr;
  ptr += sizeof(cp_version_t);
  mibs->idle_version = (void*)ptr;
  ptr += sizeof(cp_version_t);
  mibs->oof_version = (void*)ptr;
  ptr += sizeof(cp_version_t);
  mibs->fwd = (void*)ptr;
  ptr += sizeof(struct cp_fwd_row) * (mibs->dim->fwd_mask + 1);
  mibs->fwd_prefix = (void*)ptr;
  ptr += sizeof(ci_uint64) * CP_FWD_PREFIX_NUM;

  /* second mib frame shares the above tables */
  mibs[1] = mibs[0];

  /* frame specific mib state */
  for( i = 0; i < 2; ++i ) {
    mibs[i].llap_version = (void*)ptr;
    ptr += sizeof(cp_version_t);
    mibs[i].hwport = (void*)ptr;
    ptr += sizeof(struct cp_hwport_row) * mibs->dim->hwport_max;
    mibs[i].llap = (void*)ptr;
    ptr += sizeof(cicp_llap_row_t) * mibs->dim->llap_max;
    mibs[i].ipif = (void*)ptr;
    ptr += sizeof(cicp_ipif_row_t) * mibs->dim->ipif_max;
    mibs[i].ip6if = (void*)ptr;
    ptr += sizeof(cicp_ip6if_row_t) * mibs->dim->ip6if_max;
  }
  return ptr - (uintptr_t)romem;
}

static inline int ci_rot_r(ci_uint32 i, int n)
{
  n = n & 0x1f;
  /* gcc-4.8 recognizes it and converts to the "roll" instruction,
   * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=57157 .
   * "i << (32-n)" has undefinded behaviour for n==0. */
  return (i >> n) | (i << ((-n) & 31));
}

static cicp_mac_rowid_t
__cp_fwd_find_row(struct cp_mibs* mib, struct cp_fwd_key* key,
                  struct cp_fwd_key* match)
{
  cicp_mac_rowid_t hash1 = onload_hash1(AF_INET, mib->dim->fwd_mask,
                                        &key->dst, key->ifindex,
                                        &key->src, key->tos, 0);
  /* As a future optimisation we could skip calculating hash2 until we
   * know it's needed. */
  cicp_mac_rowid_t hash2 = cplane_hash2(AF_INET, &key->dst, key->ifindex,
                                        &key->src, key->tos);
  cicp_mac_rowid_t hash = hash1;
  int iter = 0;

  do {
    struct cp_fwd_row* fwd = cp_get_fwd_by_id(mib, hash);
    if( fwd->use == 0 )
      return CICP_MAC_ROWID_BAD;
    if( cp_fwd_key_match(fwd, match) )
      return hash;
    hash = (hash + hash2) & mib->dim->fwd_mask;
  } while( ++iter < (mib->dim->fwd_mask >> 2) );

  return CICP_MAC_ROWID_BAD;
}

cicp_mac_rowid_t
cp_fwd_find_row(struct cp_mibs* mib, struct cp_fwd_key* key)
{
  return __cp_fwd_find_row(mib, key, key);
}

cicp_mac_rowid_t
__cp_fwd_find_match(struct cp_mibs* mib, struct cp_fwd_key* key,
                    ci_uint64 src_prefs_in, ci_uint64 dst_prefs)
{
  ci_uint64 src_prefs;
  ci_uint8 src_pref, dst_pref;
  struct cp_fwd_key k = *key;

  /* We must check entries with large destination prefixes (/32 for IPv4)
   * first to ensure we get correct PMTU information.  All other prefixes
   * are equally good.
   */
  for( ; dst_prefs != 0; dst_prefs &= ~(1ull << dst_pref) ) {
    dst_pref = cp_get_largest_prefix(dst_prefs);
    k.dst = key->dst & cp_prefixlen2bitmask(dst_pref);

    for( src_prefs = src_prefs_in;
         src_prefs != 0;
         src_prefs &= ~(1ull << src_pref) ) {
      cicp_mac_rowid_t id;

      src_pref = cp_get_largest_prefix(src_prefs);
      k.src = key->src & cp_prefixlen2bitmask(src_pref);

      id = __cp_fwd_find_row(mib, &k, key);
      if( id != CICP_ROWID_BAD )
        return id;
    }
  }

  return CICP_ROWID_BAD;
}


int cp_get_acceleratable_llap_count(struct cp_mibs* mib)
{
  int count = 0;
  int rowid;

  for( rowid = 0; rowid < mib->dim->llap_max; ++rowid ) {
    if( cicp_llap_row_is_free(&mib->llap[rowid]) )
      break;
    if( mib->llap[rowid].rx_hwports != 0 )
      ++count;
  }

  return count;
}


int cp_get_acceleratable_ifindices(struct cp_mibs* mib, ci_ifid_t* ifindices,
                                   int max_count)
{
  int count = 0;
  int rowid;

  for( rowid = 0; rowid < mib->dim->llap_max && count < max_count; ++rowid ) {
    if( cicp_llap_row_is_free(&mib->llap[rowid]) )
      break;
    if( mib->llap[rowid].rx_hwports != 0 )
      ifindices[count++] = mib->llap[rowid].ifindex;
  }

  return count;
}


/* Returns the row index in the llap of a row with the matching ifindex and
 * hwports values. -1 if none is found. This is a helper for
 * cp_get_hwport_ifindex() */
static int
ci_find_ifindex_hwports(struct cp_mibs* mib, ci_ifid_t ifindex,
                        cicp_hwport_mask_t hwports)
{
  int rowid;
  for( rowid = 0; rowid < mib->dim->llap_max; ++rowid ) {
    if( cicp_llap_row_is_free(&mib->llap[rowid]) )
      break;
    if( mib->llap[rowid].ifindex == ifindex
        && mib->llap[rowid].rx_hwports == hwports )
      return rowid;
  }
  return -1;
}


/* Returns the ifindex of the 'best' interface for using hwport. Used by zf
 * to find the interface to use for ef_vi underneath bonds, vlans, etc.
 * The caller is responsible for performing a version-check before and after
 * this function is called; see oo_cp_get_hwport_ifindex(). */
ci_ifid_t cp_get_hwport_ifindex(struct cp_mibs* mib, ci_hwport_id_t hwport)
{
  int rowid;
  cicp_hwport_mask_t hwports = cp_hwport_make_mask(hwport);
  ci_ifid_t id = CI_IFID_BAD;

  for( rowid = 0; rowid < mib->dim->llap_max; ++rowid ) {
    if( cicp_llap_row_is_free(&mib->llap[rowid]) )
      break;
    /* The mapping of interfaces to hwport is complicated by the existence of
     * bonds, VLANs, MACVLANs and so on.  But we can define "the" interface for
     * an hwport to be the one that maps to precisely that hwport and that is
     * not a higher-level interface (i.e. ifindex == vlan_ifindex).
     * This fails when a bond contains only one interface; we fix that by
     * avoiding bond masters explicitly. It is also possible to create a
     * container with no access to the underlying interface; we choose a
     * somewhat-arbitrary 'next-best' in that case since we have no information
     * on what the true underlying interface would be. */
    if( mib->llap[rowid].rx_hwports == hwports
        && ! (mib->llap[rowid].encap.type & CICP_LLAP_TYPE_BOND) ) {
      if( mib->llap[rowid].ifindex == mib->llap[rowid].vlan_ifindex )
        return mib->llap[rowid].ifindex;

      /* This row might be a second-best match, but if we can also see a row
       * which is definitely less-derived than this one then we should prefer
       * that row. */
      if( ci_find_ifindex_hwports(mib, mib->llap[rowid].vlan_ifindex,
                                  hwports) < 0 )
        id = mib->llap[rowid].ifindex;
    }
  }

  return id;
}
