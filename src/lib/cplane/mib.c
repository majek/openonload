/*
** Copyright 2005-2018  Solarflare Communications Inc.
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

#include <onload/hash.h>
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
    mibs[i].hwport = (void*)ptr;
    ptr += sizeof(struct cp_hwport_row) * mibs->dim->hwport_max;
    mibs[i].llap = (void*)ptr;
    ptr += sizeof(cicp_llap_row_t) * mibs->dim->llap_max;
    mibs[i].ipif = (void*)ptr;
    ptr += sizeof(cicp_ipif_row_t) * mibs->dim->ipif_max;
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
  cicp_mac_rowid_t hash1 = onload_hash1(mib->dim->fwd_mask,
                                        key->dst, key->ifindex,
                                        key->src, key->tos, 0);
  /* As a future optimisation we could skip calculating hash2 until we
   * know it's needed. */
  cicp_mac_rowid_t hash2 = cplane_hash2(key->dst, key->ifindex,
                                        key->src, key->tos);
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
cp_fwd_find_match(struct cp_mibs* mib, struct cp_fwd_key* key)
{
  ci_uint64 src_prefs, dst_prefs;
  ci_uint8 src_pref, dst_pref;
  struct cp_fwd_key k = *key;

  /* We must check dst/32 entries first to ensure we get correct PMTU
   * information.  All other prefixes are equally good.
   */
  for( dst_prefs = mib->fwd_prefix[CP_FWD_PREFIX_DST];
       dst_prefs != 0;
       dst_prefs &= ~(1ull << dst_pref) ) {
    dst_pref = ci_ffs64(dst_prefs) - 1;
    k.dst = key->dst & cp_prefixlen2bitmask(dst_pref);

    for( src_prefs = mib->fwd_prefix[CP_FWD_PREFIX_SRC];
         src_prefs != 0;
         src_prefs &= ~(1ull << src_pref) ) {
      cicp_mac_rowid_t id;

      src_pref = ci_ffs64(src_prefs) - 1;
      k.src = key->src & cp_prefixlen2bitmask(src_pref);

      id = __cp_fwd_find_row(mib, &k, key);
      if( id != CICP_ROWID_BAD )
        return id;
    }
  }

  return CICP_ROWID_BAD;
}
