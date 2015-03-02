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
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2008/09/10
** Description: Onload nic management.
** </L5_PRIVATE>
\**************************************************************************/

#include <ci/internal/ip.h>
#include <onload/nic.h>
#include <ci/efhw/efhw_types.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/licensing.h>
#include <ci/efch/op_types.h>
#include <ci/driver/efab/hardware.h>
#include <onload/cplane.h>
#include <onload/tcp_driver.h>

#include <linux/rtnetlink.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
# define DEV_GET_BY_NAME(n) dev_get_by_name(n)
#else
# define DEV_GET_BY_NAME(n) dev_get_by_name(&init_net, (n))
#endif

struct oo_nic_black_white_list oo_nic_white_list = {
  .bwl_list_type = OO_NIC_WHITELIST,
};

struct oo_nic_black_white_list oo_nic_black_list = {
  .bwl_list_type = OO_NIC_BLACKLIST,
};


/* This array can be modified as a result of: 
 * - interfaces up/down via driverlink (rtnl lock already held)
 * - module parameter changes for black/white list
 *
 * It is used from 
 * - tcp_filters.c but always with fm_outer_lock mutex
 * - stack/cluster creation to find interfaces
 * 
 * NIC removal will not interfer with filter code because filter state
 * is removed (with fm_outer_lock mutex) before oo_nic entry removed.
 */

struct oo_nic oo_nics[CI_CFG_MAX_REGISTER_INTERFACES];
int oo_n_nics;
int oo_nic_whitelist_not_empty;


/* Returns a copy of str while eliminating superfluous whitespace
 * characters.
 */
static char* sanitise_string_copy(const char* str)
{
  int i, j = 0, add_space = 0;
  int len = strlen(str);
  char* ret = kmalloc(len + 1, GFP_KERNEL);
  if( ! ret )
    return NULL;

  for( i = 0; i < len; ++i ) {
    ci_assert_le(j, i);
    if( isspace(str[i]) ) {
      if( add_space ) {
        ret[j++] = ' ';
        add_space = 0;
      }
    }
    else {
      ret[j++] = str[i];
      add_space = 1;
    }
  }
  if( j == 0 || add_space )
    ret[j] = '\0';
  else
    ret[j - 1] = '\0';
  return ret;
}


static void cplane_add(struct oo_nic* onic)
{
  int oo_nic_i = onic - oo_nics;
  ci_hwport_id_t hwport = CI_HWPORT_ID(oo_nic_i);
  cicp_encap_t encapsulation;

  cicp_hwport_add_nic(&CI_GLOBAL_CPLANE, hwport);

  encapsulation.type = CICP_LLAP_TYPE_SFC;
  encapsulation.vlan_id = 0;
  cicp_llap_set_hwport(&CI_GLOBAL_CPLANE,
                       efrm_client_get_ifindex(onic->efrm_client),
                       hwport, &encapsulation);
}


static void cplane_remove(struct oo_nic* onic)
{
  cicp_llap_set_hwport(&CI_GLOBAL_CPLANE,
                       efrm_client_get_ifindex(onic->efrm_client),
                       CI_HWPORT_ID_BAD, NULL);
  cicp_hwport_remove_nic(&CI_GLOBAL_CPLANE, CI_HWPORT_ID(onic - oo_nics));
}


static void __oo_nic_black_white_list_update(const char* name, int list_type)
{
  int i, max = sizeof(oo_nics) / sizeof(oo_nics[0]);
  struct net_device* dev = DEV_GET_BY_NAME(name);
  if( dev != NULL ) {
    for( i = 0; i < max; ++i ) {
      if( oo_nics[i].efrm_client != NULL ) {
        if( efrm_client_get_ifindex(oo_nics[i].efrm_client) == 
            dev->ifindex ) {
          oo_nics[i].black_white_list |= list_type;
          break;
        }
      }
    }
    dev_put(dev);
  }
}


/* Update oo_nics->black_white_list state.  "buf_const" must be NULL
 * or NULL terminated. */
static int oo_nic_black_white_list_update(const char* buf_const, int list_type)
{
  int i, buf_len;
  char *buf, *buf_orig = NULL;
  int max = sizeof(oo_nics) / sizeof(oo_nics[0]);
  int bytes_consumed = 0;
  char* next_name;

  CI_DEBUG(ASSERT_RTNL());

  /* First reset black/white list */
  for( i = 0; i < max; ++i )
    oo_nics[i].black_white_list &=~ list_type;
  if( list_type == OO_NIC_WHITELIST )
    oo_nic_whitelist_not_empty = 0;

  if( buf_const != NULL && (buf_len = strlen(buf_const)) != 0 ) {
    /* Take a copy of the string, so we can replace ' ' with '\0' */
    buf = buf_orig = kmalloc(buf_len + 1, GFP_KERNEL);
    if( ! buf )
      return -ENOMEM;
    memcpy(buf, buf_const, buf_len + 1);

    if( list_type == OO_NIC_WHITELIST )
      oo_nic_whitelist_not_empty = 1;

    /* Now update with the new entries */
    do {
      next_name = strnchr(buf, strlen(buf), ' ');
      if( next_name != NULL ) {
        /* replace space with null */
        *next_name = '\0';
        bytes_consumed += (next_name - buf) + 1;
        /* move next_name to character after space, if any */
        if( bytes_consumed < buf_len )
          ++next_name;
      }
      __oo_nic_black_white_list_update(buf, list_type);
      buf = next_name;
    } while( next_name != NULL );
  }

  if( buf_orig != NULL )
    kfree(buf_orig);
  return 0;
}


/* This function checks whether a NIC is licensed for Onload, and sets
 * NIC_FLAG_ONLOAD_UNSUPPORTED if not. Otherwise, and in all cases on Falcon
 * architectures, it does not change whether the flag is set.
 *
 * The function is not necessary for the enforcement of the licensing
 * restrictions as stack creation would fail subsequently in any case, but it
 * allows unlicensed NICs to be screened out so that setups with multiple NICs,
 * some licensed and some not, can function.
 */
static void oo_check_nic_licensed_for_onload(struct oo_nic* onic)
{
  struct efhw_nic* nic = efrm_client_get_nic(onic->efrm_client);
  int rc;
  int licensed;

  rc = efhw_nic_license_check(nic, CI_LCOP_CHALLENGE_FEATURE_ONLOAD, &licensed);

  if( !((rc == 0 && licensed) || rc == -EOPNOTSUPP) )
    nic->flags |= NIC_FLAG_ONLOAD_UNSUPPORTED;
}


struct oo_nic* oo_nic_add(struct efrm_client* efrm_client)
{
  struct oo_nic* onic;
  int i, max = sizeof(oo_nics) / sizeof(oo_nics[0]);
  int ifindex = efrm_client_get_ifindex(efrm_client);

  CI_DEBUG(ASSERT_RTNL());

  for( i = 0; i < max; ++i )
    if( (onic = &oo_nics[i])->efrm_client == NULL )
      break;
  if( i == max ) {
    ci_log("%s: NOT registering ifindex=%d (too many)", __FUNCTION__, ifindex);
    return NULL;
  }

  onic->efrm_client = efrm_client;
  onic->black_white_list = 0;

  ++oo_n_nics;
  ci_log("%s: ifindex=%d oo_index=%d", __FUNCTION__, ifindex, i);
  cplane_add(onic);

  oo_nic_black_white_list_update(oo_nic_white_list.bwl_val, OO_NIC_WHITELIST);
  oo_nic_black_white_list_update(oo_nic_black_list.bwl_val, OO_NIC_BLACKLIST);

  oo_check_nic_licensed_for_onload(onic);

  return onic;
}


void oo_nic_remove(struct oo_nic* onic)
{
  int ifindex = efrm_client_get_ifindex(onic->efrm_client);

  CI_DEBUG(ASSERT_RTNL());

  ci_log("%s: ifindex=%d oo_index=%d",
         __FUNCTION__, ifindex, (int) (onic - oo_nics));
  ci_assert(oo_n_nics > 0);
  ci_assert(onic->efrm_client != NULL);
  cplane_remove(onic);
  --oo_n_nics;
  onic->efrm_client = NULL;
}


struct oo_nic* oo_nic_find_ifindex(int ifindex)
{
  int i, max = sizeof(oo_nics) / sizeof(oo_nics[0]);

  CI_DEBUG(ASSERT_RTNL());

  for( i = 0; i < max; ++i )
    if( oo_nics[i].efrm_client != NULL &&
        efrm_client_get_ifindex(oo_nics[i].efrm_client) == ifindex )
      return &oo_nics[i];
  return NULL;
}


int oo_nic_hwport(struct oo_nic* onic)
{
  int oo_nic_i = onic - oo_nics;

  CI_DEBUG(ASSERT_RTNL());

  return CI_HWPORT_ID(oo_nic_i);
}


/* Update the global black/white lists when called from module
 * parameter.  Needs to handle arbitrary string input from user. */
int oo_nic_black_white_list_set(struct oo_nic_black_white_list* bwl,
                                const char* val)
{
  int rc;
  if( bwl->bwl_val )
    kfree(bwl->bwl_val);
  bwl->bwl_val = sanitise_string_copy(val);
  if( bwl->bwl_val == NULL )
    return -ENOMEM;
  rtnl_lock();
  rc = oo_nic_black_white_list_update(bwl->bwl_val, bwl->bwl_list_type);
  rtnl_unlock();
  return rc;
}


/* Copy the state in the global black/white lists.  Used by module
 * parameters to return state to user. */
int oo_nic_black_white_list_get(struct oo_nic_black_white_list* bwl, char* buf,
                                int buflen)
{
  int len;
  if( bwl->bwl_val != NULL ) {
    len = strlen(bwl->bwl_val) + 1;
    if( len < buflen ) {
      memcpy(buf, bwl->bwl_val, len);
      return len - 1;
    }
    else {
      memcpy(buf, bwl->bwl_val, buflen - 1);
      buf[buflen - 1] = '\0';
      return buflen - 1;
    }
  }
  else {
    return 0;
  }
}


/* Output the black_white_list state of all NICs for handling
 * /proc. */
int oo_nic_black_white_list_proc_get(struct seq_file* seq)
{
  int i;
  int max = sizeof(oo_nics) / sizeof(oo_nics[0]);
  int ifindex;
  struct net_device* dev;

  seq_printf(seq, "Intf\tWhite\tBlack\n");

  rtnl_lock();

  for( i = 0; i < max; ++i ) {
    if( oo_nics[i].efrm_client != NULL ) {
      ifindex = efrm_client_get_ifindex(oo_nics[i].efrm_client);
      dev = dev_get_by_index(&init_net, ifindex);
      if( dev != NULL ) {
        seq_printf(seq, "%s\t%c\t%c\n", dev->name,
                   oo_nics[i].black_white_list & OO_NIC_WHITELIST ? '+' : '-',
                   oo_nics[i].black_white_list & OO_NIC_BLACKLIST ? '+' : '-');
        dev_put(dev);
      }
    }
  }

  rtnl_unlock();
  
  return 0;
}


int oo_check_nic_suitable_for_onload(struct oo_nic* onic)
{
  struct efhw_nic *nic = efrm_client_get_nic(onic->efrm_client);

  if( onic->black_white_list & OO_NIC_BLACKLIST )
    return 0;

  if( oo_nic_whitelist_not_empty &&
      ! (onic->black_white_list & OO_NIC_WHITELIST) )
    return 0;

  if( nic->flags & NIC_FLAG_ONLOAD_UNSUPPORTED )
    return 0;

  /* Onload does not currently play well with packed stream firmware */
  return !(nic->flags & NIC_FLAG_PACKED_STREAM);
}
