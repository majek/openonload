/*
** Copyright 2005-2016  Solarflare Communications Inc.
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
#include <cplane/exported.h>
#include <onload/tcp_driver.h>
#include <onload/tcp_helper_fns.h>

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

struct oo_nic oo_nics[CPLANE_MAX_REGISTER_INTERFACES];
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
static void oo_nic_onload_licensing(struct oo_nic* onic)
{
  struct efhw_nic* nic = efrm_client_get_nic(onic->efrm_client);
  ci_hwport_id_t hwport = CI_HWPORT_ID(onic - oo_nics);
  int rc, licensed;

  rc = efhw_nic_license_check(nic, CI_LCOP_CHALLENGE_FEATURE_ONLOAD,
                              &licensed);

  if( !((rc == 0 && licensed) || rc == -EOPNOTSUPP) )
    nic->flags |= NIC_FLAG_ONLOAD_UNSUPPORTED;

  cicp_licensing_validate_signature(hwport, NULL, 0, 0, 0, NULL, NULL,
                                    !(nic->flags & NIC_FLAG_ONLOAD_UNSUPPORTED),
                                    &nic->devtype);
}


static void oo_nic_onload_v3_licensing(struct oo_nic* onic)
{
  uint8_t signature[EFRM_V3_LICENSE_CHALLENGE_SIGNATURE_LEN] = { 0 };
  char challenge[EFRM_V3_LICENSE_CHALLENGE_CHALLENGE_LEN];
  uint8_t base_mac[EFRM_V3_LICENSE_CHALLENGE_MACADDR_LEN];
  uint8_t v_mac[EFRM_V3_LICENSE_CHALLENGE_MACADDR_LEN];
  struct efhw_nic* nic = efrm_client_get_nic(onic->efrm_client);
  ci_hwport_id_t hwport = CI_HWPORT_ID(onic - oo_nics);
  uint64_t app_id = CI_LCOP_CHALLENGE_FEATURE_ONLOAD;
  uint32_t expiry, days;
  int rc;
  int licensed;

  rc = efhw_nic_v3_license_check(nic, app_id, &licensed);
  if( rc != 0 || ! licensed ) {
    nic->flags |= NIC_FLAG_ONLOAD_UNSUPPORTED;
    cicp_licensing_validate_signature(hwport, NULL, 0, 0, 0, NULL, NULL, 0,
                                      &nic->devtype);
    return;
  }

  nic->flags &= ~NIC_FLAG_ONLOAD_UNSUPPORTED;

  rc = cicp_licensing_get_challenge(hwport, challenge,
                                    EFRM_V3_LICENSE_CHALLENGE_CHALLENGE_LEN);
  if( rc != 0 ) {
    cicp_licensing_validate_signature(hwport, NULL, 0, 0, 0, NULL, NULL, 0,
                                      &nic->devtype);
    return;
  }
  efhw_nic_v3_license_challenge(nic, app_id, challenge,
                                &expiry, &days, signature, base_mac, v_mac);
  /* If efhw_nic_v3_license_challenge() fails, continue anyway:  the signature
   * validation will fail in cicp_licensing_validate_signature() below and the
   * interface will be marked as unlicensed. */

  cicp_licensing_validate_signature(hwport, signature, app_id, expiry, days,
                                    base_mac, v_mac, 0, &nic->devtype);
}


static void oo_check_nic_licensed_for_onload(struct oo_nic* onic)
{
  struct efhw_nic* nic = efrm_client_get_nic(onic->efrm_client);
  struct efhw_device_type* devtype = &nic->devtype;
  ci_hwport_id_t hwport = CI_HWPORT_ID(onic - oo_nics);

  if( cicp_licensing_has_state_been_set(hwport) )
    return;

  if( devtype->arch == EFHW_ARCH_EF10 && devtype->variant > 'A' )
    oo_nic_onload_v3_licensing(onic);
  else
    oo_nic_onload_licensing(onic);
}


/* Our responses to the pre- and post-reset notifications from the resource
 * driver have much in common with one another.  This function implements the
 * basic pattern. */
static void
oo_efrm_reset_hook_generic(struct efrm_client* client,
                           void impl_fn(ci_netif*, int intf_i))
{
  struct oo_nic* onic;
  ci_netif* ni;
  int hwport, intf_i;
  int ifindex = efrm_client_get_ifindex(client);
  ci_irqlock_state_t lock_flags;
  ci_dllink *link;

  if( (onic = oo_nic_find_ifindex(ifindex)) != NULL ) {
    hwport = onic - oo_nics;

    /* First of all, handle non-fully-created stacks.
     * Possibly, we'll process them twice: here and later, when they are
     * created and moved to all_stacks list.
     * There is almost no harm except for bug 33496, which is present
     * regardless of our behaviour here.
     */
    ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
    CI_DLLIST_FOR_EACH(link, &THR_TABLE.started_stacks) {
      tcp_helper_resource_t *thr;
      thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
      ni = &thr->netif;
      if( (intf_i = ni->hwport_to_intf_i[hwport]) >= 0 )
        impl_fn(ni, intf_i);
    }
    ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

    ni = NULL;
    while( iterate_netifs_unlocked(&ni) == 0 )
      if( (intf_i = ni->hwport_to_intf_i[hwport]) >= 0 )
        impl_fn(ni, intf_i);
  }
}

static void oo_efrm_reset_callback(struct efrm_client* client, void* arg)
{
  /* Schedule the reset work for the stack. */
  oo_efrm_reset_hook_generic(client, tcp_helper_reset_stack);
}

static void
oo_efrm_reset_suspend_callback(struct efrm_client* client, void* arg)
{
  /* Label each stack as needing reset, but don't schedule that reset yet. */
  oo_efrm_reset_hook_generic(client, tcp_helper_suspend_interface);
}

static struct efrm_client_callbacks oo_efrm_client_callbacks = {
  oo_efrm_reset_callback,
  oo_efrm_reset_suspend_callback,
};


struct oo_nic* oo_nic_add(int ifindex)
{
  struct oo_nic* onic;
  int i, max = sizeof(oo_nics) / sizeof(oo_nics[0]);
  struct efrm_client* efrm_client;
  int rc;

  CI_DEBUG(ASSERT_RTNL());

  rc = efrm_client_get(ifindex, &oo_efrm_client_callbacks, NULL, &efrm_client);
  if( rc != 0 )
    /* Resource driver doesn't know about this ifindex. */
    goto fail1;

  for( i = 0; i < max; ++i )
    if( (onic = &oo_nics[i])->efrm_client == NULL )
      break;
  if( i == max ) {
    ci_log("%s: NOT registering ifindex=%d (too many)", __FUNCTION__, ifindex);
    goto fail2;
  }

  onic->efrm_client = efrm_client;
  onic->black_white_list = 0;
  onic->oo_nic_flags = 0;

  ++oo_n_nics;
  ci_log("%s: ifindex=%d oo_index=%d", __FUNCTION__, ifindex, i);

  oo_nic_black_white_list_update(oo_nic_white_list.bwl_val, OO_NIC_WHITELIST);
  oo_nic_black_white_list_update(oo_nic_black_list.bwl_val, OO_NIC_BLACKLIST);

  oo_check_nic_licensed_for_onload(onic);

  return onic;

 fail2:
  efrm_client_put(efrm_client);
 fail1:
  return NULL;
}


static void oo_nic_remove(struct oo_nic* onic)
{
  int ifindex = efrm_client_get_ifindex(onic->efrm_client);

  CI_DEBUG(ASSERT_RTNL());

  ci_log("%s: ifindex=%d oo_index=%d",
         __FUNCTION__, ifindex, (int) (onic - oo_nics));
  ci_assert(oo_n_nics > 0);
  ci_assert(onic->efrm_client != NULL);
  --oo_n_nics;
  efrm_client_put(onic->efrm_client);
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
  bwl->bwl_val = sanitise_string_copy((val != NULL) ? val : "");
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


/* Tidies up all oo_nic state. Called at module unload. */
void oo_nic_shutdown(void)
{
  struct oo_nic* onic;

  rtnl_lock();

  for( onic = oo_nics;
       onic - oo_nics < sizeof(oo_nics) / sizeof(oo_nics[0]);
       ++onic )
    if( onic->efrm_client != NULL )
      oo_nic_remove(onic);

  rtnl_unlock();
}

