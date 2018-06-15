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
#include <onload/tcp_driver.h>
#include <onload/tcp_helper_fns.h>
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>

#include <linux/rtnetlink.h>


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

struct oo_nic oo_nics[CI_CFG_MAX_HWPORTS];
int oo_n_nics;

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
  onic->oo_nic_flags = 0;

  ++oo_n_nics;

  ci_log("%s: ifindex=%d oo_index=%d", __FUNCTION__, ifindex, i);

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

  return (oo_nic_i);
}


int oo_check_nic_suitable_for_onload(struct oo_nic* onic)
{
  struct efhw_nic *nic = efrm_client_get_nic(onic->efrm_client);

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

