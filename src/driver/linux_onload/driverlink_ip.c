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

/**************************************************************************\
*//*! \file driverlink_ip.c  Inter-driver communications for the IP driver
** <L5_PRIVATE L5_SOURCE>
** \author  gnb
**  \brief  Package - driver/efab	EtherFabric NIC driver
**   \date  2005/10/26
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*/

#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <linux/netfilter_ipv4.h>

#include <ci/internal/ip.h>
#include <onload/driverlink_filter.h>
#include <onload/cplane.h>
#include <driver/linux_net/driverlink_api.h>
#include <onload/linux_onload_internal.h>
#include <ci/internal/cplane_handle.h>
#include <onload/tcp_helper_fns.h>
#include <onload/nic.h>
#include <onload/oof_interface.h>
#include <ci/efrm/efrm_client.h>
#include "onload_internal.h"
#include "onload_kernel_compat.h"
#include <ci/driver/efab/hardware.h>


static int oo_use_vlans = 1;
module_param(oo_use_vlans, int, S_IRUGO);
MODULE_PARM_DESC(oo_use_vlans,
                 "Do use VLANs in Onload stack (on by default)");

static int oo_bond_poll_peak = (HZ/100);
module_param(oo_bond_poll_peak, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oo_bond_poll_peak,
                 "Period (in jiffies) between peak-rate polls of /sys "
                 "for bonding state synchronisation");

static int oo_bond_peak_polls = 20;
module_param(oo_bond_peak_polls, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oo_bond_peak_polls,
                 "Number of times to poll /sys at \"peak-rate\" before "
                 "reverting to base rate");


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
/* Define vlan_dev_real_dev() and vlan_dev_vlan_id()
 * if they are not defined. */
#ifndef VLAN_DEV_INFO
#define VLAN_DEV_INFO(netdev) vlan_dev_info(netdev)
#endif
#ifndef vlan_dev_real_dev
static inline struct net_device *
vlan_dev_real_dev(const struct net_device *dev)
{
	return VLAN_DEV_INFO(dev)->real_dev;
}
#endif
#ifndef vlan_dev_vlan_id
static inline u16 vlan_dev_vlan_id(const struct net_device *dev)
{
	return VLAN_DEV_INFO(dev)->vlan_id;
}
#endif
#endif


#if CI_CFG_TEAMING
# ifdef IFF_BONDING
#  define NETDEV_IS_BOND_MASTER(_dev)                                   \
  ((_dev->flags & (IFF_MASTER)) && (_dev->priv_flags & IFF_BONDING))
#  define NETDEV_IS_BOND(_dev)                                          \
  ((_dev->flags & (IFF_MASTER | IFF_SLAVE)) && (_dev->priv_flags & IFF_BONDING))
# else
#  define NETDEV_IS_BOND_MASTER(_dev) (_dev->flags & (IFF_MASTER))
#  define NETDEV_IS_BOND(_dev) (_dev->flags & (IFF_MASTER | IFF_SLAVE))
# endif
#else
# define NETDEV_IS_BOND_MASTER(_dev) 0
# define NETDEV_IS_BOND(_dev) 0
#endif


/* Check whether device may match software filters for Onload */
static inline int oo_nf_dev_match(const struct net_device *net_dev)
{
  if( net_dev->priv_flags & IFF_802_1Q_VLAN )
    net_dev = vlan_dev_real_dev(net_dev);

#if CI_CFG_TEAMING
  if( NETDEV_IS_BOND_MASTER(net_dev) )
    return 1;
#endif

  return efx_dl_netdev_is_ours(net_dev);
}

/* Find packet payload (whatever comes after the Ethernet header) */
static int oo_nf_skb_get_payload(struct sk_buff* skb, void** pdata, int* plen)
{
  if( skb_is_nonlinear(skb) ) {
    /* Look in the first page fragment */
    unsigned head_len = skb_headlen(skb);
    skb_frag_t* frag = &skb_shinfo(skb)->frags[0];

    if( skb_shinfo(skb)->frag_list || frag->page_offset < head_len )
      return 0;
    *pdata = skb_frag_address(frag) - head_len;
    *plen = frag->size + head_len;
    return 1;
  } else {
    *pdata = skb->data;
    *plen = skb->len;
    return 1;
  }
}

static unsigned int oo_netfilter_arp(
#ifdef EFRM_HAVE_NETFILTER_HOOK_OPS
                                    const struct nf_hook_ops* ops,
#else
                                    unsigned int hooknum,
#endif
#ifdef EFX_HAVE_NETFILTER_INDIRECT_SKB
                                     struct sk_buff** pskb,
#else
                                     struct sk_buff* skb,
#endif
                                     const struct net_device* indev,
                                     const struct net_device* outdev,
                                     int (*okfn)(struct sk_buff*))
{
#ifdef EFX_HAVE_NETFILTER_INDIRECT_SKB
  struct sk_buff* skb = *pskb;
#endif
  void* data;
  int len;

  if( oo_nf_dev_match(indev) &&
      oo_nf_skb_get_payload(skb, &data, &len) &&
      len >= sizeof(ci_ether_arp) ) {
    cicppl_handle_arp_pkt(&CI_GLOBAL_CPLANE,
                          (ci_ether_hdr*) skb_mac_header(skb),
                          (ci_ether_arp*) data,
                          indev->ifindex, indev->flags & IFF_SLAVE);
  }

  return NF_ACCEPT;
}


#ifndef CONFIG_NETFILTER
# error "OpenOnload requires that the kernel has CONFIG_NETFILTER enabled."
#endif


static struct nf_hook_ops oo_netfilter_arp_hook = {
  .hook = oo_netfilter_arp,
  .owner = THIS_MODULE,
#ifdef EFX_HAVE_NFPROTO_CONSTANTS
  .pf = NFPROTO_ARP,
#else
  .pf = NF_ARP,
#endif
  .hooknum = NF_ARP_IN,
};

static unsigned int oo_netfilter_ip(
#ifdef EFRM_HAVE_NETFILTER_HOOK_OPS
                                    const struct nf_hook_ops* ops,
#else
                                    unsigned int hooknum,
#endif
#ifdef EFX_HAVE_NETFILTER_INDIRECT_SKB
                                    struct sk_buff** pskb,
#else
                                    struct sk_buff* skb,
#endif
                                    const struct net_device* indev,
                                    const struct net_device* outdev,
                                    int (*okfn)(struct sk_buff*))
{
#ifdef EFX_HAVE_NETFILTER_INDIRECT_SKB
  struct sk_buff* skb = *pskb;
#endif
  void* data;
  int len;

  if( oo_nf_dev_match(indev) &&
      oo_nf_skb_get_payload(skb, &data, &len) &&
      efx_dlfilter_handler(indev->ifindex, efab_tcp_driver.dlfilter,
                           (const ci_ether_hdr*) skb_mac_header(skb),
                           data, len) ) {
    kfree_skb(skb);
    return NF_STOLEN;
  } else {
    return NF_ACCEPT;
  }
}

static struct nf_hook_ops oo_netfilter_ip_hook = {
  .hook = oo_netfilter_ip,
  .owner = THIS_MODULE,
#ifdef EFX_HAVE_NFPROTO_CONSTANTS
  .pf = NFPROTO_IPV4,
#else
  .pf = PF_INET,
#endif
#ifdef NF_IP_PRE_ROUTING
  .hooknum = NF_IP_PRE_ROUTING,
#else
  .hooknum = NF_INET_PRE_ROUTING,
#endif
  .priority = NF_IP_PRI_FIRST,
};


static void oo_efrm_reset_callback(struct efrm_client* client, void* arg)
{
  struct oo_nic* onic;
  ci_netif* ni;
  int hwport, intf_i;
  int ifindex = efrm_client_get_ifindex(client);
  ci_irqlock_state_t lock_flags;
  ci_dllink *link;

  if( (onic = oo_nic_find_ifindex(ifindex)) != NULL ) {
    hwport = onic - oo_nics;

    /* First of all, reset non-fully-created stacks.
     * Possibly, we'll reset them twice: here and later, when they are
     * created and moved to all_stacks list.
     * There is almost no harm except for bug 33496, which is present
     * regardless of our behaviour here.
     */
    ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
    CI_DLLIST_FOR_EACH(link, &THR_TABLE.started_stacks) {
      tcp_helper_resource_t *thr;
      thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
      ni = &thr->netif;
      /* We call tcp_helper_reset_stack, but it surely fails to get lock,
       * so we just set up flags here. */
      if( (intf_i = ni->hwport_to_intf_i[hwport]) >= 0 )
        tcp_helper_reset_stack(ni, intf_i);
    }
    ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

    ni = NULL;
    while( iterate_netifs_unlocked(&ni) == 0 )
      if( (intf_i = ni->hwport_to_intf_i[hwport]) >= 0 )
        tcp_helper_reset_stack(ni, intf_i);
  }
}

static struct efrm_client_callbacks oo_efrm_client_callbacks = {
  oo_efrm_reset_callback
};


/* This function will create an oo_nic if one hasn't already been created.
 *
 * There are two code paths whereby this function can be called multiple
 * times for the same device:
 *
 * - If the interface was IFF_UP when this driver was loaded, then
 *   oo_netdev_event() will call oo_netdev_may_add() before dl_probe is run,
 *   which will call oo_netdev_may_add() itself.
 *
 * - If stacks were present when oo_netdev_event() received NETDEV_GOING_DOWN,
 *   it won't have called oo_nic_remove(). A lter NETDEV_UP would then
 *   call oo_nic_add().
 */
static struct oo_nic *oo_netdev_may_add(const struct net_device *net_dev)
{
  struct efrm_client* efrm_client;
  struct efhw_nic* efhw_nic; 
  struct oo_nic* onic;
  int rc;

  BUG_ON(!netif_running(net_dev));

  onic = oo_nic_find_ifindex(net_dev->ifindex);

  if( onic == NULL ) {
    rc = efrm_client_get(net_dev->ifindex, &oo_efrm_client_callbacks, 
                         NULL, &efrm_client);
    if( rc != 0 )
      /* Resource driver doesn't know about this ifindex. */
      goto fail1;

    onic = oo_nic_add(efrm_client);
    if( onic == NULL ) {
      ci_log("%s: oo_nic_add(ifindex=%d) failed", __func__, net_dev->ifindex);
      goto fail2;
    }
  }

  if( net_dev->flags & IFF_UP ) {
    efhw_nic = efrm_client_get_nic(onic->efrm_client);
    oof_hwport_up_down(oo_nic_hwport(onic), 1,
                       efhw_nic->devtype.arch == EFHW_ARCH_EF10 ? 1:0,
                       efhw_nic->flags & NIC_FLAG_VLAN_FILTERS);
  }

  return onic;

 fail2:
  efrm_client_put(efrm_client);
 fail1:
  return NULL;
}

static void oo_netdev_remove(struct oo_nic *onic)
{
  struct efrm_client *efrm_client;

  efrm_client = onic->efrm_client;
  oo_nic_remove(onic);
  efrm_client_put(efrm_client);
}

static int oo_dl_probe(struct efx_dl_device* dl_dev,
                       const struct net_device* net_dev,
                       const struct efx_dl_device_info* dev_info,
                       const char* silicon_rev)
{
  struct oo_nic* onic = NULL;

#if EFX_DRIVERLINK_API_VERSION >= 8
  struct efx_dl_falcon_resources *res;

  efx_dl_for_each_device_info_matching(dev_info, EFX_DL_FALCON_RESOURCES,
                                       struct efx_dl_falcon_resources,
                                       hdr, res) {
    if( res->rx_usr_buf_size > FALCON_RX_USR_BUF_SIZE ) {
      ci_log("%s: ERROR: Net driver rx_usr_buf_size %u > %u", __func__,
             res->rx_usr_buf_size, FALCON_RX_USR_BUF_SIZE);
      return -1;
    }
  }
#endif

  if( netif_running(net_dev) ) {
    onic = oo_netdev_may_add(net_dev);
    if( onic == NULL )
      return -1;
  }
  dl_dev->priv = (void *)net_dev;
  return 0;
}


static void oo_dl_remove(struct efx_dl_device* dl_dev)
{
  struct net_device *net_dev = dl_dev->priv;
  struct oo_nic* onic;
  ci_irqlock_state_t lock_flags;

  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  if( ci_dllist_not_empty(&THR_TABLE.all_stacks) ) {
    ci_log("Driverlink unregistering but still stacks present");
    ci_assert(0);
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  onic = oo_nic_find_ifindex(net_dev->ifindex);
  if( onic != NULL )
    oo_netdev_remove(onic);
}


static void oo_dl_reset_suspend(struct efx_dl_device* dl_dev)
{
  ci_log("%s:", __FUNCTION__);
}


static void oo_dl_reset_resume(struct efx_dl_device* dl_dev, int ok)
{
  ci_log("%s:", __FUNCTION__);
}


static void oo_fixup_wakeup_breakage(int ifindex)
{
  /* This is needed after a hardware interface is brought up, and after an
   * MTU change.  When a netdev goes down, or the MTU is changed, the net
   * driver event queues are destroyed and brought back.  This can cause
   * wakeup events to get lost.
   *
   * NB. This should cease to be necessary once the net driver is changed
   * to keep event queues up when the interface goes down.
   */
  struct oo_nic* onic;
  ci_netif* ni = NULL;
  int hwport, intf_i;
  if( (onic = oo_nic_find_ifindex(ifindex)) != NULL ) {
    hwport = onic - oo_nics;
    while( iterate_netifs_unlocked(&ni) == 0 )
      if( (intf_i = ni->hwport_to_intf_i[hwport]) >= 0 )
        ci_bit_clear(&ni->state->evq_primed, intf_i);
  }
}


static void oo_netdev_up(struct net_device* netdev)
{
  struct oo_nic* onic;

  /* Does efrm own this device? */
  if( efrm_nic_present(netdev->ifindex) ) {
    oo_netdev_may_add(netdev);
    oo_fixup_wakeup_breakage(netdev->ifindex);
  }
  else {
    cicp_encap_t encap;

    encap.type = CICP_LLAP_TYPE_NONE;
    encap.vlan_id = 0;

#if CI_CFG_TEAMING
    if( NETDEV_IS_BOND_MASTER(netdev) ) {
      OO_DEBUG_BONDING(ci_log("Bond master %s UP", netdev->name));
      encap.type |= CICP_LLAP_TYPE_BOND;
    }
#endif

    if( oo_use_vlans && (netdev->priv_flags & IFF_802_1Q_VLAN) ) {
      encap.type |= CICP_LLAP_TYPE_VLAN;
      encap.vlan_id = vlan_dev_vlan_id(netdev);

      if( NETDEV_IS_BOND_MASTER(vlan_dev_real_dev(netdev)) )
        encap.type |= CICP_LLAP_TYPE_BOND;
    }

    if( encap.type != CICP_LLAP_TYPE_NONE ) {
#if CI_CFG_TEAMING
      if( encap.type & CICP_LLAP_TYPE_BOND ) {
        cicp_encap_t old_encap;
        ci_ifid_t master_ifindex;

        if( encap.type & CICP_LLAP_TYPE_VLAN ) {
          struct net_device *real_dev = vlan_dev_real_dev(netdev);
          master_ifindex = real_dev->ifindex;
          ci_bonding_get_xmit_policy_flags(real_dev, &encap.type);
        } 
        else {
          master_ifindex = netdev->ifindex;
          ci_bonding_get_xmit_policy_flags(netdev, &encap.type);
        }

        if( cicp_llap_get_encapsulation(&CI_GLOBAL_CPLANE, netdev->ifindex,
                                        &old_encap) != 0 )
          cicpos_llap_import(&CI_GLOBAL_CPLANE, NULL, netdev->ifindex, 
                             netdev->mtu, 1, netdev->name, NULL, NULL);
        else 
          OO_DEBUG_BONDING
            (ci_log("NETDEV_UP changing encap on %d from %d to %d", 
                    netdev->ifindex, old_encap.type, encap.type));

        cicp_llap_set_bond(&CI_GLOBAL_CPLANE, netdev->ifindex, 
                           master_ifindex, &encap);
        if( encap.type & CICP_LLAP_TYPE_VLAN ) 
          cicp_llap_set_vlan(&CI_GLOBAL_CPLANE, netdev->ifindex,
                             master_ifindex);
      }
      else
#endif
      if( (encap.type & CICP_LLAP_TYPE_VLAN) && 
          efrm_nic_present(vlan_dev_real_dev(netdev)->ifindex) ) {
        struct net_device* real_dev = vlan_dev_real_dev(netdev);
        onic = oo_nic_find_ifindex(real_dev->ifindex);
        if( onic == NULL )
          /* VLAN has come up before parent, so try adding parent now */
          onic = oo_netdev_may_add(real_dev);
        if( onic != NULL ) {
          cicp_llap_set_hwport(&CI_GLOBAL_CPLANE, netdev->ifindex,
                               CI_HWPORT_ID(onic - oo_nics), &encap);
          if( encap.type & CICP_LLAP_TYPE_VLAN ) 
            cicp_llap_set_vlan(&CI_GLOBAL_CPLANE, netdev->ifindex, 
                               real_dev->ifindex);
        }
        else 
          OO_DEBUG_BONDING(ci_log("Failed to configure VLAN if %d as parent "
                                  "onic (if %d) not found", 
                                  netdev->ifindex, real_dev->ifindex));
      }
    }
  }
#if CI_CFG_TEAMING
  if( NETDEV_IS_BOND(netdev) )
    ci_bonding_set_timer_period(oo_bond_poll_peak, oo_bond_peak_polls);
#endif
}


static void oo_netdev_going_down(struct net_device* netdev)
{
  ci_irqlock_state_t lock_flags;
  struct oo_nic *onic;

  onic = oo_nic_find_ifindex(netdev->ifindex);
  if( onic != NULL ) {
      oof_hwport_up_down(oo_nic_hwport(onic), 0, 0, 0);
      ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
      if( ci_dllist_is_empty(&THR_TABLE.all_stacks) )
        oo_netdev_remove(onic);
      else
        ci_log("Unable to oo_nic_remove(ifindex=%d, hwport=%d) because of "
               "open stacks", netdev->ifindex, oo_nic_hwport(onic));
      ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
    }
    else {
      if( (netdev->priv_flags & IFF_802_1Q_VLAN) ||
          NETDEV_IS_BOND_MASTER(netdev) ) {
        /* NB. I am deliberately not testing oo_use_vlans and
         * efrm_nic_present(real_dev_ifindex) as below.
         */
        cicp_llap_set_hwport(&CI_GLOBAL_CPLANE, netdev->ifindex,
                             CI_HWPORT_ID_BAD, NULL);
      }

#if CI_CFG_TEAMING
      if( NETDEV_IS_BOND_MASTER(netdev) )
        cicp_bond_remove_master(&CI_GLOBAL_CPLANE, netdev->ifindex);
#endif
    }
#if CI_CFG_TEAMING
    if( NETDEV_IS_BOND(netdev) )
      ci_bonding_set_timer_period(oo_bond_poll_peak, oo_bond_peak_polls);
#endif
}


/* Context: rtnl lock held */
static int oo_netdev_event(struct notifier_block *this,
                           unsigned long event, void *ptr)
{
  struct net_device *netdev = netdev_notifier_info_to_dev(ptr);

  switch( event ) {
  case NETDEV_UP:
    oo_netdev_up(netdev);
    break;

  case NETDEV_GOING_DOWN:
    oo_netdev_going_down(netdev);
    break;

  case NETDEV_CHANGEMTU:
    oo_fixup_wakeup_breakage(netdev->ifindex);
    break;

#if CI_CFG_TEAMING && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
  case NETDEV_BONDING_FAILOVER:
    ci_bonding_set_timer_period(oo_bond_poll_peak, oo_bond_peak_polls);
    break;
#endif

  default:
    break;
  }

  return NOTIFY_DONE;
}


static struct notifier_block oo_netdev_notifier = {
  .notifier_call = oo_netdev_event,
};


static struct efx_dl_driver oo_dl_driver = {
  .name = "onload",
#if EFX_DRIVERLINK_API_VERSION >= 8
  .flags = EFX_DL_DRIVER_CHECKS_FALCON_RX_USR_BUF_SIZE,
#endif
  .probe = oo_dl_probe,
  .remove = oo_dl_remove,
  .reset_suspend = oo_dl_reset_suspend,
  .reset_resume = oo_dl_reset_resume
};


int oo_driverlink_register(void)
{
  int rc;

  rc = register_netdevice_notifier(&oo_netdev_notifier);
  if (rc != 0)
    goto fail1;

  rc = efx_dl_register_driver(&oo_dl_driver);
  if (rc != 0)
    goto fail2;

  rc = nf_register_hook(&oo_netfilter_arp_hook);
  if( rc < 0 )
    goto fail3;

  rc = nf_register_hook(&oo_netfilter_ip_hook);
  if( rc < 0 )
    goto fail4;

  return 0;

 fail4:
  nf_unregister_hook(&oo_netfilter_arp_hook);
 fail3:
  efx_dl_unregister_driver(&oo_dl_driver);
 fail2:
  unregister_netdevice_notifier(&oo_netdev_notifier);
 fail1:
  ci_log("%s: efx_dl_register_driver failed (%d)", __FUNCTION__, rc);
  return rc;
}


void oo_driverlink_unregister_nf(void)
{
  nf_unregister_hook(&oo_netfilter_ip_hook);
  nf_unregister_hook(&oo_netfilter_arp_hook);
  unregister_netdevice_notifier(&oo_netdev_notifier);
}

void oo_driverlink_unregister_dl(void)
{
  efx_dl_unregister_driver(&oo_dl_driver);
}


/*! \cidoxg_end */
