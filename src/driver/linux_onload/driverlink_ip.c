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
  /* We should return 1 for accelerated bond or team interface.
   * There is no easy way to check if an interface is team or not,
   * so we just look into the cplane llap table and see if this llap is
   * accelerated. */
  {
    cicp_encap_t encap;
    ci_hwport_id_t hwport;

    if( cicp_llap_retrieve(&CI_GLOBAL_CPLANE, net_dev->ifindex,
                           NULL, &hwport, NULL, &encap, NULL, NULL) == 0 &&
        ( hwport != CI_HWPORT_ID_BAD ||
          (encap.type & CICP_LLAP_TYPE_CAN_ONLOAD_BAD_HWPORT) ) )
      return 1;
  }
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

#if defined (RHEL_MAJOR) && defined (RHEL_MINOR)
#if RHEL_MAJOR == 7 && RHEL_MINOR >= 2
/* RHEL 7.2 kernel is crazy and can't be parsed by kernel_compat.sh correctly */
#define EFRM_HAVE_NETFILTER_INDEV_OUTDEV yes
#endif
#endif


static unsigned int oo_netfilter_arp(
#ifdef EFRM_HAVE_NETFILTER_HOOK_STATE
                                     const struct nf_hook_ops* ops,
                                     struct sk_buff* skb,
#ifdef EFRM_HAVE_NETFILTER_INDEV_OUTDEV
                                     const struct net_device* indev,
                                     const struct net_device* outdev,
#else
#define indev state->in
#endif
                                     const struct nf_hook_state *state
#else
#ifdef EFRM_HAVE_NETFILTER_HOOK_OPS
                                     const struct nf_hook_ops* ops,
                                     struct sk_buff* skb,
#else
                                     unsigned int hooknum,
#ifdef EFRM_HAVE_NETFILTER_INDIRECT_SKB
        /* this is the oldest case, linux<2.6.24 */
                                     struct sk_buff** pskb,
#define skb (*pskb)
#else
                                     struct sk_buff* skb,
#endif
#endif
                                     const struct net_device* indev,
                                     const struct net_device* outdev,
                                     int (*okfn)(struct sk_buff*)
#endif
                                     )

{
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
#undef indev
#undef skb


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
#ifdef EFRM_HAVE_NETFILTER_HOOK_STATE
                                     const struct nf_hook_ops* ops,
                                     struct sk_buff* skb,
#ifdef EFRM_HAVE_NETFILTER_INDEV_OUTDEV
                                     const struct net_device* indev,
                                     const struct net_device* outdev,
#else
#define indev state->in
#endif
                                     const struct nf_hook_state *state
#else
#ifdef EFRM_HAVE_NETFILTER_HOOK_OPS
                                     const struct nf_hook_ops* ops,
                                     struct sk_buff* skb,
#else
                                     unsigned int hooknum,
#ifdef EFRM_HAVE_NETFILTER_INDIRECT_SKB
        /* this is the oldest case, linux<2.6.24 */
                                     struct sk_buff** pskb,
#define skb (*pskb)
#else
                                     struct sk_buff* skb,
#endif
#endif
                                     const struct net_device* indev,
                                     const struct net_device* outdev,
                                     int (*okfn)(struct sk_buff*)
#endif
                                    )
{
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
#undef indev
#undef skb

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


/******************************************************************************
 * cplane_add() and cplane_remove() are called in the course of the driverlink
 * handlers for the appropriate netdev events.
 *****************************************************************************/

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
  struct efhw_nic* efhw_nic;
  struct oo_nic* onic;

  BUG_ON(!netif_running(net_dev));

  onic = oo_nic_find_ifindex(net_dev->ifindex);
  if( onic == NULL )
    onic = oo_nic_add(net_dev->ifindex);

  if( onic != NULL ) {
    if( net_dev->flags & IFF_UP ) {
      cplane_add(onic);
      efhw_nic = efrm_client_get_nic(onic->efrm_client);
      oof_hwport_up_down(oo_nic_hwport(onic), 1,
                         efhw_nic->devtype.arch == EFHW_ARCH_EF10 ? 1:0,
                         efhw_nic->flags & NIC_FLAG_VLAN_FILTERS);
      onic->oo_nic_flags |= OO_NIC_UP;
    }
    /* Remove OO_NIC_UNPLUGGED regardless of whether the interface is IFF_UP,
     * as we don't want to attempt to create ghost VIs now that the hardware is
     * back.
     */
    onic->oo_nic_flags &= ~OO_NIC_UNPLUGGED;
  }

  return onic;
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
  /* We need to fini all of the hardware queues immediately. The net driver
   * will tidy up its own queues and *all* VIs, so if we don't free our own
   * queues they will be left dangling and will not be cleared even on an
   * entity reset.
   *   A note on locking: iterate_netifs_unlocked() will give us netif pointers
   * that are guaranteed to remain valid, but the state of the underlying
   * netifs may be unstable. However, we only touch immutable state. We can't
   * defer the work to the lock holders as we need to speak to the hardware
   * right now, before it goes away.
   */
  ci_netif* ni = NULL;
  struct net_device* netdev = dl_dev->priv;
  struct oo_nic* onic;
  if( (onic = oo_nic_find_ifindex(netdev->ifindex)) != NULL ) {
    int hwport = onic - oo_nics;
    onic->oo_nic_flags |= OO_NIC_UNPLUGGED;
    while( iterate_netifs_unlocked(&ni) == 0 )
      tcp_helper_shutdown_vi(ni, hwport);
  }
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
  /* Does efrm own this device? */
  if( efrm_nic_present(netdev->ifindex) ) {
    oo_netdev_may_add(netdev);
    oo_fixup_wakeup_breakage(netdev->ifindex);
  }
  else if( oo_use_vlans && (netdev->priv_flags & IFF_802_1Q_VLAN) ) {
    cicp_encap_t encap;

    if( cicp_llap_get_encapsulation(&CI_GLOBAL_CPLANE, netdev->ifindex,
                                    &encap) != 0 )
      cicpos_llap_import(&CI_GLOBAL_CPLANE, NULL, netdev->ifindex, 
                         netdev->mtu, 1, CICP_LLAP_TYPE_VLAN,
                         netdev->name, NULL, NULL);
    cicp_llap_set_vlan(&CI_GLOBAL_CPLANE, netdev->ifindex, 
                       vlan_dev_real_dev(netdev)->ifindex,
                       vlan_dev_vlan_id(netdev));
  }
#if CI_CFG_TEAMING
  else if( NETDEV_IS_BOND_MASTER(netdev) ) {
    cicp_encap_t encap;

    if( cicp_llap_get_encapsulation(&CI_GLOBAL_CPLANE, netdev->ifindex,
                                    &encap) != 0 ) {
      cicpos_llap_import(&CI_GLOBAL_CPLANE, NULL, netdev->ifindex,
                         netdev->mtu, 1, CICP_LLAP_TYPE_BOND,
                         netdev->name, NULL, NULL);
    }
    else {
      OO_DEBUG_BONDING(ci_log("NETDEV_UP changing encap on %d from %x to %x",
                              netdev->ifindex, encap.type,
                              CICP_LLAP_TYPE_BOND));
    }

    /* To avoid deadlock, we should not call something like
     * ci_bonding_check_mode().  */
     cicp_llap_set_bond(&CI_GLOBAL_CPLANE, netdev->ifindex);
  }
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
      onic->oo_nic_flags &= ~OO_NIC_UP;
      cplane_remove(onic);
      ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  }
  else {
    /* ensure that acceleration is off */
    cicp_llap_set_hwport(&CI_GLOBAL_CPLANE, netdev->ifindex,
                         CI_HWPORT_ID_BAD, NULL);
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
