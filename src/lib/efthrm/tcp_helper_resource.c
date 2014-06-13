/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
**      Author: ctk
**     Started: 2004/03/15
** Description: TCP helper resource
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_driver_efab */
#include <ci/internal/transport_config_opt.h>
# include <onload/linux_onload_internal.h>
# include <onload/linux_onload.h>
# include <onload/linux_ip_protocols.h>
# include <onload/linux_sock_ops.h>
#include <ci/driver/efab/efrm_mmap.h>
#include <onload/cplane.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/tcp_helper_fns.h>
#include <onload/efabcfg.h>
#include <onload/driverlink_filter.h>
#include <onload/version.h>


#include <etherfabric/timer.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/vf_resource.h>
#include <ci/driver/efab/hardware.h>
#include <onload/oof_onload.h>
#include <onload/oof_interface.h>
#include <onload/nic.h>


#ifdef NDEBUG
# define DEBUG_STR  ""
#else
# define DEBUG_STR  " debug"
#endif


#define EFAB_THR_MAX_NUM_INSTANCES  0x00010000


/* Global structure for onload driver */
efab_tcp_driver_t efab_tcp_driver;


static void tcp_helper_dtor(tcp_helper_resource_t* trs);

static void oo_handle_wakeup_int_driven(void*, int is_timeout,
                                        struct efhw_nic*);

static void
efab_tcp_helper_rm_free_locked(tcp_helper_resource_t*, int can_destroy_now);

static void
oo_handle_wakeup_or_timeout(void*, int is_timeout, struct efhw_nic*);
static void
tcp_helper_initialize_and_start_periodic_timer(tcp_helper_resource_t*);
static void
tcp_helper_stop_periodic_timer(tcp_helper_resource_t*);


/*----------------------------------------------------------------------------
 *
 * tcp helpers table implementation
 *
 *---------------------------------------------------------------------------*/

static int thr_table_ctor(tcp_helpers_table_t *table)
{
  ci_dllist_init(&table->all_stacks);
  ci_irqlock_ctor(&table->lock);
  ci_id_pool_ctor(&table->instances, EFAB_THR_MAX_NUM_INSTANCES,
                  /* initial size */ 8);
  return 0;
}


static void thr_table_dtor(tcp_helpers_table_t *table)
{
  /* Onload is going away, so kill off any remaining stacks. */

  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t* thr;
  ci_dllink* link;

  ci_irqlock_lock(&table->lock, &lock_flags);

  while( ci_dllist_not_empty(&table->all_stacks) ) {
    link = ci_dllist_pop(&table->all_stacks);
    thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
    ci_dllink_mark_free(&thr->all_stacks_link);

    /* The only stacks that should remain at this point are orphaned stacks
     * still living to allow their connections to close gracefully or
     * time-out.
     *
     * This is prone to race conditions against the self-destruction of
     * orphaned TCP helper resources.
     * a) we know this function can only be called once all efab file
     *    descriptors are closed i.e. we know that tcp_helper_rm_free has
     *    completed
     * b) we could be between tcp_helper_rm_free and
     *    tcp_helper_rm_free_locked awaiting the netif lock
     * c) we could be between tcp_helper_rm_free_locked and tcp_helper_dtor
     *    awaiting TCP connections to close
     *
     * We get (a) to put the TCP resource on a list - whoever removes the
     * TCP helper resource from this list destroys it. If we are between
     * (b) and (c) and the last TCP connection closes, the act of closure
     * will try and remove the resource from this list and destroy it. List
     * removal is protected by a spin lock so safe.  Other problem is we
     * don't know whether (b) has yet run. However, if we manage to remove
     * the resource form the orpaned list the first thing the
     * tcp_helper_dtor does is to call tcp_helper_stop to stop async
     * callbacks - by the time this returns we know that the kernel netif
     * lock will have been dropped and therefore
     * efab_tcp_helper_rm_free_locked will have run and returned.
     */
    if( ! (thr->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND) )
      ci_log("%s: ERROR: non-orphaned stack=%u ref_count=%d k_ref_count=%x",
             __FUNCTION__, thr->id, oo_atomic_read(&thr->ref_count),
             thr->k_ref_count);

    ci_irqlock_unlock(&table->lock, &lock_flags);
    OO_DEBUG_TCPH(ci_log("%s: killing stack %d", __FUNCTION__, thr->id));
    tcp_helper_dtor(thr);
    ci_irqlock_lock(&table->lock, &lock_flags);
  }

  ci_irqlock_unlock(&table->lock, &lock_flags);
  ci_id_pool_dtor(&table->instances);
}


static
void efab_thr_table_insert(tcp_helper_resource_t* thr)
{
  tcp_helpers_table_t* table = &THR_TABLE;
  ci_irqlock_state_t lock_flags;
  ci_irqlock_lock(&table->lock, &lock_flags);
  ci_dllist_push(&table->all_stacks, &thr->all_stacks_link);
  ci_irqlock_unlock(&table->lock, &lock_flags);
}


static
int efab_thr_table_insert_name(tcp_helper_resource_t* thr, const char* name)
{
  /* Insert stack into the table provided there is not already a stack with
   * the same name.
   */
  tcp_helpers_table_t* table = &THR_TABLE;
  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t *thr2;
  ci_dllink *link;
  int rc = 0;

  ci_irqlock_lock(&table->lock, &lock_flags);
  CI_DLLIST_FOR_EACH(link, &table->all_stacks) {
    thr2 = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
    if( strncmp(thr2->netif.state->name, name, CI_CFG_STACK_NAME_LEN) == 0 &&
        (thr2->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND) == 0 ) {
      rc = -EEXIST;
      break;
    }
  }
  if( rc == 0 )
    ci_dllist_push(&THR_TABLE.all_stacks, &thr->all_stacks_link);
  ci_irqlock_unlock(&table->lock, &lock_flags);
  return rc;
}


/* Module option to override secure stack sharing rules. */
int allow_insecure_setuid_sharing;


int efab_thr_can_access_stack(tcp_helper_resource_t* thr, int check_user)
{
  /* On entry, [check_user] tells us whether the calling code path requires
   * the user to be checked.  Some paths do not because the call is not
   * being made on behalf of a user.
   */
  ci_netif* ni = &thr->netif;
  uid_t euid = ci_geteuid();
  uid_t uid = ci_getuid();

  if( /* We're not about to give a user access to the stack. */
      (~check_user & EFAB_THR_TABLE_LOOKUP_CHECK_USER) ||
      /* bob and setuid-bob can access stacks created by bob or setuid-bob. */
      euid == ni->euid ||
      /* root can map any stack. */
      uid == 0 )
    return 1;

  if( /* Owner does not allow other users to map this stack. */
      NI_OPTS(ni).share_with == 0 ||
      /* Stack can be shared with another user, but not this user. */
      (NI_OPTS(ni).share_with > 0 && euid != NI_OPTS(ni).share_with) )
    return 0;

  /* By default we don't allow setuid processes to map other users' stacks,
   * because the setuid process could then be compromised.
   */
  return euid == uid || allow_insecure_setuid_sharing;
}


int efab_thr_table_lookup(const char* name, unsigned id, int check_user,
                          tcp_helper_resource_t** thr_p)
{
  tcp_helpers_table_t* table = &THR_TABLE;
  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t *thr;
  ci_dllink *link;
  int match, rc = -ENODEV;

  ci_assert(thr_p != NULL);
  ci_assert(check_user == EFAB_THR_TABLE_LOOKUP_NO_CHECK_USER ||
            (check_user & EFAB_THR_TABLE_LOOKUP_CHECK_USER));

  ci_irqlock_lock(&table->lock, &lock_flags);
  CI_DLLIST_FOR_EACH(link, &table->all_stacks) {
    thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
    if( name )
      match = strcmp(thr->name, name) == 0;
    else
      match = thr->id == id;
    if( match ) {
      if( ! efab_thr_can_access_stack(thr, check_user) ) {
        ci_log("User %d:%d can't share stack %d(%s) owned by %d:%d "
               "share_with=%d", (int) ci_getuid(), (int) ci_geteuid(), thr->id,
               thr->name, (int) thr->netif.uid, (int) thr->netif.euid,
               NI_OPTS(&thr->netif).share_with);
        rc = -EACCES;
      }
      else if( thr->k_ref_count & TCP_HELPER_K_RC_DEAD )
        rc = -EBUSY;
      else if( thr->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND ) {
        if( check_user & EFAB_THR_TABLE_LOOKUP_NO_UL ) {
          *thr_p = thr;
          /* do not call efab_thr_ref()  */
          efab_tcp_helper_k_ref_count_inc(thr);
          ci_irqlock_unlock(&table->lock, &lock_flags);
          return 0;
        }
        else
          rc = -EBUSY;
      }
      else if( check_user & EFAB_THR_TABLE_LOOKUP_NO_UL )
        rc = -EACCES;
      else {
        efab_thr_ref(thr);
        *thr_p = thr;
        rc = 0;
      }
      break;
    }
  }
  ci_irqlock_unlock(&table->lock, &lock_flags);
  return rc;
}


int tcp_helper_dump_stack(unsigned id)
{
  tcp_helpers_table_t* table = &THR_TABLE;
  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t *thr = NULL;
  ci_dllink *link;
  int rc = -ENODEV;

  ci_irqlock_lock(&table->lock, &lock_flags);
  CI_DLLIST_FOR_EACH(link, &table->all_stacks) {
    thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
    if( thr->id == id ) {
      rc = efab_tcp_helper_k_ref_count_inc(thr);
      break;
    }
  }
  ci_irqlock_unlock(&table->lock, &lock_flags);

  if( rc == 0 ) {
    ci_log("============================================================");
    ci_netif_dump(&thr->netif);
    ci_log("============================================================");
    ci_netif_dump_sockets(&thr->netif);
    efab_tcp_helper_k_ref_count_dec(thr, 1);
  }

  return rc;
}


void
tcp_helper_resource_assert_valid(tcp_helper_resource_t* thr, int rc_is_zero,
                                 const char *file, int line)
{
  _ci_assert(thr, file, line);
  _ci_assert_nequal(thr->id, CI_ID_POOL_ID_NONE, file, line);
  _ci_assert_equal(thr->id, thr->netif.state->stack_id, file, line);

  if (rc_is_zero >=0) {
    if ((rc_is_zero && oo_atomic_read(&thr->ref_count) > 0) ||
        (!rc_is_zero && oo_atomic_read(&thr->ref_count) == 0)) {
      ci_log("%s %d: %s check %u for %szero ref=%d", file, line,
             __FUNCTION__, thr->id, rc_is_zero ? "" : "non-",
             oo_atomic_read(&thr->ref_count));
    }
    _ci_assert(rc_is_zero || oo_atomic_read(&thr->ref_count), file, line);
  }
}


static int allocate_vi(tcp_helper_resource_t* trs,
                       unsigned evq_sz, ci_resource_onload_alloc_t* alloc,
                       void* vi_state, unsigned vi_state_bytes)
{
  /* Format is "onload:pretty_name-intf_i"
   * Do not use slash in this name! */
  char vf_name[7 + CI_CFG_STACK_NAME_LEN+8 + 3];
  ci_netif* ni = &trs->netif;
  ci_netif_state* ns = ni->state;
  enum ef_vi_flags vi_flags;
  ci_uint16 in_flags;
  int rc, intf_i, vf_mode = -1;
  ci_uint32 txq_capacity = 0, rxq_capacity = 0;
  const char* pci_dev_name;

  /* The array of nic_hw is potentially sparse, but the memory mapping
   * is not, so we keep a count to calculate offsets rather than use
   * nic_index */

  vi_flags = 0;
  in_flags = EFHW_VI_JUMBO_EN;

  if( (alloc->in_flags & CI_NETIF_FLAGS_INTERRUPT) ) {
    in_flags |= EFHW_VI_RM_WITH_INTERRUPT;
    alloc->in_flags &= ~CI_NETIF_FLAGS_INTERRUPT;
  }
  if( ! NI_OPTS(ni).tx_push )
    vi_flags |= EF_VI_TX_PUSH_DISABLE;

  if( (alloc->in_flags & (CI_NETIF_FLAGS_PHYS_ADDR_MODE | CI_NETIF_FLAGS_ISCSI))
      != (CI_NETIF_FLAGS_PHYS_ADDR_MODE | CI_NETIF_FLAGS_ISCSI) ) {
    txq_capacity = NI_OPTS(ni).txq_size;
    rxq_capacity = NI_OPTS(ni).rxq_size;
    if( alloc->in_flags & CI_NETIF_FLAGS_PHYS_ADDR_MODE ) {
      in_flags |= EFHW_VI_RX_PHYS_ADDR_EN | EFHW_VI_TX_PHYS_ADDR_EN;
      vi_flags |= EF_VI_RX_PHYS_ADDR | EF_VI_TX_PHYS_ADDR;
    }
  }

  ns->vi_mem_mmap_offset = trs->buf_mmap_bytes;
  ns->vi_io_mmap_offset = trs->io_mmap_bytes;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    trs->nic[intf_i].vi_rs = NULL;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    struct tcp_helper_nic* trs_nic = &trs->nic[intf_i];
    ci_netif_state_nic_t* nsn = &ns->nic[intf_i];
    struct efhw_nic* nic;
    struct efrm_vf *vf = NULL;

    ci_assert(trs_nic->vi_rs == NULL);
    ci_assert(trs_nic->oo_nic != NULL);
    ci_assert(trs_nic->oo_nic->efrm_client != NULL);

    if( trs->name[0] == '\0' )
      snprintf(ns->pretty_name, sizeof(ns->pretty_name), "%d", ns->stack_id);
    else
      snprintf(ns->pretty_name, sizeof(ns->pretty_name), "%d,%s",
               ns->stack_id, trs->name);
    snprintf(vf_name, sizeof(vf_name), "onload:%s-%d",
             ns->pretty_name, intf_i);

    if( NI_OPTS(ni).packet_buffer_mode == 1 || vf_mode == 1 ) {
try_sriov:
      rc = efrm_vf_resource_alloc(trs_nic->oo_nic->efrm_client, &vf);
      if( rc < 0 ) {
        OO_DEBUG_VM (ci_log ("%s: ERROR: efrm_vf_resource_alloc(%d) failed %d",
                             __FUNCTION__, intf_i, rc));
        goto error_out;
      }

      /* With PCI VF, we are forced to use phys addr mode. */
      ci_assert(vf);
      alloc->in_flags |= CI_NETIF_FLAGS_PHYS_ADDR_MODE;
      in_flags |= EFHW_VI_RX_PHYS_ADDR_EN | EFHW_VI_TX_PHYS_ADDR_EN;
      vi_flags |= EF_VI_RX_PHYS_ADDR | EF_VI_TX_PHYS_ADDR;
    }
    rc = efrm_vi_resource_alloc(trs_nic->oo_nic->efrm_client,
                                NULL, NULL, 0, vf, vf_name, in_flags,
                                evq_sz, txq_capacity, rxq_capacity, 0, 0, 
                                NI_OPTS(ni).irq_core, NI_OPTS(ni).irq_channel,
                                &trs_nic->vi_rs, &nsn->vi_io_mmap_bytes,
                                &nsn->vi_mem_mmap_bytes, NULL, NULL);
    if( rc < 0 && vf == NULL && 
        NI_OPTS(ni).packet_buffer_mode == 2 && vf_mode != 0 )
      goto try_sriov;
    if( vf != NULL ) {
      efrm_vf_resource_release(vf); /* vi_rs keeps a ref */
      vf_mode = 1;
    }
    else {
      vf_mode = 0;
    }
    if( rc < 0 ) {
      OO_DEBUG_VM (ci_log ("%s: ERROR: efrm_vi_resource_alloc(%d) failed %d",
                           __FUNCTION__, intf_i, rc));
      goto error_out;
    }

    pci_dev_name = pci_name(efrm_vi_get_pci_dev(trs_nic->vi_rs));
    strncpy(nsn->pci_dev, pci_dev_name, sizeof(nsn->pci_dev));
    nsn->pci_dev[sizeof(nsn->pci_dev) - 1] = '\0';
    trs_nic->vi_mem_mmap_bytes = nsn->vi_mem_mmap_bytes;
    nsn->vi_instance = (ci_uint16) EFAB_VI_RESOURCE_INSTANCE(trs_nic->vi_rs);
    nic = efrm_client_get_nic(trs_nic->oo_nic->efrm_client);
    nsn->vi_arch = (ci_uint8) nic->devtype.arch;
    nsn->vi_variant = (ci_uint8) nic->devtype.variant;
    nsn->vi_revision = (ci_uint8) nic->devtype.revision;

    efrm_vi_resource_mappings(trs_nic->vi_rs, ni->vi_data);
    ef_vi_init(&ni->nic_hw[intf_i].vi, ni->vi_data, (ef_vi_state*) vi_state,
               &nsn->evq_state, vi_flags);
    ef_vi_set_stats_buf(&ni->nic_hw[intf_i].vi, &ni->state->vi_stats);
    vi_state = (char*) vi_state + vi_state_bytes;
    ef_eventq_state_init(&ni->nic_hw[intf_i].vi);
    ef_vi_state_init(&ni->nic_hw[intf_i].vi);
    if( txq_capacity || rxq_capacity )
      ef_vi_add_queue(&ni->nic_hw[intf_i].vi, &ni->nic_hw[intf_i].vi);
    nsn->vi_flags = vi_flags;
    nsn->vi_evq_bytes = efrm_vi_rm_evq_bytes(trs_nic->vi_rs, -1);
    nsn->vi_rxq_size = (ci_uint16) NI_OPTS(ni).rxq_size;
    nsn->vi_txq_size = (ci_uint16) NI_OPTS(ni).txq_size;
    nsn->evq_timer_offset = efrm_vi_timer_page_offset(trs_nic->vi_rs);
    nsn->timer_quantum_ns = nic->timer_quantum_ns;
    trs->buf_mmap_bytes += efab_vi_resource_mmap_bytes(trs_nic->vi_rs, 1);
    trs->io_mmap_bytes += efab_vi_resource_mmap_bytes(trs_nic->vi_rs, 0);

    efrm_vi_irq_moderate(trs_nic->vi_rs, NI_OPTS(ni).irq_usec);
    if( NI_OPTS(ni).irq_core >= 0 && vf_mode == 1 ) {
      rc = efrm_vi_irq_affinity(trs_nic->vi_rs, NI_OPTS(ni).irq_core);
      if( rc < 0 )
        OO_DEBUG_ERR(ci_log("%s: ERROR: failed to set irq affinity to %d",
                            __FUNCTION__, (int) NI_OPTS(ni).irq_core));
    }
  }

  ns->vi_state_bytes = vi_state_bytes;

  OO_DEBUG_RES(ci_log("%s: done", __FUNCTION__));

  return 0;

error_out:
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    if( trs->nic[intf_i].vi_rs ) {
      efrm_vi_resource_release(trs->nic[intf_i].vi_rs);
      trs->nic[intf_i].vi_rs = NULL;
    }
  return rc;
}


static void vi_complete(void *completion_void)
{
  complete((struct completion *)completion_void);
}

static void release_vi(tcp_helper_resource_t* trs)
{
  int intf_i;
  struct completion flush_completion[CI_CFG_MAX_INTERFACES];

  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    init_completion(&flush_completion[intf_i]);
    efrm_vi_register_flush_callback(trs->nic[intf_i].vi_rs,
                                    &vi_complete,
                                    &flush_completion[intf_i]);
    efrm_vi_resource_release_callback(trs->nic[intf_i].vi_rs);
    trs->nic[intf_i].vi_rs = NULL;
    CI_DEBUG_ZERO(&trs->netif.nic_hw[intf_i].vi);
  }
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i)
    wait_for_completion(&flush_completion[intf_i]);
}


/* Onload module parameter which provides upper limit to opts->max_packets */
extern int max_packets_per_stack;

static int
allocate_netif_resources(ci_resource_onload_alloc_t* alloc,
                         tcp_helper_resource_t* trs)
{
  ci_netif* ni;
  ci_netif_state* ns;
  int i, sz, rc, no_table_entries, synrecv_ofs;
  int intf_i;
  unsigned vi_state_bytes;
  unsigned rxq_sz, txq_sz, evq_sz, evq_min;

  ni = &trs->netif;

  trs->mem_mmap_bytes = 0;
  trs->io_mmap_bytes = 0;
  trs->buf_mmap_bytes = 0;

  no_table_entries = ci_pow2(NI_OPTS(ni).max_ep_bufs_ln2) * 2;

  /* Choose DMA queue sizes, and calculate suitable size for EVQ. */
  rxq_sz = NI_OPTS(ni).rxq_size;
  txq_sz = NI_OPTS(ni).txq_size;
  vi_state_bytes = ef_vi_calc_state_bytes(rxq_sz, txq_sz);
  evq_min = rxq_sz + txq_sz;
  for( evq_sz = 512; evq_sz <= evq_min; evq_sz *= 2 )
    ;

  /* allocate shmbuf for netif state */
  ci_assert_le(NI_OPTS(ni).max_ep_bufs_ln2, 
               CI_CFG_NETIF_MAX_ENDPOINTS_SHIFT_MAX);
  sz = sizeof(ci_netif_state) + vi_state_bytes * trs->netif.nic_n +
    sizeof(ci_netif_filter_table) +
    sizeof(ci_netif_filter_table_entry) * (no_table_entries - 1);

  /* Allocate the synrecv buffs */
  synrecv_ofs = sz;
  sz += sizeof (ci_tcp_state_synrecv) * NI_OPTS(ni).tcp_backlog_max;

  sz = CI_ROUND_UP(sz, CI_PAGE_SIZE);

  rc = ci_contig_shmbuf_alloc(&ni->state_buf, sz);
  if( rc < 0 ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_alloc: failed to alloc state_buf (%d)", rc));
    goto fail1;
  }
  memset(ci_contig_shmbuf_ptr(&ni->state_buf), 0,
         ci_contig_shmbuf_size(&ni->state_buf));

#ifdef CI_HAVE_OS_NOPAGE
  i = (ci_pow2(NI_OPTS(ni).max_ep_bufs_ln2) + EP_BUF_PER_PAGE - 1)
    / EP_BUF_PER_PAGE * CI_PAGE_SIZE;
  rc = ci_shmbuf_alloc(&ni->pages_buf, i);
  if( rc < 0 ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_alloc: failed to alloc pages buf (%d)", rc));
    goto fail2;
  }
#else
  i = (ci_pow2(NI_OPTS(ni).max_ep_bufs_ln2) + EP_BUF_BLOCKNUM-1) 
    >> EP_BUF_BLOCKSHIFT; 
  ni->k_shmbufs = ci_alloc(sizeof(ci_shmbuf_t *) * i);
  if( ! ni->k_shmbufs ) {
    OO_DEBUG_ERR(ci_log("%s: out of memory at %d", __FUNCTION__, __LINE__));
    rc = -ENOMEM;
    goto fail2;
  }
  memset(ni->k_shmbufs, 0, sizeof(ni->k_shmbufs[0]) * i);
  ni->k_shmbufs_n = 0;
#endif

  ns = ni->state = (ci_netif_state*) ci_contig_shmbuf_ptr(&ni->state_buf);
  memset(ns, 0, synrecv_ofs);
  CI_DEBUG(ns->flags |= CI_NETIF_FLAG_DEBUG);

#ifdef CI_HAVE_OS_NOPAGE
  ns->netif_mmap_bytes =
    ci_contig_shmbuf_size(&ni->state_buf) + ci_shmbuf_size(&ni->pages_buf);
#else
  ns->netif_mmap_bytes =
    ci_contig_shmbuf_size(&ni->state_buf);
#endif

  ns->stack_id = trs->id;
  ns->ep_ofs = ni->ep_ofs = sz;
  ns->synrecv_ofs = synrecv_ofs;
  ns->n_ep_bufs = 0;
  ns->nic_n = trs->netif.nic_n;

  /* An entry in intf_i_to_hwport should not be touched if the intf does
   * not exist.  Belt-and-braces: initialise to 0.
   */
  memset(ns->intf_i_to_hwport, 0, sizeof(ns->intf_i_to_hwport));
  memcpy(ns->hwport_to_intf_i, ni->hwport_to_intf_i,
         sizeof(ns->hwport_to_intf_i));
  for( i = 0; i < CI_CFG_MAX_REGISTER_INTERFACES; ++i )
    if( ns->hwport_to_intf_i[i] >= 0 )
      ns->intf_i_to_hwport[(int) ns->hwport_to_intf_i[i]] = i;

  memcpy(ns->blacklist_intf_i, ni->blacklist_intf_i,
         sizeof(ns->blacklist_intf_i));
  ns->blacklist_length = ni->blacklist_length;

  ns->table_ofs = sizeof(ci_netif_state) + vi_state_bytes * trs->netif.nic_n;
  ni->filter_table = (void*) ((char*) ns + ns->table_ofs);

  /* Initialize the free list of synrecv bufs */
  ns->free_synrecvs = OO_P_NULL;
  for( i = 0; i < (int) NI_OPTS(ni).tcp_backlog_max; ++i ) {
    ci_tcp_state_synrecv* tsr = (ci_tcp_state_synrecv*)
      ((char*) ns + ns->synrecv_ofs) + i;
    ci_ni_dllist_link_init(ni, &tsr->link,
                           oo_ptr_to_statep(ni, &tsr->link), "fsyn");
    ci_tcp_synrecv_free(ni, tsr);
  }

  /* The shared netif-state buffer and EP buffers are part of the mem mmap */
  trs->mem_mmap_bytes += ns->netif_mmap_bytes;
  OO_DEBUG_MEMSIZE(ci_log(
	"added %d (0x%x) bytes for shared netif state and ep buffers, "
	"reached %d (0x%x)", ns->netif_mmap_bytes, ns->netif_mmap_bytes,
	trs->mem_mmap_bytes, trs->mem_mmap_bytes));

  rc = allocate_vi(trs, evq_sz, alloc, ns + 1, vi_state_bytes);
  if( rc < 0 )  goto fail3;

  if( alloc->in_flags & CI_NETIF_FLAGS_ISCSI ) {
    ci_log("%s: iscsi support requested but not configured", __FUNCTION__);
    rc = -ENOENT;
    goto fail4;
  }

  sz = ci_pkt_dimension_iobufset(NULL);
  ci_assert_lt(sz, 1<<16);
  sz <<= CI_PAGE_SHIFT;
  ni->pkt_sets_n = 0;

  ni->pkt_sets_max = (CI_MIN(NI_OPTS(ni).max_packets, max_packets_per_stack) + 
                      PKTS_PER_SET - 1) >> PKTS_PER_SET_S;
  ns->pkt_sets_max = ni->pkt_sets_max;
  ns->pkt_sets_n = 0;
  ns->pkt_set_bytes = sz;
  ns->n_pkts_allocated = 0;

  /* Reserve space for I/O buffers */
  ns->buf_ofs = trs->buf_mmap_bytes;
  ci_assert_equal((ns->buf_ofs & (CI_PAGE_SIZE - 1)), 0);
#ifdef CI_HAVE_OS_NOPAGE
  trs->buf_mmap_bytes += ni->pkt_sets_max * sz;
#endif

  /* Allocate an eplock resource. */
  rc = eplock_ctor(ni);
  if( rc < 0 ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_alloc: failed to allocate EPLOCK (%d)", rc));
    goto fail5;
  }

  ni->pkt_bufs = CI_ALLOC_ARRAY(ef_iobufset*, ni->pkt_sets_max);
  if (ni->pkt_bufs == NULL) {
    OO_DEBUG_ERR(ci_log("tcp_helper_alloc: failed to allocate iobufset table"));
    rc = -ENOMEM;
    goto fail6;
  }
  CI_ZERO_ARRAY(ni->pkt_bufs, ni->pkt_sets_max);

  sz = sizeof(struct iobufset_resource*) * ni->pkt_sets_max;
  if( (ni->pkt_rs = ci_alloc(sz)) == NULL ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_alloc: failed to allocate iobufset table"));
    rc = -ENOMEM;
    goto fail7;
  }
  memset(ni->pkt_rs, 0, sz);

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ni->nic_hw[intf_i].pkt_rs = NULL;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    if( (ni->nic_hw[intf_i].pkt_rs = ci_alloc(sz)) == NULL ) {
      OO_DEBUG_ERR(ci_log("%s: failed to allocate iobufset tables",
                          __FUNCTION__));
      goto fail8;
    }
    memset(ni->nic_hw[intf_i].pkt_rs, 0, sz);
  }

  /* initialize NIC from driver data */
  cicp_ni_sethandle(&ni->cplane, &CI_GLOBAL_CPLANE);
  trs->mem_mmap_bytes += cicp_ns_map(&ns->control_mmap,
                                     CICP_HANDLE(ni));
  OO_DEBUG_MEMSIZE(ci_log("added %ld (0x%lx) bytes for global cplane, "
		       "reached %d (0x%x)",
                      (unsigned long) cicp_ns_map(&ns->control_mmap,
						  CICP_HANDLE(ni)),
                      (unsigned long) cicp_ns_map(&ns->control_mmap,
						  CICP_HANDLE(ni)),
		       trs->mem_mmap_bytes, trs->mem_mmap_bytes));

  /* Advertise the size of the IO and buf mmap that needs to be performed. */
  ns->io_mmap_bytes = trs->io_mmap_bytes;
  ns->buf_mmap_bytes = trs->buf_mmap_bytes;

  /* set kernel netif address space */
  ni->addr_spc_id = CI_ADDR_SPC_ID_KERNEL;

  OO_DEBUG_MEMSIZE(ci_log("helper=%u map_bytes=%u (0x%x)",
                          trs->id,
                          trs->mem_mmap_bytes, trs->mem_mmap_bytes));
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    LOG_NC(ci_log("VI=%d", ef_vi_instance(&ni->nic_hw[intf_i].vi)));

  /* Get the initial IP ID range */
  rc = ci_ipid_ctor(ni, (ci_fd_t)-1);
  if (rc < 0) {
    goto fail8;
  }

  ci_waitq_ctor(&trs->pkt_waitq);

  /* Apply pacing value. */
  if( NI_OPTS(ni).tx_min_ipg_cntl != 0 )
    tcp_helper_pace(trs, NI_OPTS(ni).tx_min_ipg_cntl);

  /* This is needed because release_netif_resources() tries to free the ep
  ** table. */
  ni->ep_tbl = 0;

  return 0;

 fail8:
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    if( ni->nic_hw[intf_i].pkt_rs )
      ci_free(ni->nic_hw[intf_i].pkt_rs);
  ci_free(ni->pkt_rs);
 fail7:
  ci_free(ni->pkt_bufs);
 fail6:
  eplock_dtor(ni);
 fail5:
 fail4:
  release_vi(trs);
 fail3:
#ifdef CI_HAVE_OS_NOPAGE
  ci_shmbuf_free(&ni->pages_buf);
#else
  /* Can we have allocated these yet?  Let's try to free things anyway */
  for( i = 0; i < (int)ni->k_shmbufs_n; ++i ) {
    ci_shmbuf_free(ni->k_shmbufs[i]);
    ci_free(ni->k_shmbufs[i]);
  }
  ci_free(ni->k_shmbufs);
#endif
 fail2:
  ci_contig_shmbuf_free(&ni->state_buf);
 fail1:
  LOG_NC(ci_log("failed to allocate tcp_helper resources (%d)", rc));
  return rc;
}


static void
release_ep_tbl(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  int i;
  if( ni->ep_tbl != NULL ) {
    for( i = 0; i < ni->ep_tbl_n; ++i ) {
#if CI_CFG_USERSPACE_PIPE
      /* skip buffers which were not filled */
      if( ! ni->ep_tbl[i] )
        continue;
#else
      ci_assert(ni->ep_tbl[i]);
#endif
      tcp_helper_endpoint_dtor(ni->ep_tbl[i]);
      ci_free(ni->ep_tbl[i]);
      CI_DEBUG(ni->ep_tbl[i] = 0);
    }
    ci_vfree(ni->ep_tbl);
  }
}


static void
release_netif_resources(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  unsigned i;
  int intf_i;

  OO_DEBUG_SHM(ci_log("release_netif_resources:"));

  /* do this first because we currently we may find filters still installed
   * - leaving them install doesn't only leak resources, it leaves the NET
   *   driver software filtering open to duplicates
   * - for now we deinstall the filters in the destructor of the TCP EP
   */
  release_ep_tbl(trs);

  ci_ipid_dtor(ni, (ci_fd_t)-1);
  
  eplock_dtor(ni);
  release_vi(trs);

  ci_waitq_dtor(&trs->pkt_waitq);

  for (i = 0; i < ni->pkt_sets_n; i++) {
    ci_assert(ni->pkt_bufs[i] != NULL);
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
      efrm_iobufset_resource_release(ni->nic_hw[intf_i].pkt_rs[i]);
    CI_FREE_OBJ(ni->pkt_bufs[i]);
  }
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ci_free(ni->nic_hw[intf_i].pkt_rs);
  ci_free(ni->pkt_bufs);
  ci_free(ni->pkt_rs);
#ifdef CI_HAVE_OS_NOPAGE
  ci_shmbuf_free(&ni->pages_buf);
#else
  for( i = 0; i < ni->k_shmbufs_n; ++i ) {
    ci_shmbuf_free(ni->k_shmbufs[i]);
    ci_free(ni->k_shmbufs[i]);
  }
  ci_free(ni->k_shmbufs);
#endif
  ci_contig_shmbuf_free(&ni->state_buf);
}


static int oo_version_check(ci_resource_onload_alloc_t* alloc)
{
  int ver_chk_bad, intf_chk_bad;
  int rc = 0;

  alloc->in_version[sizeof(alloc->in_version) - 1] = '\0';
  ver_chk_bad = strcmp(alloc->in_version, ONLOAD_VERSION);

  alloc->in_uk_intf_ver[sizeof(alloc->in_uk_intf_ver) - 1] = '\0';
  intf_chk_bad = strcmp(alloc->in_uk_intf_ver, oo_uk_intf_ver);

  if( ver_chk_bad ) {
    ci_log("ERROR: user/driver version mismatch");
    ci_log("  user-version: %s", alloc->in_version);
    ci_log("  driver-version: %s", ONLOAD_VERSION);
    rc = -ELIBACC;
  }
  if( intf_chk_bad ) {
    ci_log("ERROR: user/driver interface mismatch");
    ci_log("  user-interface: %s", alloc->in_uk_intf_ver);
    ci_log("  driver-interface: %s", oo_uk_intf_ver);
    rc = -ELIBACC;
  }
  if( rc != 0 )
    ci_log("HINT: Most likely you need to reload the sfc and onload drivers");

  return rc;
}


static int oo_get_nics(tcp_helper_resource_t* trs,
                       ci_resource_onload_alloc_t* alloc,
                       const int* ifindices, int ifindices_len)
{
  ci_netif* ni = &trs->netif;
  struct oo_nic* onic;
  int rc, i, intf_i;

  efrm_nic_set_clear(&ni->nic_set);
  trs->netif.nic_n = 0;

  if( ifindices_len > CI_CFG_MAX_INTERFACES )
    return -E2BIG;

  for( i = 0; i < CI_CFG_MAX_REGISTER_INTERFACES; ++i )
    ni->hwport_to_intf_i[i] = (ci_int8) -1;
  
  for( i = 0; i < CI_CFG_MAX_INTERFACES; ++i )
    ni->intf_i_to_hwport[i] = (ci_int8) -1;

  for( i = 0; i < CI_CFG_MAX_BLACKLIST_INTERFACES; ++i )
    ni->blacklist_intf_i[i] = (ci_int8) -1;
  ni->blacklist_length = 0;

  if( ifindices_len <= 0 ) {
    onic = oo_nics;
    for( intf_i = 0; intf_i < CI_CFG_MAX_INTERFACES; ++intf_i ) {
      while( onic < oo_nics + CI_CFG_MAX_REGISTER_INTERFACES )
        if( onic->efrm_client != NULL )
          break;
        else
          ++onic;
      if( onic >= oo_nics + CI_CFG_MAX_REGISTER_INTERFACES )
        break;
      efrm_nic_set_write(&ni->nic_set, intf_i, CI_TRUE);
      trs->nic[intf_i].intf_i = intf_i;
      trs->nic[intf_i].oo_nic = onic;
      ni->hwport_to_intf_i[onic - oo_nics] = intf_i;
      ni->intf_i_to_hwport[intf_i] = onic - oo_nics;;
      ++trs->netif.nic_n;
      ++onic;
    }
  }
  else {
    /*??*/
    ci_log("%s: TODO", __FUNCTION__);
    rc = -EINVAL;
    goto fail;
  }

  if( trs->netif.nic_n == 0 ) {
    ci_log("%s: ERROR: No Solarflare network interfaces are active/UP. "
	   "Please check your config with ip addr or ifconfig", __FUNCTION__);
    return -ENODEV;
  }
  return 0;

 fail:
  return rc;
}


ci_inline void efab_notify_stacklist_change(tcp_helper_resource_t *thr)
{
  /* here we should notify tcpdump process that the stack list have
   * changed */
  /*ci_log("add/remove stack %d(%s), refcount %d", thr->id, thr->name,
         oo_atomic_read(&thr->ref_count));*/
  efab_tcp_driver.stack_list_seq++;
  ci_rmb();
  ci_waitq_wakeup(&efab_tcp_driver.stack_list_wq);
}

static int tcp_helper_rm_alloc(ci_resource_onload_alloc_t* alloc,
                               const ci_netif_config_opts* opts,
                               const int* ifindices, int ifindices_len,
                               tcp_helper_resource_t** rs_out)
{
  tcp_helper_resource_t* rs;
  ci_irqlock_state_t lock_flags;
  struct efhw_nic *nic;
  int rc, intf_i;
  ci_netif* ni;

  ci_assert(alloc);
  ci_assert(rs_out);
  ci_assert(ifindices_len <= 0 || ifindices != NULL);

  rc = oo_version_check(alloc);
  if( rc < 0 )
    goto fail1;

  rs = CI_ALLOC_OBJ(tcp_helper_resource_t);
  if( !rs ) {
    rc = -ENOMEM;
    goto fail1;
  }
  oo_atomic_set(&rs->ref_count, 1);
  ni = &rs->netif;

  rc = oo_get_nics(rs, alloc, ifindices, ifindices_len);
  if( rc < 0 )
    goto fail2;

  /* Allocate an instance number. */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  rs->id = ci_id_pool_alloc(&THR_TABLE.instances);
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  if (rs->id == CI_ID_POOL_ID_NONE) {
    OO_DEBUG_ERR(ci_log("%s: out of instances", __FUNCTION__));
    rc = -EBUSY;
    goto fail3;
  }

  rs->trusted_lock = OO_TRUSTED_LOCK_UNLOCKED;
  rs->k_ref_count = 1;          /* 1 reference for userland */
  alloc->in_name[CI_CFG_STACK_NAME_LEN] = '\0';
  strcpy(rs->name, alloc->in_name);

  ni->opts = *opts;
  ci_netif_config_opts_rangecheck(&ni->opts);

  /* Allocate buffers for shared state, hardware resources etc. */
  rc = allocate_netif_resources(alloc, rs);
  if( rc < 0 ) goto fail4;

  /* Prepare per-socket data structures, and allocate the first few socket
  ** buffers. */
  ni->ep_tbl_max = ci_pow2(NI_OPTS(ni).max_ep_bufs_ln2);
  ni->ep_tbl_n = 0;
  ni->ep_tbl = CI_VMALLOC_ARRAY(tcp_helper_endpoint_t*, ni->ep_tbl_max);
  if( ni->ep_tbl == 0 ) {
    OO_DEBUG_ERR(ci_log("tcp_helper_rm_alloc: failed to allocate ep_tbl"));
    rc = -ENOMEM;
    goto fail5;
  }
#if CI_CFG_USERSPACE_PIPE
  CI_ZERO_ARRAY(ni->ep_tbl, ni->ep_tbl_max);
#endif

  /* do this after the kernel netif has been constructed as we rewrite the
   * netifs addr_spc_id.
   */
  ci_addr_spc_id_set(&alloc->out_addr_spc_id, current->mm);

  ci_irqlock_ctor(&rs->lock);
  ci_sllist_init(&rs->ep_tobe_closed);
  rs->callback_fn = NULL;
  ni->flags = alloc->in_flags;
  ni->uid = ci_getuid();
  ni->euid = ci_geteuid();
  ci_netif_state_init(&rs->netif, alloc->in_cpu_khz, alloc->in_name);
  OO_STACK_FOR_EACH_INTF_I(&rs->netif, intf_i) {
    nic = efrm_client_get_nic(rs->nic[intf_i].oo_nic->efrm_client);
    if( nic->flags & NIC_FLAG_ONLOAD_UNSUPPORTED )
      ni->state->flags |= CI_NETIF_FLAG_ONLOAD_UNSUPPORTED;
  }
#ifndef NDEBUG
  ni->state->lock.lock = CI_EPLOCK_LOCKED;
#endif
  efab_tcp_helper_more_socks(rs);
#ifndef NDEBUG
  ni->state->lock.lock = 0;
#endif

  /* At this point, we are certain that construction of the netif will not
   * fail, so we move out of "Uninitialised" and into "Locked".
   */
  ci_assert_equal(ni->state->lock.lock, CI_EPLOCK_UNINITIALISED);
  ni->state->lock.lock = CI_EPLOCK_LOCKED;
  CI_MAGIC_SET(ni, NETIF_MAGIC);

  if( (rc = ci_netif_init_fill_rx_rings(ni)) != 0 )
    goto fail5;

  /* We're about to expose this stack to other people.  So we should be
   * sufficiently initialised here that other people don't get upset.
   */
  if( alloc->in_name[0] ) {
    rc = efab_thr_table_insert_name(rs, alloc->in_name);
    if( rc != 0 )
      goto fail5;
  }
  else
    efab_thr_table_insert(rs);
  /* Now other people can see this stack, so don't assume we have exclusive
   * access.  (But we do still have the lock).
   */
  efab_notify_stacklist_change(rs);

  ci_netif_unlock(ni);

  /* We deliberately avoid starting periodic timer and callback until now,
   * so we don't have to worry about stopping them if we bomb out early.
   */
  OO_STACK_FOR_EACH_INTF_I(&rs->netif, intf_i) {
    if( NI_OPTS(ni).int_driven )
      efrm_eventq_register_callback(rs->nic[intf_i].vi_rs,
                                    &oo_handle_wakeup_int_driven,
                                    &rs->nic[intf_i]);
    else
      efrm_eventq_register_callback(rs->nic[intf_i].vi_rs,
                                    &oo_handle_wakeup_or_timeout,
                                    &rs->nic[intf_i]);
  }
  tcp_helper_initialize_and_start_periodic_timer(rs);
  if( NI_OPTS(ni).int_driven )
    tcp_helper_request_wakeup(netif2tcp_helper_resource(ni));

  alloc->out_netif_mmap_bytes = rs->mem_mmap_bytes;
  alloc->out_nic_set = ni->nic_set;
  *rs_out = rs;
  OO_DEBUG_RES(ci_log("tcp_helper_rm_alloc: allocated %u", rs->id));
  return 0;

 fail5:
  release_netif_resources(rs);
 fail4:
  ci_id_pool_free(&THR_TABLE.instances, rs->id, &THR_TABLE.lock);
 fail3:
 fail2:
  CI_FREE_OBJ(rs);
 fail1:
  return rc;
}



int tcp_helper_alloc_ul(ci_resource_onload_alloc_t* alloc,
                        const int* ifindices, int ifindices_len,
                        tcp_helper_resource_t** rs_out)
{
  ci_netif_config_opts* opts;
  int rc;

  if( (alloc->in_flags & CI_NETIF_FLAGS_PHYS_ADDR_MODE))
    /* User-level is not allowed to use physical address mode.
     * VI-in-VF turns physicall address mode later. */
    return -EPERM;
  if( alloc->in_flags & CI_NETIF_FLAGS_ISCSI )
    /* iSCSI options do not work at user-level. */
    return -EPERM;

  if( (opts = kmalloc(sizeof(*opts), GFP_KERNEL)) == NULL )
    return -ENOMEM;
  rc = -EFAULT;
  if( copy_from_user(opts, CI_USER_PTR_GET(alloc->in_opts), sizeof(*opts)) )
    goto out;

  rc = tcp_helper_rm_alloc(alloc, opts, ifindices, ifindices_len, rs_out);
 out:
  kfree(opts);
  return rc;
}



int tcp_helper_alloc_kernel(ci_resource_onload_alloc_t* alloc,
                            const ci_netif_config_opts* opts,
                            const int* ifindices, int ifindices_len,
                            tcp_helper_resource_t** rs_out)
{
  return tcp_helper_rm_alloc(alloc, opts, ifindices, ifindices_len, rs_out);
}


/*--------------------------------------------------------------------
 *!
 * Called when reference count on a TCP helper resource reaches zero.
 * The code is arranged so that this happens when the user-mode closes
 * the last efab file - irrespective of whether any TCP connections
 * need to live on
 *
 * At this stage we need to recover from corruption of the shared eplock
 * state - for exmaple, user application may have crashed whilst holding
 * this lock. However, we need to be race free against valid kernel users
 * of this lock - therefore, we proceed only once we have obtained the
 * kernel netif lock
 *
 * \param trs             Efab resource
 *
 *--------------------------------------------------------------------*/

static void
tcp_helper_rm_free(tcp_helper_resource_t* trs)
{
  int safe_to_destroy;
  unsigned l, new_l;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 1);

  OO_DEBUG_TCPH(ci_log("%s: [%u]", __FUNCTION__, trs->id));

  do {
    l = trs->trusted_lock;
    /* NB. We clear other flags when setting AWAITING_FREE.
     * tcp_helper_rm_free_locked() will close pending sockets, and other
     * flags are not critical.
     */
    new_l = OO_TRUSTED_LOCK_LOCKED | OO_TRUSTED_LOCK_AWAITING_FREE;
  } while( ci_cas32u_fail(&trs->trusted_lock, l, new_l) );

  if( l & OO_TRUSTED_LOCK_LOCKED )
    /* Lock holder will call efab_tcp_helper_rm_free_locked(). */
    return;

  safe_to_destroy = 1;
  efab_tcp_helper_rm_free_locked(trs, safe_to_destroy);
  OO_DEBUG_TCPH(ci_log("%s: [%u] done", __FUNCTION__, trs->id));
}


void
efab_thr_release(tcp_helper_resource_t *thr)
{
  ci_irqlock_state_t lock_flags;
  unsigned tmp;
  int is_ref;

  TCP_HELPER_RESOURCE_ASSERT_VALID(thr, 0);


  if( ! oo_atomic_dec_and_test(&thr->ref_count) ) {
    if( oo_atomic_read(&thr->ref_count) == 1 )
      efab_notify_stacklist_change(thr);
    return;
  }
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  if( (is_ref = oo_atomic_read(&thr->ref_count)) == 0 ) {
    /* Interlock against efab_thr_table_lookup(). */
    do {
      tmp = thr->k_ref_count;
      ci_assert( ! (tmp & TCP_HELPER_K_RC_DEAD) );
      ci_assert( ! (tmp & TCP_HELPER_K_RC_NO_USERLAND) );
    } while( ci_cas32_fail(&thr->k_ref_count, tmp,
                           tmp | TCP_HELPER_K_RC_NO_USERLAND) );
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  if( ! is_ref )
    tcp_helper_rm_free(thr);
}


/*--------------------------------------------------------------------
 *!
 * Enqueues a work-item to call tcp_helper_dtor() at a safe time.
 *
 * \param trs             TCP helper resource
 *
 *--------------------------------------------------------------------*/

static void
tcp_helper_dtor_schedule(tcp_helper_resource_t * trs)
{
  OO_DEBUG_TCPH(ci_log("%s [%u]: starting", __FUNCTION__, trs->id));

  ci_workitem_init(&trs->work_item,
                   (CI_WITEM_ROUTINE)(tcp_helper_dtor), trs);
  ci_verify( ci_workqueue_add(&CI_GLOBAL_WORKQUEUE, &trs->work_item) == 0);

}


/*--------------------------------------------------------------------
 * Called when [trs->k_ref_count] goes to zero.  This can only happen
 * after all references to the resource have gone, and all sockets have
 * reached closed.
 *
 * \param trs               TCP helper resource
 * \param can_destroy_now   OK to destroy now?  (else schedule work item)
 *--------------------------------------------------------------------*/

static void
efab_tcp_helper_k_ref_count_is_zero(tcp_helper_resource_t* trs,
                                                int can_destroy_now)
{
  /* although we have atomically got to zero we still have to contend
   * with a possible race from the resource manager destruction
   * (which needs the ability to force destruction of orphaned resources)
   * Therefore, we still have to test whether resource is in the list
   */
  ci_irqlock_state_t lock_flags;

  ci_assert(trs);
  ci_assert_equal(TCP_HELPER_K_RC_REFS(trs->k_ref_count), 0);
  ci_assert(trs->k_ref_count & TCP_HELPER_K_RC_NO_USERLAND);
  ci_assert(trs->k_ref_count & TCP_HELPER_K_RC_DEAD);

  OO_DEBUG_TCPH(ci_log("%s: [%u] k_ref_count=%x can_destroy_now=%d",
                       __FUNCTION__, trs->id, trs->k_ref_count,
                       can_destroy_now));

  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  if( !ci_dllink_is_free(&trs->all_stacks_link) ) {
    ci_dllist_remove(&trs->all_stacks_link);
    ci_dllink_mark_free(&trs->all_stacks_link);
  }
  else
    trs = 0;
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  if( trs ) {
    if( can_destroy_now )  tcp_helper_dtor(trs);
    else                   tcp_helper_dtor_schedule(trs);
  }
  OO_DEBUG_TCPH(ci_log("%s: finished", __FUNCTION__));
}


/*--------------------------------------------------------------------
 *!
 * Called to release a kernel reference to a stack.  This is called
 * by ci_drop_orphan() when userlevel is no longer around.
 *
 * \param trs             TCP helper resource
 * \param can_destroy_now true if in a context than can call destructor
 *
 *--------------------------------------------------------------------*/

void
efab_tcp_helper_k_ref_count_dec(tcp_helper_resource_t* trs,
                                     int can_destroy_now)
{
  int tmp;

  ci_assert(NULL != trs);

  OO_DEBUG_TCPH(ci_log("%s: [%d] k_ref_count=%x can_destroy_now=%d",
                       __FUNCTION__, trs->id, trs->k_ref_count,
                       can_destroy_now));
  ci_assert(~trs->k_ref_count & TCP_HELPER_K_RC_DEAD);

 again:
  tmp = trs->k_ref_count;
  if( TCP_HELPER_K_RC_REFS(tmp) == 1 ) {
    /* No-one apart from us is referencing this stack any more.  Mark it as
    ** dead to prevent anyone grabbing another reference.
    */
    if( ci_cas32_fail(&trs->k_ref_count, tmp,
                     TCP_HELPER_K_RC_DEAD | TCP_HELPER_K_RC_NO_USERLAND) )
      goto again;
    efab_tcp_helper_k_ref_count_is_zero(trs, can_destroy_now);
  }
  else
    if( ci_cas32_fail(&trs->k_ref_count, tmp, tmp - 1) )
      goto again;
}


/*! Close sockets.  Called with netif lock held.  Kernel netif lock may or
 * may not be held.
 */
static void
tcp_helper_close_pending_endpoints(tcp_helper_resource_t* trs)
{
  ci_irqlock_state_t lock_flags;
  tcp_helper_endpoint_t* ep;
  ci_sllink* link;

  OO_DEBUG_TCPH(ci_log("%s: [%d]", __FUNCTION__, trs->id));

  /* Ensure we're up-to-date so we get an ordered response to all packets.
  ** (eg. ANVL tcp_core 9.18).  Do it once here rather than per-socket.
  ** Also ensure all local packets are delivered before endpoint release.
  */
  ci_netif_poll(&trs->netif);

  while( ci_sllist_not_empty(&trs->ep_tobe_closed) ) {
    ci_irqlock_lock(&trs->lock, &lock_flags);

    /* DEBUG build: we are protected by netif lock, so the ep_tobe_closed
     * list can't be empty.
     * NDEBUG build: we are not protected by kernel netif lock, so
     * we should re-check that ep_tobe_closed is non-empty for security
     * reasons. */
    ci_assert( ci_sllist_not_empty(&trs->ep_tobe_closed) );
    if( ci_sllist_is_empty(&trs->ep_tobe_closed) ) {
      ci_irqlock_unlock(&trs->lock, &lock_flags);
      ci_log("%s: stack %d lock corrupted", __func__, trs->id);
      break;
    }
    link = ci_sllist_pop(&trs->ep_tobe_closed);
    ci_irqlock_unlock(&trs->lock, &lock_flags);

    ep = CI_CONTAINER(tcp_helper_endpoint_t, tobe_closed , link);
    OO_DEBUG_TCPH(ci_log("%s: %p [%u]: closing %d",
                         __FUNCTION__, trs, trs->id, OO_SP_FMT(ep->id)));
    oof_socket_mcast_del_all(efab_tcp_driver.filter_manager, &ep->oofilter);
    citp_waitable_all_fds_gone(&trs->netif, ep->id);
    ep->aflags = 0;
  }
}


static void
efab_tcp_helper_rm_reset_untrusted(tcp_helper_resource_t* trs)
{
  ci_netif *netif = &trs->netif;
  int i;

  for( i = 0; i < netif->ep_tbl_n; ++i ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(netif, i);
    if( (wo->waitable.state & CI_TCP_STATE_TCP_CONN) &&
        wo->waitable.state != CI_TCP_TIME_WAIT )
      ci_tcp_reset_untrusted(netif, &wo->tcp);
  }
}


/*--------------------------------------------------------------------
 *!
 * Called when reference count on a TCP helper resource reaches zero
 * AND we have the kernel netif lock. At this point we are safe to
 * correct any coruption of the netif lock. We either then
 * continue destroying the TCP helper resource OR we leave it around
 * so that it exists for connections that need to close gracefully
 * post application exit
 *
 * \param trs               TCP helper resource
 * \param safe_destroy_now  is it OK to destroy the resource now or
 *                          do we need to schedule for later
 *
 *--------------------------------------------------------------------*/

void
efab_tcp_helper_rm_free_locked(tcp_helper_resource_t* trs,
                               int safe_destroy_now)
{
  ci_netif* netif;
  int n_ep_closing;
  int netif_wedged = 0;
  unsigned i;
  int krc_old, krc_new;

  ci_assert(NULL != trs);
  ci_assert(trs->trusted_lock == (OO_TRUSTED_LOCK_LOCKED |
                                  OO_TRUSTED_LOCK_AWAITING_FREE));

  netif = &trs->netif;

  OO_DEBUG_TCPH(ci_log("%s [%u]: starting", __FUNCTION__, trs->id));

  /* shared user/kernel netif eplock "should" be unlocked at this time */
  if( ! (trs->netif.state->lock.lock & CI_EPLOCK_UNLOCKED) ) {
    if (CI_EPLOCK_UNINITIALISED == trs->netif.state->lock.lock) {
      OO_DEBUG_ERR(ci_log("%s [%u]: "
                          "ERROR netif did not fully initialise (0x%x)",
                          __FUNCTION__, trs->id,
                          trs->netif.state->lock.lock));
    }
    else {
      OO_DEBUG_ERR(ci_log("Stack [%d] released with lock stuck (0x%x)",
                          trs->id, trs->netif.state->lock.lock));
    }
    netif_wedged = 1;
  }

  if((netif->flags & CI_NETIF_FLAGS_ISCSI)!=0)
    /* Freeing iSCSI netif, claim wedged */
    netif_wedged=1;

  /* Grab the lock. */
  trs->netif.state->lock.lock = CI_EPLOCK_LOCKED;
  ci_wmb();

  /* Validate shared netif state before we continue
   *  \TODO: for now just clear in_poll flag
   */
  netif->state->in_poll = 0;


  /* If netif is wedged then for now instead of getting netif in
     a valid state we instead try never to touch it again */
#if CI_CFG_DESTROY_WEDGED
  if( netif_wedged ) {
    n_ep_closing = 0;
    goto closeall;
  }
#endif /*CI_CFG_DESTROY_WEDGED*/

  /* purge list of connections waiting to be closed
   *   - ones where we couldn't continue in fop_close because
   *     we didn't have the netif lock
   */
  tcp_helper_close_pending_endpoints(trs);

  for( i=0, n_ep_closing=0; i < netif->ep_tbl_n; i++ ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(netif, i);
    citp_waitable* w = &wo->waitable;

#if CI_CFG_USERSPACE_PIPE
    if( ! netif->ep_tbl[i] )
      continue;
#endif
    if( w->state == CI_TCP_STATE_FREE )  continue;

    if( w->state == CI_TCP_CLOSED ) {
      OO_DEBUG_ERR(ci_log("%s [%u]: ERROR endpoint %d leaked state "
                          "(cached=%d/%d)", __FUNCTION__, trs->id,
                          i, wo->tcp.cached_on_fd, wo->tcp.cached_on_pid));
      w->state = CI_TCP_STATE_FREE;
      continue;
    }

    OO_DEBUG_TCPH(ci_log("%s [%u]: endpoint %d in state %s", __FUNCTION__,
                         trs->id, i, ci_tcp_state_str(w->state)));
    /* \TODO: validate connection,
     *          - do we want to mark as closed or leave to close?
     *          - timers OK ?
     * for now we we just check the ORPHAN flag
     */
    if( ! (w->sb_aflags & CI_SB_AFLAG_ORPHAN) ) {
      OO_DEBUG_ERR(ci_log("%s [%u]: ERROR found non-orphaned endpoint %d in"
                          " state %s", __FUNCTION__, trs->id,
                          i, ci_tcp_state_str(w->state) ));
      ci_bit_set(&w->sb_aflags, CI_SB_AFLAG_ORPHAN_BIT);
    }
    ++n_ep_closing;
  }

  OO_DEBUG_TCPH(ci_log("%s: [%u] %d socket(s) closing", __FUNCTION__,
                       trs->id, n_ep_closing));

  if( n_ep_closing ) {
    /* Add in a ref to the stack for each of the closing sockets.  Set
     * CI_NETIF_FLAGS_DROP_SOCK_REFS so that the extra refs are dropped
     * when the sockets close.
     */
    do {
      krc_old = trs->k_ref_count;
      krc_new = krc_old + n_ep_closing;
    } while( ci_cas32_fail(&trs->k_ref_count, krc_old, krc_new) );
    netif->flags |= CI_NETIF_FLAGS_DROP_SOCK_REFS;
  }

  /* Drop lock so that sockets can proceed towards close. */
  ci_netif_unlock(&trs->netif);

 closeall:
  /* Don't need atomics here, because only we are permitted to touch
   * [trusted_lock] when AWAITING_FREE is set.
   */
  ci_assert(trs->trusted_lock == (OO_TRUSTED_LOCK_LOCKED |
                                  OO_TRUSTED_LOCK_AWAITING_FREE));
  trs->trusted_lock = OO_TRUSTED_LOCK_UNLOCKED;
  efab_tcp_helper_k_ref_count_dec(trs, safe_destroy_now);
  OO_DEBUG_TCPH(ci_log("%s: finished", __FUNCTION__));
}


static void
oo_trusted_lock_drop(tcp_helper_resource_t* trs)
{
  unsigned l, sl_flags;

  do {
    l = trs->trusted_lock;
    ci_assert(l & OO_TRUSTED_LOCK_LOCKED);

    if( l & OO_TRUSTED_LOCK_AWAITING_FREE ) {
      efab_tcp_helper_rm_free_locked(trs, 0);
      return;
    }
    else if( l & (OO_TRUSTED_LOCK_NEED_POLL_PRIME |
                  OO_TRUSTED_LOCK_CLOSE_ENDPOINT) ) {
      sl_flags = 0;
      if( l & OO_TRUSTED_LOCK_NEED_POLL_PRIME )
        sl_flags |= CI_EPLOCK_NETIF_NEED_PRIME | CI_EPLOCK_NETIF_NEED_POLL;
      if( l & OO_TRUSTED_LOCK_CLOSE_ENDPOINT )
        sl_flags |= CI_EPLOCK_NETIF_CLOSE_ENDPOINT;
      if( ef_eplock_trylock_and_set_flags(&trs->netif.state->lock, sl_flags) )
        ci_netif_unlock(&trs->netif);
    }
  } while( ci_cas32_fail(&trs->trusted_lock, l, OO_TRUSTED_LOCK_UNLOCKED) );
}


/* Returns true if flags were set, or false if the lock was not locked.
 * NB. We ignore flags if AWAITING_FREE.
 */
static int
oo_trusted_lock_set_flags_if_locked(tcp_helper_resource_t* trs, unsigned flags)
{
  unsigned l;

  do {
    l = trs->trusted_lock;
    if( ! (l & OO_TRUSTED_LOCK_LOCKED) )
      return 0;
    if( l & OO_TRUSTED_LOCK_AWAITING_FREE )
      /* We must not set flags when AWAITING_FREE. */
      return 1;
  } while( ci_cas32_fail(&trs->trusted_lock, l, l | flags) );

  return 1;
}


int
efab_tcp_helper_netif_try_lock(tcp_helper_resource_t* trs, 
                               ci_addr_spc_t addr_spc)
{
  if( trs->trusted_lock == OO_TRUSTED_LOCK_UNLOCKED &&
      ci_cas32u_succeed(&trs->trusted_lock, OO_TRUSTED_LOCK_UNLOCKED, 
                        OO_TRUSTED_LOCK_LOCKED) ) {
    if( ci_netif_trylock(&trs->netif) ) {
      ci_addr_spc_id_set(&trs->netif.addr_spc_id, addr_spc);
      return 1;
    }
    oo_trusted_lock_drop(trs);
  }
  return 0;
}


void
efab_tcp_helper_netif_unlock(tcp_helper_resource_t* trs)
{
  /* We need to ensure we DEFINETELY reset addr-spc before the netif lock
   * is unlocked.  This conditional is not strictly needed but useful as
   * the stack may run within the unlock callback.  If we reset the
   * addr_spc here then we may unnecessarily, delay this processing until a
   * further APC.  Therefore we have a peek at the flags and if the unlock
   * callback is going to run then we delay the reset of addr_spc until
   * then.  Obviously flag maybe set between peek and unlock but we cope
   * with this and this check makes this much rarer
   */
  if( (trs->netif.state->lock.lock & CI_EPLOCK_CALLBACK_FLAGS) == 0 )
    trs->netif.addr_spc_id = CI_ADDR_SPC_ID_KERNEL;
  ci_netif_unlock(&trs->netif);
  oo_trusted_lock_drop(trs);
}


/*--------------------------------------------------------------------
 *!
 * This function stops any async callbacks into the TCP helper resource
 * (waiting for any running callbacks to complete)
 *
 * Split into a separate function from tcp_helper_dtor only to make the
 * protection against potentail race conditions clearer
 *
 * \param trs             TCP helper resource
 *
 *--------------------------------------------------------------------*/

ci_inline void
tcp_helper_stop(tcp_helper_resource_t* trs)
{
  int intf_i;

  OO_DEBUG_TCPH(ci_log("%s [%u]: starting", __FUNCTION__, trs->id));

  /* stop the periodic timer callbacks*/
  tcp_helper_stop_periodic_timer(trs);

  /* stop callbacks from the event queue
        - wait for any running callback to complete */
  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i)
    efrm_eventq_kill_callback(trs->nic[intf_i].vi_rs);

  OO_DEBUG_TCPH(ci_log("%s [%d]: finished --- all async processes finished",
                       __FUNCTION__, trs->id));
}


/*--------------------------------------------------------------------
 *!
 * This is the code that was previously called directly when the TCP
 * helper resource ref count reaches zero to destruct the resource.
 * The call is now delayed until all endpoints have closed, or
 * forced when the TCP helper resource manager destructs.
 *
 * By the time we get here all attempts at graceful shutdown of sockets are
 * over.  This function is about releasing resources, and nothing else.  Do
 * not put any code that depends on the shared state in here!
 *
 * \param trs             TCP helper resource
 *
 *--------------------------------------------------------------------*/

static void
tcp_helper_dtor(tcp_helper_resource_t* trs)
{
  int rc;

  ci_assert(NULL != trs);

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 1);

  OO_DEBUG_TCPH(ci_log("%s [%u]: starting", __FUNCTION__, trs->id));

  if( ! (trs->netif.state->lock.lock & CI_EPLOCK_UNLOCKED) )
    /* We're doing this here because we need to be in a context that allows
     * us to block.
     */
    efab_tcp_helper_rm_reset_untrusted(trs);

  /* stop any async callbacks from kernel mode (waiting if necessary)
   *  - as these callbacks are the only events that can take the kernel
   *    netif lock, we know that once these callbacks are stopped the kernel
   *    lock will have been dropped
   *      => tcp_helper_rm_free_locked must have run to completion
   */
  tcp_helper_stop(trs);
#if defined __linux__
#if CI_CFG_SUPPORT_STATS_COLLECTION
  if( trs->netif.state->lock.lock != CI_EPLOCK_UNINITIALISED ) {
    /* Flush statistics gathered for the NETIF to global
     * statistics store before releasing resources of this NETIF.
     */
    ci_ip_stats_update_global(&trs->netif.state->stats_snapshot);
    ci_ip_stats_update_global(&trs->netif.state->stats_cumulative);
  }
#endif
#endif

  release_netif_resources(trs);

  rc = ci_id_pool_free(&THR_TABLE.instances, trs->id, &THR_TABLE.lock);
  OO_DEBUG_ERR(if (rc)
        ci_log("%s [%u]: failed to free instance number",
               __FUNCTION__, trs->id));

  OO_DEBUG_TCPH(ci_log("%s [%u]: finished", __FUNCTION__, trs->id));  
  CI_FREE_OBJ(trs);
}



/*--------------------------------------------------------------------
 *!
 * TCP driver management -- here for now while it needs a NIC to be around
 *
 * TODO: move somewhere more appropriate
 *
 *--------------------------------------------------------------------*/

int
efab_tcp_driver_ctor(unsigned max_macs, unsigned max_layer2_interfaces, 
                     unsigned max_routes)
{
  int rc;

  CI_ZERO(&efab_tcp_driver);

  /* Create driverlink filter. */
  if( (efab_tcp_driver.dlfilter = efx_dlfilter_ctor()) == NULL ) {
    rc = -ENOMEM;
    goto fail_dlf;
  }

  /* Create work queue */
  if ((rc = ci_workqueue_ctor(&CI_GLOBAL_WORKQUEUE)) < 0)
    goto fail_wq;
  
  /* Create TCP helpers table */
  if ((rc = thr_table_ctor(&efab_tcp_driver.thr_table)) < 0)
    goto fail_thr_table;

  /* Allocate resources & construct the control plane  */
  if ((rc = cicp_ctor(&efab_tcp_driver.cplane_handle, max_macs, 
                      max_layer2_interfaces, max_routes)) < 0)
    goto fail_cicp;

  if( (rc = oof_onload_ctor(&efab_tcp_driver, max_layer2_interfaces)) < 0 )
    goto fail_filter_manager;

  /* Construct the IP ID allocator */
  efab_ipid_ctor(&efab_tcp_driver.ipid);


  ci_atomic_set(&efab_tcp_driver.sendpage_pinpages_n, 0);
  /* This is was (EFHW_BUFFER_TBL_NUM >> 1), but the size is no longer
  ** known at compile time.  But the pinned-page stuff is on its way out,
  ** so no need to fix properly. */
  efab_tcp_driver.sendpage_pinpages_max = 4096;

  efab_tcp_driver.file_refs_to_drop = NULL;

  efab_tcp_driver.stack_list_seq = 0;
  ci_waitq_ctor(&efab_tcp_driver.stack_list_wq);

  return 0;

fail_filter_manager:
  cicp_dtor(&efab_tcp_driver.cplane_handle);
fail_cicp:
  thr_table_dtor(&efab_tcp_driver.thr_table);
fail_thr_table:
  ci_workqueue_dtor(&CI_GLOBAL_WORKQUEUE);
fail_wq:
  efx_dlfilter_dtor(efab_tcp_driver.dlfilter);
fail_dlf:
  OO_DEBUG_ERR(ci_log("%s: failed rc=%d", __FUNCTION__, rc));
  return rc;
}

void
efab_tcp_driver_dtor(void)
{
  OO_DEBUG_TCPH(ci_log("%s: kill stacks", __FUNCTION__));

  thr_table_dtor(&efab_tcp_driver.thr_table);

  if( efab_tcp_driver.file_refs_to_drop != NULL )
    oo_file_ref_drop_list_now(efab_tcp_driver.file_refs_to_drop);

  ci_verify( ci_workqueue_flush(&CI_GLOBAL_WORKQUEUE) == 0 );



  OO_DEBUG_TCPH(ci_log("%s: free resources", __FUNCTION__));

#ifndef NDEBUG
  if (ci_atomic_read(&efab_tcp_driver.sendpage_pinpages_n) != 0) {
    ci_log("%s: ERROR: sendpage_pinpages_n is %d at destruction",
           __FUNCTION__, ci_atomic_read(&efab_tcp_driver.sendpage_pinpages_n));
  }
#endif


  efab_ipid_dtor(&efab_tcp_driver.ipid);
  oof_onload_dtor(&efab_tcp_driver);
  cicp_dtor(&efab_tcp_driver.cplane_handle);
  ci_workqueue_dtor(&CI_GLOBAL_WORKQUEUE);
  efx_dlfilter_dtor(efab_tcp_driver.dlfilter);

  ci_waitq_dtor(&efab_tcp_driver.stack_list_wq);
}

static int
add_ep(tcp_helper_resource_t* trs, unsigned id, tcp_helper_endpoint_t* ep,
       int do_inc)
{
  ci_netif* ni = &trs->netif;
  citp_waitable_obj* wo;

  if( do_inc ) {
    if( id < ni->ep_tbl_n )  return -1;
    ci_assert_equal(id, ni->ep_tbl_n);
  }

  tcp_helper_endpoint_ctor(ep, trs, id);
  ni->ep_tbl[id] = ep;
#if CI_CFG_USERSPACE_PIPE
  oo_bit_array_set(ni->state->ep_buf_is_ep, id);
#endif

  if( do_inc ) {
    /* Only update [ep_tbl_n] once ep is installed. */
    ci_wmb();
    ni->state->n_ep_bufs = ++ni->ep_tbl_n;
  }

  wo = SP_TO_WAITABLE_OBJ(ni, ep->id);
  CI_ZERO(wo);  /* ??fixme */
  citp_waitable_init(ni, &wo->waitable, id);
  citp_waitable_obj_free(ni, &wo->waitable);
  return 0;
}

static int
install_socks(tcp_helper_resource_t* trs, unsigned id, int num, int are_new)
{
  tcp_helper_endpoint_t* eps[EP_BUF_PER_PAGE];
  ci_irqlock_state_t lock_flags;
  int i;

  if( are_new )
    ci_assert_equal(num, EP_BUF_PER_PAGE);
  else
    ci_assert_le(num, EP_BUF_PER_PAGE);

  /* Allocate the kernel state for each socket. */
  for( i = 0; i < num; ++i ) {
    eps[i] = CI_ALLOC_OBJ(tcp_helper_endpoint_t);
    if( ! eps[i] ) {
      OO_DEBUG_ERR(ci_log("%s: allocation failed", __FUNCTION__));
      while( i-- )  ci_free(eps[i]);
      return -ENOMEM;
    }
  }

  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  for( i = 0; i < EP_BUF_PER_PAGE; ++i, ++id ){
    OO_DEBUG_SHM(ci_log("%s: add ep %d", __FUNCTION__, id));
    if( add_ep(trs, id, eps[i], are_new) == 0 )
      eps[i] = NULL;
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  /* Prevents leaks! */
  for( i = 0; i < EP_BUF_PER_PAGE; ++i )
    if( eps[i] )
      ci_free(eps[i]);

  return 0;
}


int efab_tcp_helper_more_socks(tcp_helper_resource_t* trs)
{
  ci_netif* ni = &trs->netif;
  int rc;

  if( ni->ep_tbl_n >= ni->ep_tbl_max )  return -ENOSPC;

  rc = ci_shmbuf_demand_page(&ni->pages_buf,
                             (ni->ep_tbl_n * EP_BUF_SIZE) >> CI_PAGE_SHIFT,
                             &THR_TABLE.lock);
  if( rc < 0 ) {
    OO_DEBUG_ERR(ci_log("%s: demand failed (%d)", __FUNCTION__, rc));
    return rc;
  }

  return install_socks(trs, ni->ep_tbl_n, EP_BUF_PER_PAGE, CI_TRUE);
}

#if CI_CFG_USERSPACE_PIPE
/* Allocate additional bufs_num buffers. IDs of the buffers should be
 * continous as only beginning of the region is returned to the userspace!
 */
int efab_tcp_helper_more_pipe_bufs(ci_netif* ni,
                                   ci_int32 bufs_num,
                                   ci_int32* bufs_start)
{
  ci_irqlock_state_t lock_flags;
  int i;
  unsigned id;
  int rc;

  ci_assert(ni);
  ci_assert(bufs_start);

  if( bufs_num % EP_BUF_PER_PAGE != 0 )
    bufs_num += EP_BUF_PER_PAGE - (bufs_num % EP_BUF_PER_PAGE);
  ci_assert(bufs_num % EP_BUF_PER_PAGE == 0);

  id = ni->ep_tbl_n;

  /* do we have enough space? */
  if (id + bufs_num - 1 > ni->ep_tbl_max) return -ENOSPC;

  /* allocate new pages */
  for (i = 0; i < bufs_num / EP_BUF_PER_PAGE; i++) {
    rc = ci_shmbuf_demand_page(&ni->pages_buf,
                               ((id * EP_BUF_SIZE) >> CI_PAGE_SHIFT) + i,
                               &THR_TABLE.lock);
    if( rc < 0 ) {
      ci_log("%s: demand failed (%d)", __FUNCTION__, rc);
      return rc;
    }
  }

  *bufs_start = id;

  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  /* this modification shoud be done under lock as it's also
   * done from add_ep() function - see below */
  ni->ep_tbl_n += bufs_num;
  ci_wmb();
  ni->state->n_ep_bufs = ni->ep_tbl_n;
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  return 0;
}

int efab_tcp_helper_pipebufs_to_socks(tcp_helper_resource_t* trs)
{
  struct oo_pipe_buf* pbuf;
  oo_sp id;
  ci_uint32 len;
  ci_netif *ni = &trs->netif;
  int i;
  
  ci_assert(OO_SP_NOT_NULL(ni->state->free_pipe_bufs));
  ci_assert(ci_netif_is_locked(ni));

  pbuf = SP_TO_PIPE_BUF(ni, ni->state->free_pipe_bufs);
  ni->state->free_pipe_bufs = pbuf->next;
  id = pbuf->id;
  len = pbuf->length;

  for( i = 0; i * EP_BUF_PER_PAGE < len; i++) {
    int rc = install_socks(trs, id + i * EP_BUF_PER_PAGE,
                    CI_MIN(EP_BUF_PER_PAGE, len - i * EP_BUF_PER_PAGE),
                    CI_FALSE);
    if( rc != 0 )
      return rc;
  }

  return 0;
}
#endif



/*! map offset in shared data to physical page frame number */
unsigned
tcp_helper_rm_nopage_mem(tcp_helper_resource_t* trs,
                                         void* opaque, unsigned long offset,
                                         unsigned long map_size)
{
  ci_netif* ni = &trs->netif;

  OO_DEBUG_SHM(ci_log("%s: %u", __FUNCTION__, trs->id));

  /* NB: the order in which offsets are compared against shared memory
         areas must be the same order that is used to allocate those offsets in
         allocate_netif_resources() above
  */

  if( offset < ci_contig_shmbuf_size(&ni->state_buf) ) {
    unsigned rc =  ci_contig_shmbuf_nopage(&ni->state_buf, offset);
    OO_DEBUG_SHM(ci_log("1 ... ci_shmbuf_nopage() = %u", rc));
    return rc;
  }

  offset -= ci_contig_shmbuf_size(&ni->state_buf);

  if( offset < ci_shmbuf_size(&ni->pages_buf) ) {
    unsigned rc =  ci_shmbuf_nopage(&ni->pages_buf, offset);
    OO_DEBUG_SHM(ci_log("2 ... ci_shmbuf_nopage() = %u", rc));
    return rc;
  }

  offset -= ci_shmbuf_size(&ni->pages_buf);

  {
    unsigned int page_frameno;
    if (cicp_nopage_found(&ni->cplane, opaque, &offset, &page_frameno))
      return page_frameno;
  }

  ci_assert(0);
  return (unsigned) -1;
}


static void
efab_tcp_helper_more_bufs_failed(tcp_helper_resource_t* trs, int rc)
{
  /* We've failed to allocate more packet buffers -- we're out of resources
   * (probably buffer table).  We don't want to keep trying to allocate and
   * failing -- that just makes performance yet worse.  So reset the
   * various packet limits, preserving relative sizes.
   */
  ci_netif* ni = &trs->netif;
  int new_max_packets = ni->pkt_sets_n << PKTS_PER_SET_S;
  ni->pkt_sets_max = ni->pkt_sets_n;
  ni->state->pkt_sets_max = ni->pkt_sets_max;
  NI_OPTS(ni).max_rx_packets = (ci_int32)
    ((uint64_t) NI_OPTS(ni).max_rx_packets * new_max_packets /
     NI_OPTS(ni).max_packets);
  NI_OPTS(ni).max_tx_packets = (ci_int32)
    ((uint64_t) NI_OPTS(ni).max_tx_packets * new_max_packets /
     NI_OPTS(ni).max_packets);
  NI_OPTS(ni).max_packets = new_max_packets;
  ci_netif_set_rxq_limit(ni);

  if( ++ni->state->stats.bufset_alloc_fails == 1 )
    OO_DEBUG_ERR(ci_log(FN_FMT "Failed to allocate packet buffers (%d)",
                        FN_PRI_ARGS(&trs->netif), rc);
                 ci_log(FN_FMT "New limits: max_packets=%d rx=%d tx=%d "
                        "rxq_limit=%d", FN_PRI_ARGS(ni),
                        NI_OPTS(ni).max_packets, NI_OPTS(ni).max_rx_packets,
                        NI_OPTS(ni).max_tx_packets, NI_OPTS(ni).rxq_limit));
}


static int 
efab_tcp_helper_iobufset_alloc(tcp_helper_resource_t* trs, ef_iobufset* bufs,
                               struct iobufset_resource** all_out,
                               struct iobufset_resource** first_out)
{
  ci_netif* ni = &trs->netif;
  ci_int32 n_pages;
  int rc, intf_i;

  ci_assert_le(CI_CFG_PKT_BUF_SIZE, CI_PAGE_SIZE);

  n_pages = ef_iobufset_dimension(bufs, CI_CFG_PKT_BUF_SIZE, 
                                  PKTS_PER_SET, 4/*align*/);

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    all_out[intf_i] = NULL;
  *first_out = NULL;

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    rc = efrm_iobufset_resource_alloc(n_pages,
                                      efrm_vi_get_pd(trs->nic[intf_i].vi_rs),
                                      *first_out, &all_out[intf_i]);
    if( rc < 0 ) {
      OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
        if( all_out[intf_i] != NULL )
          efrm_iobufset_resource_release(all_out[intf_i]);
      return rc;
    }
    if( *first_out == NULL )
      *first_out = all_out[intf_i];
  }
  ci_assert(*first_out != NULL);

  bufs->bufs_addr = EFHW_BUFFER_ADDR((*first_out)->buf_tbl_alloc.base, 0);
  bufs->bufs_addr += PKT_START_OFF_MIN();
  bufs->bufs_ptr_off = 0;
  bufs->bufs_mmap_bytes = (*first_out)->n_bufs * CI_PAGE_SIZE;
  return 0;
}


int
efab_tcp_helper_more_bufs(tcp_helper_resource_t* trs)
{
  struct iobufset_resource* iobrs[CI_CFG_MAX_INTERFACES];
  struct iobufset_resource* first_iobrs;
  ci_irqlock_state_t lock_flags;
  ci_netif* ni = &trs->netif;
  ci_netif_state* ns = ni->state;
  ef_iobufset* newbs;
  int i, rc, bufset_id, intf_i;

  newbs = (ef_iobufset*) kmalloc(sizeof(ef_iobufset), GFP_ATOMIC);
  if( newbs == NULL )
    return -ENOMEM;

  rc = efab_tcp_helper_iobufset_alloc(trs, newbs, iobrs, &first_iobrs);
  if(CI_UNLIKELY( rc < 0 )) {
    ci_free(newbs);
    efab_tcp_helper_more_bufs_failed(trs, rc);
    return rc;
  }
  /* check we get the size we are expecting */
  ci_assert_equal(newbs->bufs_size * PKTS_PER_SET, ns->pkt_set_bytes);
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ci_assert(iobrs[intf_i] != NULL);
  ci_assert(first_iobrs != NULL);

  /* Install the new buffer allocation, protecting against multi-threads. */
  bufset_id = -1;
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);
  if( ni->pkt_sets_n < ni->pkt_sets_max ) {
    bufset_id = ni->pkt_sets_n;
    OO_DEBUG_SHM(ci_log("allocated new bufset id %d", bufset_id););
    ++ni->pkt_sets_n;
    ni->pkt_bufs[bufset_id] = newbs;
    ni->pkt_rs[bufset_id] = first_iobrs;
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
      ni->nic_hw[intf_i].pkt_rs[bufset_id] = iobrs[intf_i];
  }
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);

  if( bufset_id < 0 ) {
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
      efrm_iobufset_resource_release(iobrs[intf_i]);
    ci_free(newbs);
    OO_DEBUG_ERR(ci_log("%s: weirdness n=%d max=%d freepkts=%d", __FUNCTION__,
                        ni->pkt_sets_n, ni->pkt_sets_max,
                        OO_PP_FMT(ni->state->freepkts)));
    return -EIO;
  }

  ni->state->pkt_sets_n = ni->pkt_sets_n;
  ni->state->n_pkts_allocated = ni->pkt_sets_n << PKTS_PER_SET_S;

  /* Initialise the new buffers. */
  for( i = 0; i < PKTS_PER_SET; i++ ) {
    ci_ip_pkt_fmt* pkt;
    int id = (bufset_id * PKTS_PER_SET) + i;
    oo_pkt_p pp;

    OO_PP_INIT(ni, pp, id);
    pkt = __PKT(ni, pp, CI_TRUE);
    OO_PKT_PP_INIT(pkt, id);

    pkt->refcount = 0;
    pkt->n_buffers = 1;
    pkt->flags = 0;
    pkt->frag_next = OO_PP_NULL;

    OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
      if( ni->flags & CI_NETIF_FLAGS_PHYS_ADDR_MODE )
        pkt->base_addr[intf_i] = 
          (ef_addr)efrm_iobufset_dma_addr(iobrs[intf_i],
                                          ef_iobufset_off(newbs, i) +
                                          PKT_START_OFF_MIN());
      else 
        pkt->base_addr[intf_i] = ef_iobufset_addr(newbs, i);
    }
    pkt->base_offset = 0;


    pkt->next = ni->state->freepkts;
    ns->freepkts = OO_PKT_P(pkt);
    ++ns->n_freepkts;
  }

  CHECK_FREEPKTS(ni);
  return 0;
}


#ifdef CI_HAVE_OS_NOPAGE
static unsigned
tcp_helper_rm_nopage_iobuf(tcp_helper_resource_t* trs, void* opaque,
                           unsigned long offset, unsigned long map_size)
{
  ci_netif* ni = &trs->netif;
  ci_netif_state* ns = ni->state;
  int bufset_id, intf_i;

  OO_DEBUG_SHM(ci_log("%s: %u", __FUNCTION__, trs->id));

  if( offset < ns->buf_ofs ) {
    /* VIs (descriptor rings and event queues). */
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
      struct tcp_helper_nic* trs_nic = &trs->nic[intf_i];
      if( offset + CI_PAGE_SIZE <= trs_nic->vi_mem_mmap_bytes )
        return efab_vi_resource_nopage(trs_nic->vi_rs, opaque,
                                       offset, trs_nic->vi_mem_mmap_bytes);
      else
        offset -= trs_nic->vi_mem_mmap_bytes;
    }
    ci_assert(0);
  }
  else if( offset < ns->buf_ofs + ni->pkt_sets_max * ns->pkt_set_bytes ) {
    offset -= ns->buf_ofs;
    map_size -= ns->buf_ofs;
    bufset_id = offset / ns->pkt_set_bytes;

    if( ! ni->pkt_bufs[bufset_id] ) {
      /* Linux walks VMAs on core dump, suppress the message */
      if( ~current->flags & PF_DUMPCORE )
        OO_DEBUG_ERR(ci_log("%s: %u BAD offset=%lx bufset_id=%d",
			__FUNCTION__, trs->id, offset, bufset_id));
      return (unsigned) -1;
    }

    offset -= bufset_id * ns->pkt_set_bytes;
    map_size = ns->pkt_set_bytes;

    return efab_iobufset_resource_nopage(ni->pkt_rs[bufset_id], opaque, offset,
                                         map_size);
  } else {
    OO_DEBUG_SHM(ci_log("%s: %u offset %ld too great",
		     __FUNCTION__, trs->id, offset));
  }

  return (unsigned) -1;
}


unsigned
tcp_helper_rm_nopage(tcp_helper_resource_t* trs, void* opaque,
                     unsigned long offset, unsigned long map_size)
{

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 0);

  OO_DEBUG_SHM(ci_log("%s: %u", __FUNCTION__, trs->id));

  if( map_size == trs->mem_mmap_bytes )
    return tcp_helper_rm_nopage_mem(trs, opaque, offset, map_size);
  else if( map_size == trs->buf_mmap_bytes )
    return tcp_helper_rm_nopage_iobuf(trs, opaque, offset, map_size);
  else {
    OO_DEBUG_SHM(ci_log("%s: map_size:%ld mem_mmap_bytes:%d buf_mmap_bytes:%d",
                     __FUNCTION__, map_size, trs->mem_mmap_bytes,
		     trs->buf_mmap_bytes));
    return (unsigned) -1;
  }

  /* We currently provide no nopage support for dynamic ep_bufs or
   * pkt_bufs.  In theory, all that would have to be done is iterrate
   * through the unmapped but allocated bufs looking for the address.  Note
   * that this routine gives us the offset, so it will need to be changed!
   * FIXME
   */
}

#endif	/* CI_HAVE_OS_NOPAGE */


void
tcp_helper_rm_dump(int fd_type, oo_sp sock_id,
                   tcp_helper_resource_t* trs, const char *line_prefix) 
{
  ci_netif* ni;
  int intf_i;
  unsigned i;

  if( trs == NULL ) {
    ci_dllink *link;
    CI_DLLIST_FOR_EACH(link, &THR_TABLE.all_stacks) {
      trs = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);
      tcp_helper_rm_dump(CI_PRIV_TYPE_NETIF, OO_SP_NULL, trs, line_prefix);
      for( i = 0; i < trs->netif.ep_tbl_n; ++i )
        if (trs->netif.ep_tbl[i]) {
          ci_sock_cmn *s = ID_TO_SOCK(&trs->netif, i);
          if (s->b.state == CI_TCP_STATE_FREE || s->b.state == CI_TCP_CLOSED)
            continue;
          tcp_helper_rm_dump(s->b.state == CI_TCP_STATE_UDP ?
                             CI_PRIV_TYPE_UDP_EP : CI_PRIV_TYPE_TCP_EP,
                             OO_SP_FROM_INT(&trs->netif, i), trs, line_prefix);
        }
    }
    return;
  }

  ni = &trs->netif;

  switch (fd_type) {
  case CI_PRIV_TYPE_NETIF: 
    ci_log("%stcp helper used as a NETIF mmap_bytes=%x", 
           line_prefix, trs->mem_mmap_bytes); 
    break;
  case CI_PRIV_TYPE_NONE:
    ci_log("%stcp helper, unspecialized (?!)", line_prefix);
    break;
  case CI_PRIV_TYPE_TCP_EP:
  case CI_PRIV_TYPE_UDP_EP:
    ci_log("%stcp helper specialized as %s endpoint with id=%u", 
           line_prefix, fd_type == CI_PRIV_TYPE_TCP_EP ? "TCP":"UDP", 
           OO_SP_FMT(sock_id));
    citp_waitable_dump(ni, SP_TO_WAITABLE(ni, sock_id), line_prefix);
    break;
#if CI_CFG_USERSPACE_PIPE
  case CI_PRIV_TYPE_PIPE_READER:
  case CI_PRIV_TYPE_PIPE_WRITER:
    ci_log("%stcp_helper specialized as PIPE-%s endpoint with id=%u",
           line_prefix,
           fd_type == CI_PRIV_TYPE_PIPE_WRITER ? "WR" : "RD",
           OO_SP_FMT(sock_id));
    citp_waitable_dump(ni, SP_TO_WAITABLE(ni, sock_id), line_prefix);
    break;
#endif
  default:
    ci_log("%sUNKNOWN fd_type (%d)", line_prefix, fd_type);
  }

  ci_log("%sref_count=%d k_ref_count=%d", line_prefix,
         oo_atomic_read(&trs->ref_count), trs->k_ref_count);

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ci_log("%svi[%d]: %d", line_prefix, intf_i,
           ef_vi_instance(&ni->nic_hw[intf_i].vi));
}


/**********************************************************************
 * Callbacks (timers, interrupts)
 */


/*--------------------------------------------------------------------
 *!
 * We have the lock - run the stack
 *
 *--------------------------------------------------------------------*/



/*--------------------------------------------------------------------
 *!
 * Eventq get lock, do callback
 *    - try and get lock and if we can poll the stack
 *
 * \param rs            TCP helper resource
 * \param prime_async   request wakeup?
 *
 * \return              > 0 - stack polled
 *                      = 0 - stack not polled
 *                      < 0 - quit eventq_callback will complete later
 *
 *--------------------------------------------------------------------*/


/*--------------------------------------------------------------------
 *!
 * Eventq callback
 *    - call OS dependent code to try and poll the stack
 *    - reprime timer and/of request wakeup if needed
 *
 *--------------------------------------------------------------------*/

static void tcp_helper_wakeup(tcp_helper_resource_t* trs, int intf_i)
{
  ci_netif* ni = &trs->netif;
  int n, prime_async;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, -1);
  OO_DEBUG_RES(ci_log(FN_FMT, FN_PRI_ARGS(ni)));
  CITP_STATS_NETIF_INC(ni, interrupts);

  /* Must clear this before the poll rather than waiting till later */
  ci_bit_clear(&ni->state->evq_primed, intf_i);

  /* Don't reprime if someone is spinning -- let them poll the stack. */
  prime_async = ! ni->state->is_spinner;

  if( ci_netif_intf_has_event(ni, intf_i) ) {
    if( efab_tcp_helper_netif_try_lock(trs, CI_ADDR_SPC_ID_KERNEL) ) {
      CITP_STATS_NETIF(++ni->state->stats.interrupt_polls);
      ni->state->poll_did_wake = 0;
      n = ci_netif_poll(ni);
      CITP_STATS_NETIF_ADD(ni, interrupt_evs, n);
      if( ni->state->poll_did_wake ) {
        prime_async = 0;
        CITP_STATS_NETIF_INC(ni, interrupt_wakes);
      }
      efab_tcp_helper_netif_unlock(trs);
    }
    else {
      /* Couldn't get the lock.  We take this as evidence that another thread
       * is alive and doing stuff, so no need to re-enable interrupts.  The
       * EF_INT_REPRIME option overrides.
       */
      CITP_STATS_NETIF_INC(ni, interrupt_lock_contends);
      if( ! NI_OPTS(ni).int_reprime )
        prime_async = 0;
    }
  }
  else {
    CITP_STATS_NETIF_INC(ni, interrupt_no_events);
  }

  if( prime_async )
    if( ni->state->last_spin_poll_frc > ni->state->last_sleep_frc )
      /* A spinning thread has polled the stack more recently than a thread
       * has gone to sleep.  We assume the spinning thread will handle
       * network events (or enable interrupts at some point), so no need to
       * enable interrupts here.
       */
      prime_async = 0;

  if( prime_async ) {
    if( ci_bit_test(&ni->state->evq_primed, intf_i) )
      tcp_helper_request_wakeup_nic(trs, intf_i);
    else if( ! ci_bit_test_and_set(&ni->state->evq_primed, intf_i) )
      tcp_helper_request_wakeup_nic(trs, intf_i);
    CITP_STATS_NETIF_INC(ni, interrupt_primes);
  }
}


static void tcp_helper_timeout(tcp_helper_resource_t* trs, int intf_i)
{
#if CI_CFG_HW_TIMER
  ci_netif* ni = &trs->netif;
  int i, n;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, -1);
  OO_DEBUG_RES(ci_log(FN_FMT, FN_PRI_ARGS(ni)));
  CITP_STATS_NETIF_INC(ni, timeout_interrupts);

  /* Re-prime the timer here to ensure it is re-primed even if we don't
   * call ci_netif_poll() below.  Updating [evq_last_prime] ensures we
   * won't re-prime it again in ci_netif_poll().
   */
  ci_frc64(&ni->state->evq_last_prime);
  if( NI_OPTS(ni).timer_usec != 0 )
    OO_STACK_FOR_EACH_INTF_I(ni, i)
      ef_eventq_timer_prime(&ni->nic_hw[i].vi, NI_OPTS(ni).timer_usec);

  if( ci_netif_intf_has_event(ni, intf_i) ) {
    if( efab_tcp_helper_netif_try_lock(trs, CI_ADDR_SPC_ID_KERNEL) ) {
      CITP_STATS_NETIF(++ni->state->stats.timeout_interrupt_polls);
      ni->state->poll_did_wake = 0;
      if( (n = ci_netif_poll(ni)) ) {
        CITP_STATS_NETIF(ni->state->stats.timeout_interrupt_evs += n;
                         ni->state->stats.timeout_interrupt_wakes +=
                         ni->state->poll_did_wake);
      }
      efab_tcp_helper_netif_unlock(trs);
    }
    else {
      CITP_STATS_NETIF_INC(ni, timeout_interrupt_lock_contends);
    }
  }
  else {
    CITP_STATS_NETIF_INC(ni, timeout_interrupt_no_events);
  }
#endif
}


static void oo_handle_wakeup_or_timeout(void* context, int is_timeout,
                                        struct efhw_nic* nic)
{
  struct tcp_helper_nic* tcph_nic = context;
  tcp_helper_resource_t* trs;
  trs = CI_CONTAINER(tcp_helper_resource_t, nic[tcph_nic->intf_i], tcph_nic);

  if( ! CI_CFG_HW_TIMER || ! is_timeout )
    tcp_helper_wakeup(trs, tcph_nic->intf_i);
  else
    tcp_helper_timeout(trs, tcph_nic->intf_i);
}



static void oo_handle_wakeup_int_driven(void* context, int is_timeout,
                                        struct efhw_nic* nic_)
{
  struct tcp_helper_nic* tcph_nic = context;
  tcp_helper_resource_t* trs;
  ci_netif* ni;
  int n;

  trs = CI_CONTAINER(tcp_helper_resource_t, nic[tcph_nic->intf_i], tcph_nic);
  ni = &trs->netif;

  ci_assert( ! is_timeout );
  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, -1);
  CITP_STATS_NETIF_INC(ni, interrupts);

  /* Grab lock and poll, or set bit so that lock holder will poll.  (Or if
   * stack is being destroyed, do nothing).
   */
  while( 1 ) {
    if( ci_netif_intf_has_event(ni, tcph_nic->intf_i) ) {
      if( efab_tcp_helper_netif_try_lock(trs, CI_ADDR_SPC_ID_KERNEL) ) {
        CITP_STATS_NETIF(++ni->state->stats.interrupt_polls);
        ni->state->poll_did_wake = 0;
        n = ci_netif_poll(ni);
        CITP_STATS_NETIF_ADD(ni, interrupt_evs, n);
        if( ni->state->poll_did_wake )
          CITP_STATS_NETIF_INC(ni, interrupt_wakes);
        tcp_helper_request_wakeup_nic(trs, tcph_nic->intf_i);
        efab_tcp_helper_netif_unlock(trs);
        break;
      }
      else {
        CITP_STATS_NETIF_INC(ni, interrupt_lock_contends);
      }
    }
    else {
      CITP_STATS_NETIF_INC(ni, interrupt_no_events);
      tcp_helper_request_wakeup_nic(trs, tcph_nic->intf_i);
      break;
    }

    if( ef_eplock_set_flags_if_locked(&ni->state->lock,
                                      CI_EPLOCK_NETIF_NEED_POLL |
                                      CI_EPLOCK_NETIF_NEED_PRIME) ) {
      break;
    }
    else if( oo_trusted_lock_set_flags_if_locked(trs,
                                        OO_TRUSTED_LOCK_NEED_POLL_PRIME) ) {
      break;
    }
  }
}


/*--------------------------------------------------------------------
 *!
 * TCP helper timer implementation 
 *
 *--------------------------------------------------------------------*/

/*** Linux ***/
static int 
linux_set_periodic_timer(tcp_helper_resource_t* rs) 
{
  unsigned long t = net_random() % CI_TCP_HELPER_PERIODIC_FLOAT_T;

  if (atomic_read(&rs->timer_running) == 0) 
    return 0;

  return queue_delayed_work(rs->timer_wq, &rs->timer_work,
                            (CI_TCP_HELPER_PERIODIC_BASE_T) + t);
}

static void
linux_tcp_timer_do(struct work_struct *work)
{
#if !defined(EFX_NEED_WORK_API_WRAPPERS)
  tcp_helper_resource_t* rs = container_of(work, tcp_helper_resource_t,
                                           timer_work.work);
#else
  tcp_helper_resource_t* rs = container_of(work, tcp_helper_resource_t,
                                           timer_work);
#endif
  ci_netif* ni = &rs->netif;
  ci_uint64 now_frc;
  int rc;

  TCP_HELPER_RESOURCE_ASSERT_VALID(rs, -1);
  OO_DEBUG_VERB(ci_log("%s: running", __FUNCTION__));

  oo_timesync_update(CICP_HANDLE(ni));

  /* Avoid interfering if stack has been active recently.  This code path
   * is only for handling time-related events that have not been handled in
   * the normal course of things because we've not had any network events.
   */
  ci_frc64(&now_frc);
  if( now_frc - ni->state->evq_last_prime >
      ni->state->timer_prime_cycles * 5 ) {
    if( efab_tcp_helper_netif_try_lock(rs, CI_ADDR_SPC_ID_KERNEL) ) {
      rc = ci_netif_poll(ni);
      efab_tcp_helper_netif_unlock(rs);
      CITP_STATS_NETIF_INC(ni, periodic_polls);
      if( rc > 0 )
        CITP_STATS_NETIF_ADD(ni, periodic_evs, rc);
    }
    else {
      CITP_STATS_NETIF_INC(ni, periodic_lock_contends);
    }
  }

  linux_set_periodic_timer(rs);
}

static void
tcp_helper_initialize_and_start_periodic_timer(tcp_helper_resource_t* rs)
{
  snprintf(rs->timer_wq_name, sizeof(rs->timer_wq_name), "onload:%s-timer",
           rs->netif.state->pretty_name);
  rs->timer_wq = create_singlethread_workqueue(rs->timer_wq_name);
  INIT_DELAYED_WORK(&rs->timer_work, &linux_tcp_timer_do);
  atomic_set(&rs->timer_running, 1);
  linux_set_periodic_timer(rs);
}


static void
tcp_helper_stop_periodic_timer(tcp_helper_resource_t* rs)
{
  atomic_set(&rs->timer_running, 0);

  flush_workqueue(rs->timer_wq); /* it may re-spawn work */
  cancel_delayed_work(&rs->timer_work);
  flush_workqueue(rs->timer_wq); /* can't re-spawn since timer_running=0 */

  destroy_workqueue(rs->timer_wq);
}

/*--------------------------------------------------------------------*/

/** Solaris **/

/*--------------------------------------------------------------------
 *!
 * End of TCP helper timer implementation
 *
 *--------------------------------------------------------------------*/


void
efab_tcp_helper_close_endpoint(tcp_helper_resource_t* trs, oo_sp ep_id)
{
  ci_netif* ni;
  tcp_helper_endpoint_t* tep_p;
  ci_irqlock_state_t lock_flags;

  ni = &trs->netif;
  tep_p = ci_trs_ep_get(trs, ep_id);

  OO_DEBUG_TCPH(ci_log("%s: [%u] ep %d, trs k_ref_count %d", __FUNCTION__,
                       trs->id, OO_SP_FMT(ep_id), trs->k_ref_count));

  ci_assert(!(SP_TO_WAITABLE(ni, ep_id)->sb_aflags & CI_SB_AFLAG_ORPHAN));

  /* Drop ref to the OS socket.  Won't necessarily be the last reference to it;
   * there may also be one from the filter, and others from dup'd or forked
   * processes.  This needs to be done here rather since fput can block.
   */
  if( tep_p->os_socket != NULL ) {
    ci_irqlock_state_t lock_flags;

    if( SP_TO_WAITABLE(ni, ep_id)->state == CI_TCP_LISTEN ) {
      ci_tcp_socket_listen *tls = SP_TO_TCP_LISTEN(ni, ep_id);

      /* Shutdown() the os_socket.  This needs to be done in a blocking
       * context.
       * Alien sockets in accept queue should get lock for other stack,
       * so they also need blocking context.
       * Loopback sockets need this for unknown reason: bug28436.
       */
      if( tls->acceptq_n_alien == 0 )
        efab_tcp_helper_shutdown_os_sock(tep_p, SHUT_RDWR);
      else {
        ci_netif_lock(&trs->netif);
        ci_bit_set(&tls->s.b.sb_aflags, CI_SB_AFLAG_ORPHAN_BIT);
        tcp_helper_endpoint_shutdown(trs, ep_id, SHUT_RDWR, CI_TCP_LISTEN);
        ci_netif_unlock(&trs->netif);
      }
    }
    efab_tcp_helper_os_pollwait_unregister(tep_p);

    ci_irqlock_lock(&trs->lock, &lock_flags);
    oo_file_ref_drop(tep_p->os_socket);
    tep_p->os_socket = NULL;
    ci_irqlock_unlock(&trs->lock, &lock_flags);
  }

  /*! Add ep to the list in tcp_helper_resource_t for closing
    *   - we don't increment the ref count - as we need it to reach 0 when
    * the application exits i.e. crashes (even if its holding the netif lock)
    */
  ci_irqlock_lock(&trs->lock, &lock_flags);
  ci_sllist_push(&trs->ep_tobe_closed, &tep_p->tobe_closed);
  ci_irqlock_unlock(&trs->lock, &lock_flags);

  /* set flag in eplock to signify callback needed when netif unlocked */

  while( 1 )
    if( efab_tcp_helper_netif_try_lock(trs, CI_ADDR_SPC_ID_KERNEL) ) {
      OO_DEBUG_TCPH( ci_log("%s [%u]: closing ep %d",
                            __FUNCTION__, trs->id, OO_SP_FMT(ep_id)) );
      tcp_helper_close_pending_endpoints(trs);
      efab_tcp_helper_netif_unlock(trs);
      break;
    }
    else if( ef_eplock_set_flag_if_locked(&ni->state->lock,
                                          CI_EPLOCK_NETIF_CLOSE_ENDPOINT) ) {
      break;
    }
    else if( oo_trusted_lock_set_flags_if_locked(trs,
                                           OO_TRUSTED_LOCK_CLOSE_ENDPOINT) ) {
      break;
    }

  if( efab_tcp_driver.file_refs_to_drop != NULL )
    oo_file_ref_drop_list_now(NULL);
}


void generic_tcp_helper_close(ci_private_t* priv)
{
  tcp_helper_resource_t* trs;
  tcp_helper_endpoint_t* ep;

  ci_assert(CI_PRIV_TYPE_IS_ENDPOINT(priv->fd_type));
  trs = efab_priv_to_thr(priv);
  ep = ci_trs_ep_get(trs, priv->sock_id);


  if (ep->fasync_queue) {
    OO_DEBUG_SHM(ci_log("generic_tcp_helper_close removing fasync helper"));
    linux_tcp_helper_fop_fasync(-1, ci_privf(priv), 0);
  }


   efab_tcp_helper_close_endpoint(trs, ep->id);
}


/**********************************************************************
 * CI_RESOURCE_OPs.
 */

int
efab_attach_os_socket(tcp_helper_endpoint_t* ep, int os_sock_fd)
{
  int rc;
  ci_irqlock_state_t lock_flags;

  ci_assert(ep);
  ci_assert(IS_VALID_DESCRIPTOR(os_sock_fd));

  ci_irqlock_lock(&ep->thr->lock, &lock_flags);
  if( ep->os_socket != NULL ) {
    oo_file_ref_drop(ep->os_socket);
    ep->os_socket = NULL;
  }
  ci_irqlock_unlock(&ep->thr->lock, &lock_flags);

  rc = oo_file_ref_lookup(os_sock_fd, &ep->os_socket);
  if( rc < 0 ) {
    OO_DEBUG_ERR(ci_log("%s: %d:%d fd="DESCRIPTOR_FMT" lookup failed (%d)",
                        __FUNCTION__, ep->thr->id, OO_SP_FMT(ep->id),
                        DESCRIPTOR_PRI_ARG(os_sock_fd), rc));
    return rc;
  }
  efab_linux_sys_close(os_sock_fd);
  if( SP_TO_WAITABLE(&ep->thr->netif, ep->id)->state == CI_TCP_STATE_UDP )
    efab_tcp_helper_os_pollwait_register(ep);
  return 0;
}



/**********************************************************************
***************** Wakeups, callbacks, signals, events. ****************
**********************************************************************/

static void do_netif_callback(tcp_helper_resource_t* thr,
			      tcp_helper_endpoint_t* ep)
{
  citp_waitable_obj* wo = SP_TO_WAITABLE_OBJ(&thr->netif, ep->id);
  void (*fn)(void* arg, int why) = thr->callback_fn;

  if( fn == NULL )
    return;

  if( wo->waitable.callback_armed ) {
    /* Callbacks are only armed on TCP sockets. */
    if( tcp_rcv_usr(&wo->tcp) > (unsigned) wo->sock.so.rcvlowat ) {
      wo->waitable.callback_armed = CI_FALSE; /* deregister */
      fn(CI_USER_PTR_GET(wo->waitable.callback_arg),
         CI_TCP_HELPER_CALLBACK_RX_DATA);
    }
    else if( (wo->waitable.state & CI_TCP_STATE_ACCEPT_DATA) == 0 ) {
      wo->waitable.callback_armed = CI_FALSE; /* deregister */
      fn(CI_USER_PTR_GET(wo->waitable.callback_arg),
         CI_TCP_HELPER_CALLBACK_CLOSED);
      ci_assert(!wo->waitable.callback_armed);
    }
    else {
      /* Not enough data yet - ensure we keep getting notified. */
      ci_bit_set(&wo->waitable.wake_request, CI_SB_FLAG_WAKE_RX_B);
      tcp_helper_request_wakeup(thr);
    }
  }
}


void tcp_helper_endpoint_wakeup(tcp_helper_resource_t* thr,
                                tcp_helper_endpoint_t* ep)
{
  citp_waitable* w = SP_TO_WAITABLE(&thr->netif, ep->id);
  w->wake_request = 0;
  if( ci_waitable_active(&ep->waitq) ) {
    thr->netif.state->poll_did_wake = 1;
    CITP_STATS_NETIF(++thr->netif.state->stats.sock_wakes);
  }
  ci_waitable_wakeup_all(&ep->waitq);
  /* Check to see if application has requested ASYNC notification */
  if( ep->fasync_queue ) {
    LOG_TV(ci_log(NWS_FMT "async notification sig=%d sigown=%d",
                  NWS_PRI_ARGS(&thr->netif, w), w->sigsig, w->sigown));
    kill_fasync(&ep->fasync_queue, w->sigsig ? w->sigsig : SIGIO, POLL_IN);
    if( w->sigown )
      /* Ensure we keep getting notified. */
      ci_bit_set(&w->wake_request, CI_SB_FLAG_WAKE_RX_B);
  }
}






static void
wakeup_post_poll_list(tcp_helper_resource_t* thr)
{
  ci_netif* ni = &thr->netif;
  tcp_helper_endpoint_t* ep;
  int n = ni->ep_tbl_n;
  ci_ni_dllist_link* lnk;
  citp_waitable* w;

  LOG_TV(if( ci_ni_dllist_is_empty(ni, &ni->state->post_poll_list) )
           ci_log("netif_lock_callback: need_wake but empty"));

  /* [n] ensures the loop will terminate in reasonable time no matter how
  ** badly u/l behaves.
  */
  while( n-- > 0 && ci_ni_dllist_not_empty(ni, &ni->state->post_poll_list) ) {
    lnk = ci_ni_dllist_head(ni, &ni->state->post_poll_list);
    w = CI_CONTAINER(citp_waitable, post_poll_link, lnk);
    ci_ni_dllist_remove_safe(ni, &w->post_poll_link);
    ep = ci_netif_get_valid_ep(ni, W_SP(w));
    w->sb_flags = 0;
    tcp_helper_endpoint_wakeup(thr, ep);
    if( thr->callback_fn )
      do_netif_callback(thr, ep);
  }
}


/*--------------------------------------------------------------------
 *!
 * Callback installed with the netif (kernel/user mode shared) eplock
 * so we can get notified when the lock is dropped
 *
 * This code is either called with the kernel netif lock held (if the
 * common eplock is dropped from kernel mode). It can also be called
 * when user mode drops the eplock with the kernel lock not held.
 * However in this case we know the user mode still exists and has a
 * file open on efab. Therefore, we know that this cannot race with
 * efab_tcp_helper_rm_free_locked which is called whilst holding the kernel
 * lock once user mode has closed all efab file handles
 *
 * \param arg             TCP helper resource
 * \param lock_val        lock value
 *
 * \return                final lock value just before unlock
 *
 *--------------------------------------------------------------------*/

unsigned
efab_tcp_helper_netif_lock_callback(eplock_helper_t* epl, ci_uint32 lock_val)
{
  tcp_helper_resource_t* thr = CI_CONTAINER(tcp_helper_resource_t,
                                            netif.eplock_helper, epl);
  ci_netif* ni = &thr->netif;
  unsigned flags_set, clear_flags;
  unsigned after_unlock_flags = 0;
  ci_addr_spc_id_t orig_addr_spc_id = thr->netif.addr_spc_id;

  ci_assert(ci_netif_is_locked(ni));


  do {
    /* Restore the address space id if we've just looped. */
    thr->netif.addr_spc_id = orig_addr_spc_id;

    clear_flags = 0;

    if( lock_val & CI_EPLOCK_NETIF_IS_PKT_WAITER )
      if( ci_netif_pkt_tx_can_alloc_now(ni) ) {
        clear_flags |= CI_EPLOCK_NETIF_IS_PKT_WAITER;
        after_unlock_flags |= CI_EPLOCK_NETIF_PKT_WAKE;
        lock_val = ni->state->lock.lock;
      }

    /* Do this first as it might request another address space */
    if( lock_val & CI_EPLOCK_NETIF_SOCKET_LIST )
      lock_val = ci_netif_purge_deferred_socket_list(ni);

    /* Get flags set and clear them.  NB. Its possible no flags were set
    ** e.g. we tried to unlock the eplock (bottom of loop) but found
    ** someone had tried to lock it and therefore set the "need wake" bit.
    */
    flags_set = lock_val & CI_EPLOCK_NETIF_KERNEL_FLAGS;
    ef_eplock_clear_flags(&ni->state->lock, clear_flags | flags_set);
    after_unlock_flags |= flags_set;

    /* All code between here and the bottom of the loop should use
    ** [flags_set], and must not touch [lock_val].  If any flags
    ** subsequently get re-set, then we'll come round the loop again.
    */


    if( flags_set & CI_EPLOCK_NETIF_NEED_POLL ) {
      CITP_STATS_NETIF(++ni->state->stats.deferred_polls);
      ci_netif_poll(ni);
    }

    if( flags_set & CI_EPLOCK_NETIF_NEED_WAKE )
      wakeup_post_poll_list(thr);

    if( flags_set & CI_EPLOCK_NETIF_CLOSE_ENDPOINT )
      tcp_helper_close_pending_endpoints(thr);

    /* Hopefully about to drop netif lock, so clear the address space.  It
    ** gets restored (at the top of the loop) if instead we loop round
    ** again. */
    thr->netif.addr_spc_id = CI_ADDR_SPC_ID_KERNEL;

  } while ( !ef_eplock_try_unlock(&ni->state->lock, &lock_val,
                                  CI_EPLOCK_NETIF_KERNEL_FLAGS |
                                  CI_EPLOCK_NETIF_SOCKET_LIST) );

  ni->state->defer_work_count = 0;


  if( after_unlock_flags & CI_EPLOCK_NETIF_NEED_PRIME ) {
    int intf_i;
    if( NI_OPTS(ni).int_driven ) {
      /* TODO: When interrupt driven, evq_primed is never cleared, so we
       * don't know here which subset of interfaces needs to be primed.
       * Would be more efficient if we did.
       */
      OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
        tcp_helper_request_wakeup_nic(thr, intf_i);
    }
    else {
      tcp_helper_request_wakeup(thr);
    }
  }

  if( after_unlock_flags & CI_EPLOCK_NETIF_PKT_WAKE ) {
    CITP_STATS_NETIF_INC(&thr->netif, pkt_wakes);
    ci_waitq_wakeup(&thr->pkt_waitq);
  }

  return lock_val;
}


/**********************************************************************
***************** Iterators to find netifs ***************************
**********************************************************************/

/*--------------------------------------------------------------------
 *!
 * Called to iterate through all the various netifs, where we feel
 * safe to continue with an unlocked netif. This function guareetees
 * the netif pointer will remain valid BUT callees need to be aware
 * that other contexts could be changing the netif state.
 *
 * If the caller wants to stop iteration before the function returns
 * non-zero, he should drop the netif reference by calling
 * iterate_netifs_unlocked_dropref().
 *
 * Usage:
 *   netif = NULL;
 *   while (iterate_netifs_unlocked(&netif) == 0) {
 *     do_something_useful_with_each_netif;
 *     if (going_to_stop) {
 *       iterate_netifs_unlocked_dropref(netif);
 *       break;
 *     }
 *     do_something;
 *   }
 *
 * \param p_ni       IN: previous netif (NULL to start)
 *                   OUT: next netif
 *
 * \return either an unlocked netif or NULL if no more netifs
 *
 *--------------------------------------------------------------------*/

extern int
iterate_netifs_unlocked(ci_netif **p_ni)
{
  ci_netif *ni_prev = *p_ni;
  ci_irqlock_state_t lock_flags;
  tcp_helper_resource_t * thr_prev = NULL;
  ci_dllink *link = NULL;
  int rc = -ENOENT;

  if (ni_prev) {
    thr_prev = CI_CONTAINER(tcp_helper_resource_t, netif, ni_prev);
    TCP_HELPER_RESOURCE_ASSERT_VALID(thr_prev, -1);
  }

  /* We need a lock to protect the link and thr from removing 
   * after we've got the link and before taking refcount */
  ci_irqlock_lock(&THR_TABLE.lock, &lock_flags);

  if (ni_prev != NULL) {
    link = thr_prev->all_stacks_link.next;
    if (ci_dllist_end(&THR_TABLE.all_stacks) == link)
      link = NULL;
  } else if (ci_dllist_not_empty(&THR_TABLE.all_stacks))
    link = ci_dllist_start(&THR_TABLE.all_stacks);

  if (link) {
    int ref_count;
    tcp_helper_resource_t * thr;

    /* Skip dead thr's */
again:
    thr = CI_CONTAINER(tcp_helper_resource_t, all_stacks_link, link);

    /* get a kernel refcount */
    do {
      ref_count = thr->k_ref_count;
      if (ref_count & TCP_HELPER_K_RC_DEAD) {
        link = link->next;
        if (ci_dllist_end(&THR_TABLE.all_stacks) == link) {
          *p_ni = NULL;
          goto out;
        }
        goto again;
      }
    } while (ci_cas32_fail(&thr->k_ref_count, ref_count, ref_count + 1));

    rc = 0;
    *p_ni = &thr->netif;
  }

out:
  ci_irqlock_unlock(&THR_TABLE.lock, &lock_flags);
  if (ni_prev != NULL)
    efab_tcp_helper_k_ref_count_dec(thr_prev, 0);
  return rc;
}



extern int efab_ipid_alloc(efab_ipid_cb_t* ipid)
{
  int i;
  int rv;
  ci_irqlock_state_t lock_flags;

  ci_assert( ipid->init == EFAB_IPID_INIT );
  ci_irqlock_lock( &ipid->lock, &lock_flags );

  /* go find an unused block */
  for( i = 0; i < CI_IPID_BLOCK_COUNT; i++ ) {
    if( !ipid->range[i] ) {
      ipid->range[i]++;
      rv = CI_IPID_MIN + (i << CI_IPID_BLOCK_SHIFT);
      ci_assert((rv >= CI_IPID_MIN) && 
                (rv <= CI_IPID_MAX - CI_IPID_BLOCK_LENGTH + 1));
      goto alloc_exit;
    } else {
      ci_assert( ipid->range[i] == 1 );
    }
  }
  /* !!Out of blocks!! */
  rv = -ENOMEM;

 alloc_exit:
  ci_irqlock_unlock( &ipid->lock, &lock_flags );
  return rv;
}


int
efab_ipid_free(efab_ipid_cb_t* ipid, int base )
{
  int i;
  ci_irqlock_state_t lock_flags;

  ci_assert( ipid->init == EFAB_IPID_INIT );

  if(  (base & CI_IPID_BLOCK_MASK) != 0 )
    return -EINVAL;  /* not actually on a block boundary */

  ci_assert((base >= CI_IPID_MIN) && 
            (base <= CI_IPID_MAX - CI_IPID_BLOCK_LENGTH + 1));

  ci_irqlock_lock( &ipid->lock, &lock_flags );
  i = (base - CI_IPID_MIN) >> CI_IPID_BLOCK_SHIFT;
  ci_assert( ipid->range[i] == 1 );
  ipid->range[i] = 0;
  ci_irqlock_unlock( &ipid->lock, &lock_flags );
  return 0;
}

/*! \cidoxg_end */
