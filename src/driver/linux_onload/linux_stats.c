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
*//*! \file linux_stats.c OS Interface for reporting network statistics
** <L5_PRIVATE L5_SOURCE>
** \author  Level 5
**  \brief  Package - driver/linux/net	Linux network driver support
**     $Id$
**   \date  2004/09
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux */

 
/*--------------------------------------------------------------------
 *
 * Compile time assertions for this file
 *
 *--------------------------------------------------------------------*/

#define __ci_driver_shell__	/* implements driver to kernel interface */

/*--------------------------------------------------------------------
 *
 * CI headers
 *
 *--------------------------------------------------------------------*/

#include "onload_internal.h"
#include <onload/linux_onload_internal.h>
#include <onload/tcp_helper_fns.h>
#include <onload/tcp_driver.h>
#include <ci/internal/ip.h>
#include <ci/internal/ip_log.h>

#include <onload/cplane.h>
#include <ci/internal/ip.h>
#include <onload/efabcfg.h>
#include <onload/version.h>
#include <onload/driverlink_filter.h>

#include <net/tcp.h>
#include <net/udp.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include "../linux_resource/kernel_compat.h"



/*--------------------------------------------------------------------
 *
 * Local constant declarations
 *
 *--------------------------------------------------------------------*/

/* Maximum time in jiffies for which stats from NIC structure is steel up
 * to date */
#define CI_LINUX_STATISTICS_UPDATE_FREQUENCY    1


/** Top level directory for sfc specific stats **/
struct proc_dir_entry *oo_proc_root = NULL;


/*--------------------------------------------------------------------
 *
 * Local function declarations
 *
 *--------------------------------------------------------------------*/

static const struct file_operations efab_version_fops;
static const struct file_operations efab_dlfilters_fops;

/*--------------------------------------------------------------------
 *
 * Private proc entries table
 *
 *--------------------------------------------------------------------*/

/* Entries under /proc/drivers/sfc */
typedef struct ci_proc_efab_entry_s {
  char                          *name;  /**< Entry name */
  const struct file_operations  *fops;  /**< Proc file operations */
} ci_proc_efab_entry_t;
static ci_proc_efab_entry_t ci_proc_efab_table[] = {
    {"cplane",        &cicp_stat_fops}, 
    {"version",       &efab_version_fops},
    {"dlfilters",     &efab_dlfilters_fops},
};

#define CI_PROC_EFAB_TABLE_SIZE \
    (sizeof(ci_proc_efab_table) / sizeof(ci_proc_efab_entry_t))


/** Global statististics store */
static ci_ip_stats ci_ip_stats_global;


/****************************************************************************
 *
 * Update global statistics
 *
 ****************************************************************************/
void
ci_ip_stats_update_global(ci_ip_stats *stats) {
  ci_assert(stats);
  ci_ip_stats_update(&ci_ip_stats_global, stats);
}
EXPORT_SYMBOL(ci_ip_stats_update_global);



/****************************************************************************
 *
 * /proc/drivers/onload/stacks
 *
 ****************************************************************************/

#if CI_CFG_STATS_NETIF

static void *
efab_stacks_seq_start(struct seq_file *seq, loff_t *ppos)
{
  ci_netif *ni = NULL;
  int i, rc;

  for( i = 0; i <= *ppos; i++) {
    rc = iterate_netifs_unlocked(&ni);
    if( rc != 0 )
      return NULL;
  }
  return ni;
}

static void *
efab_stacks_seq_next(struct seq_file *seq, void *v, loff_t *ppos)
{
  ci_netif *ni = v;
  int rc;
  (*ppos)++;
  rc = iterate_netifs_unlocked(&ni);
  if( rc != 0 )
    return NULL;
  return ni;
}

static void
efab_stacks_seq_stop(struct seq_file *seq, void *v)
{
  if( v )
    iterate_netifs_unlocked_dropref(v);
}

static int
efab_stacks_seq_show(struct seq_file *seq, void *v)
{
  ci_netif *ni = v;
  ci_netif_stats* s = &ni->state->stats;
  seq_printf(seq,
             "%d: %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n",
             NI_ID(ni), (int) ni->state->pid, (int) ni->state->uid,
             s->periodic_polls, s->periodic_evs,
             s->timeout_interrupts, s->interrupts, s->interrupt_polls,
             s->interrupt_wakes, s->interrupt_evs,
             s->interrupt_primes, s->select_primes,
             s->sock_wakes_rx + s->sock_wakes_tx +
             s->sock_wakes_rx_os + s->sock_wakes_tx_os,
             s->pkt_wakes, s->unlock_slow,
             s->lock_wakes, s->deferred_work, s->sock_lock_sleeps,
             s->rx_evs, s->tx_evs);
  return 0;
}

static struct seq_operations efab_stacks_seq_ops = {
  .start    = efab_stacks_seq_start,
  .next     = efab_stacks_seq_next,
  .stop     = efab_stacks_seq_stop,
  .show     = efab_stacks_seq_show,
};

static int
efab_stacks_seq_open(struct inode *inode, struct file *file)
{
  return seq_open(file, &efab_stacks_seq_ops);

}
static struct file_operations efab_stacks_seq_fops = {
  .owner    = THIS_MODULE,
  .open     = efab_stacks_seq_open,
  .read     = seq_read,
  .llseek   = seq_lseek,
  .release  = seq_release_private,
};

#endif


/****************************************************************************
 *
 * /proc/driver/onload/version
 *
 ****************************************************************************/

static int 
efab_version_read_proc(struct seq_file *seq, void *s)
{
  seq_printf(seq, "onload_product: %s\n", ONLOAD_PRODUCT);
  seq_printf(seq, "onload_version: %s\n", ONLOAD_VERSION);
  seq_printf(seq, "uk_intf_ver: %s\n", oo_uk_intf_ver);
  return 0;
}
static int efab_version_open_proc(struct inode *inode, struct file *file)
{
    return single_open(file, efab_version_read_proc, 0);
}
static const struct file_operations efab_version_fops = {
    .owner   = THIS_MODULE,
    .open    = efab_version_open_proc,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};


/****************************************************************************
 *
 * /proc/driver/onload/dlfilters
 *
 ****************************************************************************/

static int 
efab_dlfilters_read_proc(struct seq_file *seq, void *s)
{
  int no_empty, no_tomb, no_used;

  efx_dlfilter_count_stats(efab_tcp_driver.dlfilter,
                           &no_empty, &no_tomb, &no_used);
  seq_printf(seq, "dlfilters: empty=%d, tomb=%d, used=%d\n",
             no_empty, no_tomb, no_used);
  return 0;
}
static int efab_dlfilters_open_proc(struct inode *inode, struct file *file)
{
    return single_open(file, efab_dlfilters_read_proc, 0);
}
static const struct file_operations efab_dlfilters_fops = {
    .owner   = THIS_MODULE,
    .open    = efab_dlfilters_open_proc,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};


/****************************************************************************
 *
 * Install new proc entries
 *
 ****************************************************************************/
/**
 * Install read-only files into /proc/drivers/onload as requested
 * by the table in the argument.
 */
static void
ci_proc_files_install(struct proc_dir_entry *root, char *root_name,
                      ci_proc_efab_entry_t *entries, int num_entries)
{
  int entry_no;

  /* create new etherfabric specific proc entries */
  for (entry_no = 0; entry_no < num_entries; entry_no++) {
    ci_proc_efab_entry_t  *efab_entry = &entries[entry_no];

    OO_DEBUG_STATS(ci_log("Create %s/%s: read_proc=%p",
                      root_name, efab_entry->name, efab_entry->fops));

    if (proc_create(efab_entry->name, 0, root, efab_entry->fops)
        == NULL) {

      ci_log("Unable to create %s/%s: fops=%p",
             root_name, efab_entry->name, efab_entry->fops);

      /* we're not registering any methods off the proc entry so if we
         fail outcome is just that our entry doesn't get put into /proc
      */

    }
  }
}

/**
 * Install read-only files into /proc/drivers/sfc as requested by the table
 * in the argument.
 */
static void
ci_proc_files_uninstall(struct proc_dir_entry *root,
                        ci_proc_efab_entry_t *entries, int num_entries)
{
  int entry_no;

  /* remove etherfabric specific proc entries */
  for (entry_no = 0; entry_no < num_entries; entry_no++)
    remove_proc_entry(entries[entry_no].name, root);
}


int
ci_install_proc_entries(void)
{
  oo_proc_root = proc_mkdir("driver/onload", NULL);
  if( ! oo_proc_root ) {
    ci_log("%s: failed to create driver/onload", __FUNCTION__);
    return -ENOMEM;
  }

  ci_proc_files_install(oo_proc_root, "/proc/driver/onload", 
                        ci_proc_efab_table, CI_PROC_EFAB_TABLE_SIZE);


#if CI_CFG_STATS_NETIF
  proc_create("stacks", 0, oo_proc_root, &efab_stacks_seq_fops);
#endif

#if CI_MEMLEAK_DEBUG_ALLOC_TABLE
  /* create /proc/driver/sfc/mem */
  if( create_proc_read_entry("mem", 0, oo_proc_root,
                             ci_alloc_memleak_readproc, NULL) == NULL )
    ci_log("%s: failed to create 'mem'", __FUNCTION__);
#endif

  return 0;
}

/****************************************************************************
 *
 * Uninstall proc entries, return back old proc entries
 *
 ****************************************************************************/

void ci_uninstall_proc_entries(void)
{
  ci_ip_stats_clear(&ci_ip_stats_global);

  if( oo_proc_root == NULL )
    return;

  ci_proc_files_uninstall(oo_proc_root, ci_proc_efab_table,
                          CI_PROC_EFAB_TABLE_SIZE);
#if CI_CFG_STATS_NETIF
    remove_proc_entry("stacks", oo_proc_root);
#endif
#if CI_MEMLEAK_DEBUG_ALLOC_TABLE
  remove_proc_entry("mem", oo_proc_root);
#endif
  remove_proc_entry("driver/onload", NULL);
  oo_proc_root = NULL;
}
