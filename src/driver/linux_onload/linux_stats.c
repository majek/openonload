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


static int
efab_version_read_proc(char* buf, char** start, off_t offset, int count, 
                       int* eof, void* data);
static int 
efabcfg_raw_read_proc(char *buf, char **start, off_t offset, int count, 
                      int *eof, void *data);
static int 
efab_workq_read_proc(char *buf, char **start, off_t offset, int count, 
		     int *eof, void *data);
static int
efab_dlfilters_read_proc(char* buf, char** start, off_t offset, int count, 
                         int* eof, void* data);


/*--------------------------------------------------------------------
 *
 * Private proc entries table
 *
 *--------------------------------------------------------------------*/

/* Entries under /proc/drivers/sfc */
typedef struct ci_proc_efab_entry_s {
  char        *name;             /**< Entry name */
  read_proc_t *read_proc;        /**< Entry read_proc handler */
} ci_proc_efab_entry_t;
static ci_proc_efab_entry_t ci_proc_efab_table[] = {
    {"cplane",         cicp_stat_read_proc}, 
    {"onloadcfg_raw",  efabcfg_raw_read_proc}, 
    {"workqueue",    efab_workq_read_proc},
//    {"efabcfg_opts", efabcfg_opts_read_proc}, 
    {"version",      efab_version_read_proc},
    {"dlfilters",    efab_dlfilters_read_proc},
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
 * /proc/drivers/onload/onloadcfg_raw
 *
 ****************************************************************************/

static int 
efabcfg_raw_read_proc(char *buf, char **start, off_t offset, int count, 
                      int *eof, void *data)
{
  ci_cfg_hdr_t *hdr;
  int how_much, rc;

  while (ci_cfg_rd_trylock() != 0) {
    set_current_state(TASK_INTERRUPTIBLE);
    schedule_timeout(0);
  }
  
  hdr = ci_cfg_get();
 
  /* do we have a database installed? */
  if (hdr == 0) {
    rc = -ENODATA;
    goto error;
  }

  /* have we reached or exceeded the end? */
  if (offset >= hdr->len) {
    rc = -EINVAL;
    goto error;
  }

  /* number of bytes to copy */
  how_much = CI_MIN(count, hdr->len - offset);
  ci_assert_ge(how_much, 0);

  /* copy the data */
  memcpy(buf, (char*)hdr + offset, how_much);

  ci_cfg_rd_unlock();

  return how_much;

error:
  ci_cfg_rd_unlock();
  return rc;
}




/****************************************************************************
 *
 * /proc/drivers/onload/workqueue
 *
 ****************************************************************************/

#define PROC_PRINTF(fmt, ...)					\
  if( count - len > 0 )						\
    len += snprintf(buf+len, count-len, (fmt), __VA_ARGS__)
#define EFAB_WORKQ_READ_PROC_PRINT(v)			\
  PROC_PRINTF("%14s = %u\n", #v, wqueue->stats.v)
#define PROC_PUT(str)					\
  if( count - len > 0 )					\
    len += snprintf(buf+len, count-len, "%s", (str))

static int 
efab_workq_read_proc(char *buf, char **start, off_t offset, int count, 
		     int *eof, void *data)
{
  int len = 0;
#ifndef __USE_LINUX_WORKQUEUE
  ci_irqlock_state_t lock_flags;
  ci_workqueue_t *wqueue;
  wqueue = &CI_GLOBAL_WORKQUEUE;
  ci_irqlock_lock(&wqueue->lock, &lock_flags);
  if (wqueue->state == CI_WQ_ALIVE) {
      EFAB_WORKQ_READ_PROC_PRINT(working);
      EFAB_WORKQ_READ_PROC_PRINT(iter);
      EFAB_WORKQ_READ_PROC_PRINT(backlog);
      EFAB_WORKQ_READ_PROC_PRINT(started);
  }
  else {	
    PROC_PUT("The workqueue is not running.\n");
  }
  ci_irqlock_unlock(&wqueue->lock, &lock_flags);
#endif

  return count ? strlen(buf) : 0;
}


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
efab_version_read_proc(char* buf, char** start, off_t offset, int count, 
                       int* eof, void* data)
{
  int len = 0; 
  PROC_PRINTF("onload_product: %s\n", ONLOAD_PRODUCT);
  PROC_PRINTF("onload_version: %s\n", ONLOAD_VERSION);
  PROC_PRINTF("uk_intf_ver: %s\n", oo_uk_intf_ver);
  return count ? strlen(buf) : 0;
}


/****************************************************************************
 *
 * /proc/driver/onload/dlfilters
 *
 ****************************************************************************/

static int 
efab_dlfilters_read_proc(char* buf, char** start, off_t offset, int count, 
                         int* eof, void* data)
{
  int len = 0; 
  int no_empty, no_tomb, no_used;

  efx_dlfilter_count_stats(efab_tcp_driver.dlfilter,
                           &no_empty, &no_tomb, &no_used);
  PROC_PRINTF("dlfilters: empty=%d, tomb=%d, used=%d\n",
              no_empty, no_tomb, no_used);
  return count ? strlen(buf) : 0;
}


/****************************************************************************
 *
 * Install new proc entries, substitute existing proc entries
 *
 ****************************************************************************/
/**
 * Install read-only files into /proc/drivers/sfc as requested by the table
 * in the argument.
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
                      root_name, efab_entry->name, efab_entry->read_proc));

    if (create_proc_read_entry(efab_entry->name, 0, root, 
                               efab_entry->read_proc, 0) == NULL) {

      ci_log("Unable to create %s/%s: read_proc=%p",
             root_name, efab_entry->name, efab_entry->read_proc);

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
  {
    struct proc_dir_entry *entry;
    entry = create_proc_entry("stacks", 0, oo_proc_root);
    if( entry )
      entry->proc_fops = &efab_stacks_seq_fops;
  }
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
  remove_proc_entry(oo_proc_root->name, oo_proc_root->parent);
  oo_proc_root = NULL;
}
