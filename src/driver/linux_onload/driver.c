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
*//*! \file ip_driver.c OS interface to the IP module
** <L5_PRIVATE L5_SOURCE>
** \author  gnb
**  \brief  Package - driver/linux	Linux IP driver support
**   \date  2005/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux */
#include <onload/linux_onload.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/linux_mmap.h>
#include <ci/internal/ip.h>
#include <onload/linux_trampoline.h>
#include <onload/linux_onload_internal.h>
#include <onload/efabcfg.h>
#include <ci/internal/ip_log.h>
#include <onload/ioctl.h>
#include <onload/tcp_helper_fns.h>
#include <ci/efrm/nic_table.h>
#include "onload_internal.h"
#include <onload/version.h>
#include <onload/oof_interface.h>

#if defined(__x86_64__) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
# define NEED_IOCTL32
# include <linux/ioctl32.h>
# include <onload/common.h>
#endif

/* For FALCON_RX_USR_BUF_SIZE checking. */
#include <ci/driver/efab/hardware.h>


/*--------------------------------------------------------------------
 *
 * Licence
 *
 *--------------------------------------------------------------------*/

MODULE_AUTHOR("Solarflare Communications");
MODULE_LICENSE("GPL");
MODULE_VERSION(ONLOAD_VERSION);


/*--------------------------------------------------------------------
 *
 * Module load time variables
 *
 *--------------------------------------------------------------------*/

/* This is legacy and used by macros in ci/driver/efab/debug.h, but
 * currently there is no code that sets it to a non-default value.
 */
int ci_driver_debug_bits;

static int no_ct = 0;

CI_DEBUG(int no_shared_state_panic;)
CI_DEBUG(EXPORT_SYMBOL(no_shared_state_panic);) /* used in iSCSI (?) */

module_param(no_ct, int, S_IRUGO);
MODULE_PARM_DESC(no_ct,
                 "Turn off trampoline -- do not intercept syscall table");

int oo_debug_bits = __OO_DEBUGERR__;	  /* run-time debug options */
module_param(oo_debug_bits, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oo_debug_bits, "Onload driver log level");

CI_DEBUG(int oo_debug_code_level;)
CI_DEBUG(module_param(oo_debug_code_level, int, S_IRUGO | S_IWUSR);)

CI_DEBUG(module_param(no_shared_state_panic, int, S_IRUGO | S_IWUSR);)

unsigned ci_tp_log = 0xf;
module_param(ci_tp_log, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ci_tp_log, "Onload transport log level");

int ci_cpu_speed;
EXPORT_SYMBOL(ci_cpu_speed);

int oo_igmp_on_failover = 0;
module_param(oo_igmp_on_failover, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oo_igmp_on_failover,
                 "Send IGMP joins after bonding failover (off by default)");

module_param(ci_log_options, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ci_log_options,
		 "Bitmask to turn on CPU, PID and other logging params");

module_param(oof_shared_keep_thresh, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oof_shared_keep_thresh,
                 "Number of sockets sharing a wildcard filter that will cause "
                 "the filter to persist after the wildcard socket has gone "
                 "away.");

module_param(oof_shared_steal_thresh, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oof_shared_steal_thresh,
                 "Number of sockets sharing a wildcard filter that will cause "
                 "the filter to persist even when a new wildcard socket needs "
                 "the filter.");

int phys_mode_gid = -2;
module_param(phys_mode_gid, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(phys_mode_gid,
                 "Group id which may use physical buffer mode.  "
                 "-2 (default) means \"physical buffer mode forbidden\"; "
                 "-1 means \"any user may use physical buffer mode\".  "
                 "See EF_PACKET_BUFFER_MODE environment variable.");

int timesync_period = 500;
module_param(timesync_period, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(timesync_period,
                 "Period in milliseconds between synchronising the Onload"
                 "clock with the system clock");

int safe_signals_and_exit = 1;
module_param(safe_signals_and_exit, int, S_IRUGO);
MODULE_PARM_DESC(safe_signals_and_exit,
                 "Intercept exit() syscall and guarantee that all "
                 "shared stacks are properly closed.\n"
                 "Intercept rt_sigaction() syscall and postpone signal "
                 "handlers to avoid Onload stack deadlock.");


/* Following set of three options define the control plane table sizes */

unsigned max_layer2_interfaces = 50;
module_param(max_layer2_interfaces, int, S_IRUGO);
MODULE_PARM_DESC(max_layer2_interfaces,
                 "Maximum number of LLAP interfaces (inc. bonds, vlans, etc)"
                 "in Onload's control plane tables");
unsigned max_routes = 256;
module_param(max_routes, int, S_IRUGO);
MODULE_PARM_DESC(max_routes,
                 "Maximum number of rows in Onload's route table");
unsigned max_neighs = 1024;
module_param(max_neighs, int, S_IRUGO);
MODULE_PARM_DESC(max_neighs,
                 "Maximum number of rows in Onload's ARP/neighbour table."
                 "This is rounded up internally to a power of two");


/* Extern declaration of iSCSI functions defined in iscsi_support.c */
extern void efab_prepare_for_iscsi(void);
extern void efab_cleanup_in_iscsi(void);


/* set cpu speed - only needed for kernel-created netifs */

int ci_set_cpu_khz(unsigned cpu_khz)
{
	if (cpu_khz > 0) {
		ci_cpu_speed = (int)cpu_khz / 1000;
		return 0;
	} else {
		ci_log("%s: ERROR: cant get CPU speed: cpu_khz=0",
		       __FUNCTION__);
		return -EINVAL;
	}
}
EXPORT_SYMBOL(ci_set_cpu_khz);


/**************************************************************************** 
 * 
 * ioctl: customised driver interface
 * 
 ****************************************************************************/ 

int efab_fds_dump(unsigned pid)
{
  struct task_struct* t;
  struct file* filp;
  ci_private_t* priv;
  int fd, rc = 0;

  t = ci_lock_task_by_pid(pid);

  if( ! t ) {
    ci_log("%s: bad pid %d", __FUNCTION__, pid);
    rc = -ENOENT;
  }
  else {
    if( ! t->files ) {
      ci_log("%s: files pointer is null in pid %d", __FUNCTION__, pid);
      rc = -EINVAL;
    }
    else {
      ci_fdtable *fdt;

      spin_lock(&t->files->file_lock);
      fdt = ci_files_fdtable(t->files);

      for( fd = 0; fd < fdt->max_fds; ++fd ) {
	filp = fdt->fd[fd];
	if( ! filp )  continue;
	priv = 0;

	if( filp->f_op == &oo_fops ) {
	  ci_log("pid=%d fd=%d => efab", pid, fd);
	  priv = (ci_private_t*) filp->private_data;
	}
	else if( filp->f_op == &linux_tcp_helper_fops_tcp ) {
	  ci_log("pid=%d fd=%d => TCP", pid, fd);
	  priv = (ci_private_t*) filp->private_data;
	}
	else if( filp->f_op == &linux_tcp_helper_fops_udp ) {
	  ci_log("pid=%d fd=%d => UDP", pid, fd);
	  priv = (ci_private_t*) filp->private_data;
	}
#if CI_CFG_USERSPACE_PIPE
	else if( filp->f_op == &linux_tcp_helper_fops_pipe_reader ) {
	  ci_log("pid=%d fd=%d => PIPE READER", pid, fd);
	  priv = (ci_private_t*) filp->private_data;
	}
	else if( filp->f_op == &linux_tcp_helper_fops_pipe_writer ) {
	  ci_log("pid=%d fd=%d => PIPE WRITER", pid, fd);
	  priv = (ci_private_t*) filp->private_data;
	}
#endif
	else
	  ci_log("pid=%d fd=%d => other", pid, fd);

#ifndef NDEBUG
        if( priv ) THR_PRIV_DUMP(priv, "      ");
#endif
      }

      spin_unlock(&t->files->file_lock);
    }

    ci_unlock_task();
  }

  return rc;
}



#if CI_MEMLEAK_DEBUG_ALLOC_TABLE
#error "this code is broken, fix it if necessary"
ci_noinline int
ioctl_debug_alloc_table (ci_private_t *priv, ulong arg)
{
    if (!ci_is_sysadmin()) return -EPERM;

    {
      struct ci_alloc_info local;

      copy_from_user_ret(&local, (caddr_t) arg,
                         CI_ALLOC_INFO_SIZEOF_CTRL, -EFAULT);
      ci_log("Processing request for memory allocation table: bulk #%u",
             local.bulk);
      if (local.bulk < (ci_alloc_table_sz >> CI_ALLOC_TABLE_BULK_2)) {
          copy_to_user_ret((caddr_t)((unsigned int)arg + 
                                       CI_ALLOC_INFO_SIZEOF_CTRL),
                           ci_alloc_table[local.bulk],
                           sizeof(local.entries),
                           -EFAULT);
      } else {
          return -E2BIG;
      }
    }

    return 0;
}
#endif




/**********************************************************************
 *
 * File ops.
 *
 **********************************************************************/

/****************************************************************************
 *
 * open - create a new file descriptor and hang private state
 *
 ****************************************************************************/
int oo_fop_open(struct inode* inode, struct file* filp)
{
  ci_private_t* priv;

  OO_DEBUG_VERB(ci_log("ci_char_fop_open:"));

  if( (priv = CI_ALLOC_OBJ(ci_private_t)) == NULL )
    return -ENOMEM;

  CI_ZERO(priv);
  priv->_filp = filp;
  priv->fd_type = CI_PRIV_TYPE_NONE;

  filp->private_data = (void*) priv;
  filp->f_op = &oo_fops;

  return 0;
}


/****************************************************************************
 *
 * close - cleanup filedescriptor and private state
 *
 ****************************************************************************/
int oo_fop_release(struct inode* inode, struct file* filp)
{
  ci_private_t *priv = (ci_private_t *) filp->private_data;

  OO_DEBUG_VERB(ci_log("ci_char_fop_close %d", priv->fd_type));

  /* cleanup private state */
  filp->private_data = 0;
  if (priv->thr != NULL) {
    TCP_HELPER_RESOURCE_ASSERT_VALID(priv->thr, 0);
    efab_thr_release(priv->thr);
  }
  onload_priv_free(priv);
  return 0;
}


#if OO_OPS_TABLE_HAS_NAME
# define OP_NAME(op)  ((op)->name)
#else
# define OP_NAME(op)  ""
#endif


/* It seems that gcc is a bit dumb, and if we inline all the case clauses in
 * this function, then it reserves cumulative stack for all of them.  So we
 * call separate functions for each case.
 */
long oo_fop_unlocked_ioctl(struct file* filp, unsigned cmd, unsigned long arg)
{
  ci_private_t *priv = filp->private_data;
  void __user* argp = (void __user*) arg;
  unsigned long local_arg[10];
  oo_operations_table_t* op;
  int ioc_nr = _IOC_NR(cmd);
  void* local_p;
  int rc;

  if( efab_tcp_driver.file_refs_to_drop != NULL )
    oo_file_ref_drop_list_now(NULL);

  if( ioc_nr >= OO_OP_END || _IOC_TYPE(cmd) != OO_LINUX_IOC_BASE ) {
    /* If libc is used on our sockets, sometimes it may call TCGETS ioctl to
     * determine whether the file is a tty.
     * tc* functions (tcgetpgrp, tcflush, etc) use direct ioctl syscalls,
     * so TIOC* ioctl go around onload library even if it is used.
     * So, we do not print scary warning for 0x5401(TCGETS)
     * - 0x541A(TIOCSSOFTCAR).
     * Next is FIONREAD(0x541B), which we can support, but do not do this.
     * The only ioctl which was really seen in the real life is TIOCGPGRP.
     */
    BUILD_BUG_ON(_IOC_TYPE(TIOCSSOFTCAR) != _IOC_TYPE(TCGETS));
    if( _IOC_TYPE(cmd) != _IOC_TYPE(TCGETS) ||
        _IOC_NR(cmd) > _IOC_NR(TIOCSSOFTCAR) ) {
      OO_DEBUG_ERR(ci_log("%s: bad cmd=%x type=%d(%d) nr=%d(%d)",
                          __FUNCTION__, cmd, _IOC_TYPE(cmd), OO_LINUX_IOC_BASE,
                          ioc_nr, OO_OP_END));
    }
    return -EINVAL;
  }
  op = &oo_operations[ioc_nr];
  if( op->ioc_cmd != cmd ) {
    /* If you see this, it is our bug.  Almost certainly means the
     * oo_operations table is out-of-sync with the ioctl numbers.
     */
    ci_log("%s: ioctl table bad cmd=%x nr=%u entry=%x", __FUNCTION__,
           cmd, ioc_nr, op->ioc_cmd);
    return -EINVAL;
  }

  /* Allocate in-kernel memory to keep ioctl arguments. */
  if( _IOC_SIZE(cmd) <= sizeof(local_arg) ) {
    local_p = &local_arg;
    /* In DEBUG case, we'd prefer to get oops instead of spoiled memory.
     * However, let's speed things up in NDEBUG case. */
    CI_DEBUG(if (_IOC_SIZE(cmd) == 0) local_p = NULL;)
  }
  else {
    if( (local_p = kmalloc(_IOC_SIZE(cmd), GFP_KERNEL)) == NULL )
      return -ENOMEM;
    memset(local_p, 0, _IOC_SIZE(cmd));
  }

  OO_DEBUG_OS(ci_log("%s: %s(arg=%lx,%s%s,%d)", __FUNCTION__, OP_NAME(op), arg,
                     _IOC_DIR(cmd) & _IOC_WRITE ? "W" : "",
                     _IOC_DIR(cmd) & _IOC_READ  ? "R" : "", _IOC_SIZE(cmd)));

  /* Copy data from user */
  if( (_IOC_DIR(cmd) & _IOC_WRITE) )
    if( copy_from_user(local_p, argp, _IOC_SIZE(cmd)) ) {
      rc = -EFAULT;
      goto cleanup_out;
    }

  /* Do the operation itself */
  rc = op->handler(priv, local_p);

  /* Copy arguments back to user in case of success and in case of
   * -ERESTARTSYS.  The last case is used in efab_tcp_helper_sock_sleep().
   */
  if( (rc == 0 || rc == -ERESTARTSYS) && (_IOC_DIR(cmd) & _IOC_READ) )
    if( copy_to_user(argp, local_p, _IOC_SIZE(cmd)) ) {
      rc = -EFAULT;
      goto cleanup_out;
    }

 cleanup_out:
  if( local_p != &local_arg ) 
    kfree(local_p);
  OO_DEBUG_OS(ci_log("%s: %s(arg=%lx) => %d", __FUNCTION__,
                     OP_NAME(op), arg, rc));
  return rc;
}


#if !HAVE_UNLOCKED_IOCTL
int oo_fop_ioctl(struct inode* inode, struct file *filp,
                 unsigned cmd, unsigned long arg) 
{
  return oo_fop_unlocked_ioctl(filp, cmd, arg);
}
#endif


struct file_operations oo_fops = {
  .owner   = THIS_MODULE,
  .open    = oo_fop_open,
  .release = oo_fop_release,
#if HAVE_UNLOCKED_IOCTL
  .unlocked_ioctl = oo_fop_unlocked_ioctl,
#else
  .ioctl   = oo_fop_ioctl,
#endif
#if HAVE_COMPAT_IOCTL
  .compat_ioctl = oo_fop_compat_ioctl,
#endif
  .mmap    = oo_fop_mmap,
};


/****************************************************************************
 *
 * char device ctor and dtor
 *
 ****************************************************************************/

static int         oo_dev_major;
static const char* oo_dev_name = EFAB_DEV_NAME;

static int 
ci_chrdev_ctor(struct file_operations *fops, const char *name)
{
  int rc, major = 0; /* specify default major number here */

  if ((rc = register_chrdev(major, name, fops)) < 0) {
    ci_log("%s: can't register char device %d", name, rc);
    return rc;
  }
  if (major == 0)
    major = rc;
  oo_dev_major = major;

#ifdef NEED_IOCTL32
  {
    /* Register 64 bit handler for 32 bit ioctls.  In 2.6.11 onwards, this
     * uses the .compat_ioctl file op instead.
     */
    int ioc;
    for( ioc = 0; ioc < OO_OP_END; ++ioc )
      register_ioctl32_conversion(oo_operations[ioc].ioc_cmd, NULL);
  }
#endif

  return rc;
}


static void
ci_chrdev_dtor(const char* name)
{
  if( oo_dev_major )
    unregister_chrdev(oo_dev_major, name);

#ifdef NEED_IOCTL32
  {
    /* unregister 64 bit handler for 32 bit ioctls */
    int ioc;
    for( ioc = 0; ioc < OO_OP_END; ++ioc )
      unregister_ioctl32_conversion(oo_operations[ioc].ioc_cmd);
  }
#endif
}


static int onload_sanity_checks(void)
{
  if( FALCON_RX_USR_BUF_SIZE + PKT_START_OFF() > CI_CFG_PKT_BUF_SIZE ) {
    ci_log("ERROR: FALCON_RX_USR_BUF_SIZE=%d PKT_START_OFF=%d BUF_SIZE=%d",
           FALCON_RX_USR_BUF_SIZE, PKT_START_OFF(), CI_CFG_PKT_BUF_SIZE);
    return -EINVAL;
  }
  if( FALCON_RX_USR_BUF_SIZE + PKT_START_OFF() < CI_CFG_PKT_BUF_SIZE - 64)
    ci_log("WARNING: FALCON_RX_USR_BUF_SIZE=%d could be bigger",
           FALCON_RX_USR_BUF_SIZE);
  return 0;
}


/**********************************************************************
 *
 * Module initialisation.
 *
 **********************************************************************/

static int __init onload_module_init(void)
{
  int rc;

  ci_set_log_prefix("[onload] ");
  ci_log("%s %s", ONLOAD_PRODUCT, ONLOAD_VERSION);
  ci_log("%s", ONLOAD_COPYRIGHT);

  ci_cpu_speed = cpu_khz / 1000;

  /* In library, .owner is not initialised correctly.
   * So, repeat it here. */
  linux_tcp_helper_fops_tcp.owner = THIS_MODULE;
  linux_tcp_helper_fops_udp.owner = THIS_MODULE;
#if CI_CFG_USERSPACE_PIPE
  linux_tcp_helper_fops_pipe_writer.owner = THIS_MODULE;
  linux_tcp_helper_fops_pipe_reader.owner = THIS_MODULE;
#endif

  rc = onload_sanity_checks();
  if( rc < 0 )
    goto fail_sanity;

  rc = ci_cfg_drv_ctor();
  if( rc < 0 ) {
    ci_log("%s: ERROR: ci_cfg_drv_ctor failed (%d)", __FUNCTION__, rc);
    goto fail_cfg_drv_ctor;
  }
  
  oo_mm_tbl_init();

  rc = efab_linux_trampoline_ctor(no_ct);
  if( rc < 0 ) {
    ci_log("%s: ERROR: efab_linux_trampoline_ctor failed (%d)",
           __FUNCTION__, rc);
    goto failed_trampoline;
  }

  rc = ci_install_proc_entries();
  if( rc < 0 ) {
    ci_log("%s: ERROR: ci_install_proc_entries failed (%d)", __FUNCTION__, rc);
    goto fail_proc;
  }

  rc = efab_tcp_driver_ctor(max_neighs, max_layer2_interfaces, max_routes);
  if( rc != 0 )
    goto fail_ip_ctor;

  rc = ci_bonding_init();
  if( rc < 0 ) {
    ci_log("%s: ERROR: ci_bonding_init failed (%d)", __FUNCTION__, rc);
    goto fail_bonding;
  }

  efab_prepare_for_iscsi();

  rc = oo_driverlink_register();
  if( rc < 0 )
    goto failed_driverlink;

  /* Onloadfs should be created before the char dev */
  rc = onloadfs_init();
  if(rc < 0 )
    goto failed_onloadfs;

  /* Now register as a character device. */
  rc = ci_chrdev_ctor(&oo_fops, oo_dev_name);
  if( rc < 0 )
    goto failed_chrdev;

  rc = oo_epoll_chrdev_ctor();
  if( rc < 0 )
    goto failed_epolldev_ctor;

  OO_DEBUG_LOAD(ci_log("Onload module initialised successfully."));
  return 0;

  oo_epoll_chrdev_dtor();
failed_epolldev_ctor:
  ci_chrdev_dtor(EFAB_DEV_NAME);
 failed_chrdev:
  onloadfs_fini();
 failed_onloadfs:
  oo_driverlink_unregister_nf();
  oo_driverlink_unregister_dl();
 failed_driverlink:
  ci_bonding_fini();
 fail_bonding:
  efab_tcp_driver_dtor();
 fail_ip_ctor:
  ci_uninstall_proc_entries();
 fail_proc:
  efab_linux_trampoline_dtor(no_ct);
 failed_trampoline:
  ci_cfg_drv_dtor();
 fail_cfg_drv_ctor:
 fail_sanity:
  return rc;
}

module_init(onload_module_init);


static void onload_module_exit(void)
{
  OO_DEBUG_LOAD(ci_log("Onload module unloading"));

  oo_epoll_chrdev_dtor();
  ci_chrdev_dtor(oo_dev_name);
  onloadfs_fini();

  ci_bonding_fini();

  oo_driverlink_unregister_nf();

  /* The ordering here is not strict reverse of construction.  But it is
   * essential that we do efab_tcp_driver_dtor() early so that any
   * remaining stacks are destroyed early.
   *
   * But not too early: driverlink ARP filter should be removed before
   * cplane is destructed.
   */
  efab_tcp_driver_dtor();

  oo_driverlink_unregister_dl();

  ci_uninstall_proc_entries();
  OO_DEBUG_VERB(ci_log("Unregistered client driver"));

  efab_linux_trampoline_dtor(no_ct);

  efab_cleanup_in_iscsi();
  ci_cfg_drv_dtor();
  OO_DEBUG_LOAD(ci_log("Onload module unloaded"));
}

module_exit(onload_module_exit);


EXPORT_SYMBOL(efab_tcp_helper_close_endpoint);
EXPORT_SYMBOL(efab_linux_tcp_helper_fop_poll_tcp);
EXPORT_SYMBOL(ci_netif_ctor);
EXPORT_SYMBOL(ci_tcp_sendmsg);
EXPORT_SYMBOL(ci_netif_poll_n);
EXPORT_SYMBOL(ci_tcp_close);
EXPORT_SYMBOL(ci_netif_dtor);
EXPORT_SYMBOL(ci_tcp_recvmsg);
EXPORT_SYMBOL(__ef_eplock_lock_slow);
EXPORT_SYMBOL(ci_sock_lock_slow);
EXPORT_SYMBOL(ci_sock_unlock_slow);
EXPORT_SYMBOL(efab_tcp_helper_sock_callback_arm);
EXPORT_SYMBOL(efab_tcp_helper_sock_callback_disarm);
EXPORT_SYMBOL(efab_tcp_helper_sock_callback_set);
EXPORT_SYMBOL(ci_tcp_recvmsg_get);
EXPORT_SYMBOL(ip_addr_str);
EXPORT_SYMBOL(ci_netif_send);
EXPORT_SYMBOL(ci_netif_pkt_alloc_slow);
EXPORT_SYMBOL(__ci_copy_iovec_to_pkt);
EXPORT_SYMBOL(ci_netif_pkt_wait);
EXPORT_SYMBOL(efab_linux_sys_close);
EXPORT_SYMBOL(ef_eventq_has_event);
#if CI_CFG_BUILD_DUMP_CODE_IN_KERNEL
EXPORT_SYMBOL(ci_netif_dump);
EXPORT_SYMBOL(ci_netif_dump_sockets);
#endif

/* For af_onload. */
EXPORT_SYMBOL(ci_sock_sleep);
EXPORT_SYMBOL(ci_assert_valid_pkt);
EXPORT_SYMBOL(ci_tcp_tx_advance);
EXPORT_SYMBOL(efab_tcp_helper_poll_os_sock);
EXPORT_SYMBOL(ci_tp_log);
EXPORT_SYMBOL(efab_tcp_driver);
