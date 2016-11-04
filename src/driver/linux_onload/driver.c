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
#include <onload/nic.h>
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
#include <ci/tools.h>
#ifdef ONLOAD_OFE
#include "ofe/onload.h"
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

unsigned ci_tp_log = CI_TP_LOG_DEFAULT;
module_param(ci_tp_log, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ci_tp_log, "Onload transport log level");

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

module_param(oof_all_ports_required, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oof_all_ports_required, 
                 "When set Onload will generate an error if it is unable to "
                 "install a filter on all the up interfaces it needs to. "
                 "In some configurations - e.g. multiple PFs on a single "
                 "physical port - this is not necessary, and setting to 0 will "
                 "allow Onload to tolerate these filter errors.");

int phys_mode_gid = -2;
module_param(phys_mode_gid, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(phys_mode_gid,
                 "Group id which may use physical buffer mode.  "
                 "-2 (default) means \"physical buffer mode forbidden\"; "
                 "-1 means \"any user may use physical buffer mode\".  "
                 "See EF_PACKET_BUFFER_MODE environment variable.");


static int param_black_white_list_set(const char *val, struct kernel_param *kp)
{
  struct oo_nic_black_white_list* bwl = kp->arg;
  return oo_nic_black_white_list_set(bwl, val);
}


static int param_black_white_list_get(char *buffer, struct kernel_param *kp)
{
  struct oo_nic_black_white_list* bwl = kp->arg;
  /* 4096 documented in linux/moduleparam.h */
  return oo_nic_black_white_list_get(bwl, buffer, 4096);
}


/* Note that module_param_call() is present but deprecated in 3.x
 * kernels.  It is superceded by module_param_cb(). */
module_param_call(intf_white_list, param_black_white_list_set,
                  param_black_white_list_get, &oo_nic_white_list,
                  S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(intf_white_list,
                 "Control which interfaces are accelerated.  "
                 "Can be used in parallel with intf_black_list.  "
                 "Specified as '<intf0> <intf1> ...'.  "
                 "Changes are not accumulative.  "
                 "Specify an empty string to reset"
                 "Putting the same interface in both lists is undefined.");
module_param_call(intf_black_list, param_black_white_list_set,
                  param_black_white_list_get, &oo_nic_black_list,
                  S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(intf_black_list,
                 "Control which interfaces are not accelerated.  "
                 "See intf_white_list for more detail.");

int safe_signals_and_exit = 1;
module_param(safe_signals_and_exit, int, S_IRUGO);
MODULE_PARM_DESC(safe_signals_and_exit,
                 "Intercept exit() syscall and guarantee that all "
                 "shared stacks are properly closed.\n"
                 "Intercept rt_sigaction() syscall and postpone signal "
                 "handlers to avoid Onload stack deadlock.");

int scalable_filter_gid = -2;
module_param(scalable_filter_gid, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(scalable_filter_gid,
                 "Group id which may use scalable filters.  "
                 "-2 (default) means \"CAP_NET_RAW required\"; "
                 "-1 means \"any user may use scalable filter mode\".  "
                 "See EF_SCALABLE_FILTERS environment variable.");


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

  rcu_read_lock();
  t = ci_get_task_by_pid(pid);

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
      for( fd = 0; fd < files_fdtable(t->files)->max_fds; ++fd ) {
	rcu_read_lock();
	filp = fcheck_files(t->files, fd);

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
    }
  }
  rcu_read_unlock();

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
  ci_dllist_init(&priv->dshm_list);

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

#if ! defined (__PPC__)
    BUILD_BUG_ON(_IOC_TYPE(TIOCSSOFTCAR) != _IOC_TYPE(TCGETS));
    if( _IOC_TYPE(cmd) != _IOC_TYPE(TCGETS) ||
        _IOC_NR(cmd) > _IOC_NR(TIOCSSOFTCAR) ) {
#else 
    /* On PPC TTY ioctls are organized in a complicated way, so for now
     * we just shut up warnings for a few known ioctl codes
     */
    if( cmd != TCGETS && cmd != TIOCGPGRP) {
#endif 
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


struct file_operations oo_fops = {
  .owner   = THIS_MODULE,
  .open    = oo_fop_open,
  .release = oo_fop_release,
  .unlocked_ioctl = oo_fop_unlocked_ioctl,
  .compat_ioctl = oo_fop_compat_ioctl,
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

  return rc;
}


static void
ci_chrdev_dtor(const char* name)
{
  if( oo_dev_major )
    unregister_chrdev(oo_dev_major, name);
}


static int onload_sanity_checks(void)
{
  const int dma_start_off = CI_MEMBER_OFFSET(ci_ip_pkt_fmt, dma_start);
  if( FALCON_RX_USR_BUF_SIZE + dma_start_off > CI_CFG_PKT_BUF_SIZE ) {
    ci_log("ERROR: FALCON_RX_USR_BUF_SIZE=%d dma_start_off=%d BUF_SIZE=%d",
           FALCON_RX_USR_BUF_SIZE, dma_start_off, CI_CFG_PKT_BUF_SIZE);
    return -EINVAL;
  }
  if( FALCON_RX_USR_BUF_SIZE + dma_start_off < CI_CFG_PKT_BUF_SIZE - 64 )
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

  rc = efab_tcp_driver_ctor();
  if( rc != 0 )
    goto fail_ip_ctor;

  rc = oo_driverlink_register();
  if( rc < 0 )
    goto failed_driverlink;

  rc = ci_install_proc_entries();
  if( rc < 0 ) {
    ci_log("%s: ERROR: ci_install_proc_entries failed (%d)", __FUNCTION__, rc);
    goto fail_proc;
  }

  rc = efab_linux_trampoline_ctor(no_ct);
  if( rc < 0 ) {
    ci_log("%s: ERROR: efab_linux_trampoline_ctor failed (%d)",
           __FUNCTION__, rc);
    goto failed_trampoline;
  }

#ifdef ONLOAD_OFE
  ofe_init(1);
#endif

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
  efab_linux_trampoline_dtor(no_ct);

  /* User API was available for some time: make sure there are no Onload
   * stacks. */
  efab_tcp_driver_stop();
 failed_trampoline:
  ci_uninstall_proc_entries();
 fail_proc:
  oo_driverlink_unregister();
 failed_driverlink:
  /* Remove all NICs when driverlink is gone.
   * It is possible that efx_dl_register_driver() call was successful, so
   * we have to shut down all NICs even if oo_driverlink_register() failed. */
  oo_nic_shutdown();
  efab_tcp_driver_dtor();
 fail_ip_ctor:
  ci_cfg_drv_dtor();
 fail_cfg_drv_ctor:
 fail_sanity:
  return rc;
}

module_init(onload_module_init);


static void onload_module_exit(void)
{
  OO_DEBUG_LOAD(ci_log("Onload module unloading"));

  /* Destroy User API: char devices. */
  oo_epoll_chrdev_dtor();
  ci_chrdev_dtor(oo_dev_name);
  onloadfs_fini();

  /* There are no User API now - so we do not need trampoline any more.
   * Destroy trampoline early to alleviate the race condition with RT
   * kernels - see efab_linux_trampoline_dtor() for details. */
  efab_linux_trampoline_dtor(no_ct);

  /* Destroy all the stacks.
   * It should be done early, as soon as User API is not available. */
  efab_tcp_driver_stop();

  /* Remove external interfaces to efab_tcp_driver. */
  ci_uninstall_proc_entries();
  oo_driverlink_unregister();

  /* Remove all NICs when driverlink is gone. */
  oo_nic_shutdown();

  efab_tcp_driver_dtor();

  ci_cfg_drv_dtor();
  OO_DEBUG_LOAD(ci_log("Onload module unloaded"));
}

module_exit(onload_module_exit);


/* Placeholders: in-kernel versions of ci_netif_ctor/dtor are not used,
 * but David asked to not kill them. */
EXPORT_SYMBOL(ci_netif_ctor);
EXPORT_SYMBOL(ci_netif_dtor);

