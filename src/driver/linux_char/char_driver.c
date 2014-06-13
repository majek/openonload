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
*//*! \file char_driver.c OS interface to driver
** <L5_PRIVATE L5_SOURCE>
** \author  ok_sasha
**  \brief  Package - driver/linux	Linux driver support
**     $Id$
**   \date  2002/08
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

#include "linux_char_internal.h"
#include <ci/efhw/public.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efch/op_types.h>
#include "char_internal.h"
#include <linux/init.h>


#if defined(__x86_64__) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
# define NEED_IOCTL32
/* for ioctl32 conversion registration */
# include <linux/ioctl32.h>
#endif

int phys_mode_gid = 0;
module_param(phys_mode_gid, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(phys_mode_gid,
                 "Group id of ef_vi apps which may use physical buffer mode.  "
                 "0 is default.  "
		 "-1 means \"any user may use physical buffer mode\".  "
		 "-2 means means \"physical buffer mode forbidden\".");


MODULE_AUTHOR("Solarflare Communications");
MODULE_LICENSE("GPL");




/*--------------------------------------------------------------------
 *
 * Driver log/debug settings, exported to dependent modules (ip, iscsi)
 *
 *--------------------------------------------------------------------*/


/************************************
 * IOCTL                            *
 ************************************/

ci_noinline int
ioctl_resource_alloc (ci_private_char_t *priv, ulong arg)
{
  int rc;
  ci_resource_alloc_t local;
  copy_from_user_ret(&local, (caddr_t) arg, sizeof(local), -EFAULT);
  rc = efch_resource_alloc(&priv->rt, &local);
  if( rc < 0 )  return rc;
  copy_to_user_ret((caddr_t) arg, &local, sizeof(local), -EFAULT);
  return rc;
}

ci_noinline int
ioctl_resource_op (ci_private_char_t *priv, ulong arg)
{
  ci_resource_op_t local;
  int rc, copy_out = 0;
  copy_from_user_ret(&local, (caddr_t) arg, sizeof(local), -EFAULT);
  rc = efch_resource_op(&priv->rt, &local, &copy_out);
  if( copy_out )
    copy_to_user_ret((caddr_t) arg, &local, sizeof(local), -EFAULT);

  return rc;
}

ci_noinline int
ioctl_license_challenge (ci_private_char_t *priv, ulong arg)
{
  struct ci_license_challenge_op_s local;
  int rc, copy_out = 0;
  copy_from_user_ret(&local, (caddr_t) arg, sizeof(local), -EFAULT);
  rc = efch_license_challenge(&priv->rt, &local, &copy_out);
  if( copy_out )
    copy_to_user_ret((caddr_t) arg, &local, sizeof(local), -EFAULT);

  return rc;
}


static long
ci_char_fop_ioctl(struct file *filp, uint cmd, ulong arg) 
{ 
  ci_private_char_t *priv = (ci_private_char_t *) filp->private_data;

  switch (cmd) {
  case CI_RESOURCE_OP:
    return ioctl_resource_op (priv, arg);

  case CI_RESOURCE_ALLOC:
    return ioctl_resource_alloc (priv, arg);

  case CI_LICENSE_CHALLENGE:
    return ioctl_license_challenge (priv, arg);

  default:
    ci_log("unknown ioctl (%u)", cmd);
    return -ENOTTY;

  }
  return 0;
}

#ifndef HAVE_UNLOCKED_IOCTL
static int
ci_char_fop_legacy_ioctl(struct inode *ino, struct file *filp,
                         uint cmd, ulong arg)
{ 
  return (int) ci_char_fop_ioctl(filp, cmd, arg);
}
#endif


/****************************************************************************
 *
 * open - create a new file descriptor and hang private state
 *
 ****************************************************************************/
static int
ci_char_fop_open(struct inode *inode, struct file *filp)
{
  ci_private_char_t *priv;

  EFCH_TRACE("%s:", __FUNCTION__);

  if ((priv = CI_ALLOC_OBJ(ci_private_char_t)) == NULL)
    return -ENOMEM;
  CI_ZERO(priv);
  ci_resource_table_ctor(&priv->rt,
            ci_is_sysadmin() ? CI_CAP_BAR | CI_CAP_PHYS | CI_CAP_DRV : 0);
  filp->private_data = (void*) priv;
  return 0; 
}

/****************************************************************************
 *
 * close - cleanup filedescriptor and private state
 *
 ****************************************************************************/
static int
ci_char_fop_close(struct inode *inode, struct file *filp) 
{  
  ci_private_char_t *priv = (ci_private_char_t *) filp->private_data;

  EFCH_TRACE("%s:", __FUNCTION__);

  /* cleanup private state */
  filp->private_data = 0;
  ci_resource_table_dtor(&priv->rt);
  ci_free(priv);

  return 0;  
} 


/*--------------------------------------------------------------------
 *
 * char device interface
 *
 *--------------------------------------------------------------------*/

struct file_operations ci_char_fops = {
  .owner = THIS_MODULE,
#ifdef HAVE_UNLOCKED_IOCTL
  .unlocked_ioctl = ci_char_fop_ioctl,
#else
  .ioctl = ci_char_fop_legacy_ioctl,
#endif
#ifdef HAVE_COMPAT_IOCTL
  .compat_ioctl = ci_char_fop_ioctl,
#endif
  .mmap = ci_char_fop_mmap,
  .open = ci_char_fop_open,
  .release = ci_char_fop_close,
};

static int ci_char_major = 0;


/************************************************
 * Init/destroy module functions                *
 ************************************************/

static int init_etherfabric_char(void)
{
  int rc = 0;
  int major = 0; /* specify default major number here */

  ci_set_log_prefix("[sfc_char_debug] ");

  ci_mm_tbl_init();

  if ((rc = register_chrdev(major, EFAB_CHAR_NAME, &ci_char_fops)) < 0) {
    ci_log("%s: can't register char device %d", EFAB_CHAR_NAME, rc);
    return rc;
  }

  if (major == 0)
    major = rc;

  ci_char_major = major;

#ifdef NEED_IOCTL32
  /* In 2.6.11 onwards, this uses the .compat_ioctl file op instead */
  /* register 64 bit handler for 32 bit ioctls */
  {
    int ioc;
    for(ioc = CI_IOC_CHAR_BASE; ioc <= CI_IOC_CHAR_MAX; ioc ++){
      register_ioctl32_conversion(ioc, NULL);
    }
  }
#endif

  return 0;
}

/**************************************************************************** 
 * 
 * close_driver: unregister the character device and the PCI driver
 * 
 ****************************************************************************/ 
static void 
cleanup_etherfabric_char(void) 
{ 

  if (ci_char_major) 
    unregister_chrdev(ci_char_major, EFAB_CHAR_NAME);

#ifdef NEED_IOCTL32
  /* In 2.6.11 onwards, this uses the .compat_ioctl file op instead */
  /* register 64 bit handler for 32 bit ioctls */
  {
    int ioc;
    for(ioc = CI_IOC_CHAR_BASE; ioc <= CI_IOC_CHAR_MAX; ioc ++){
      unregister_ioctl32_conversion(ioc);
    }
  }
#endif
}

module_init(init_etherfabric_char);
module_exit(cleanup_etherfabric_char);

