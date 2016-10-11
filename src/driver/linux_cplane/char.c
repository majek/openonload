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

#include "linux_cplane_internal.h"
#include <cplane/ioctl.h>
#include "cplane_api_version.h"
#include <linux/termios.h> /* for TCGETS */
#include "driver/linux_resource/kernel_compat.h" /* for EFRM_VMA_HAS_NOPAGE */

int cicp_fop_open(struct inode* inode, struct file* filp)
{
  filp->private_data = &CI_GLOBAL_CPLANE;
  return 0;
}
int cicp_fop_release(struct inode* inode, struct file* filp)
{
  return 0;
}

#define VERSION_LEN 32
static int
cicp_check_version(const char* kver, ci_user_ptr_t uver, const char* type)
{
  char version[VERSION_LEN+1];

  ci_assert_equal(strlen(kver), VERSION_LEN);
  if( copy_from_user(version, CI_USER_PTR_GET(uver), VERSION_LEN + 1) )
    return -EFAULT;
  if( memcmp(version, kver, VERSION_LEN + 1) != 0 ) {
    ci_log("CICP_IOC_INIT_MMAP: invalid %s version %s != %s",
           type, version, kver);
    return -ENODEV;
  }

  return 0;
}

long cicp_fop_ioctl(struct file* filp, unsigned cmd, unsigned long arg)
{
  cicp_handle_t* control_plane = filp->private_data;
  void __user* argp = (void __user*) arg;
  unsigned long local_arg[30];
  int rc = 0;

  /* We can't prevent UL from passing a bogus cmd, but we can refuse to
   * serve it */
  ci_assert_le(_IOC_SIZE(cmd), sizeof(local_arg));
  if( _IOC_SIZE(cmd) > sizeof(local_arg) )
    goto bad_cmd;

  if( (_IOC_DIR(cmd) & _IOC_WRITE) ) {
    if( copy_from_user(&local_arg, argp, _IOC_SIZE(cmd)) )
      return -EFAULT;
  }

  switch( cmd) {
    case CICP_IOC_INIT_MMAP:
    {
      cicp_ns_mmap_info_t *info = (void *)&local_arg;

      rc = cicp_check_version(cicp_binary_version(CP_VERSION_LIB),
                              info->lib_version, "binary");
      if( rc != 0 )
        return rc;
      rc = cicp_check_version(CPLANE_API_VERSION, info->api_version, "API");
      if( rc != 0 )
        return rc;

      cicp_ns_map(info, control_plane);
      CP_DBG_SHM(ci_log("%d (0x%x) bytes for global cplane",
                        info->mmap_len, info->mmap_len));
      break;
    }

    case CICP_IOC_USER_FIND_HOME:
    {
      cp_src_addr_checks_t *op = (void *)&local_arg;
      rc = cicp_user_find_home(control_plane, &op->ip_be32, &op->hwport,
                               &op->ifindex, &op->mac, &op->mtu,
                               &op->encap);
      break;
    }

    case CICP_IOC_MAC_UPDATE:
    {
      cp_mac_update_t *op = (void *)&local_arg;
      cicp_mac_update(control_plane, &op->ver, op->ip, op->ifindex,
                      op->mac, op->confirm);
      break;
    }

    default:
 bad_cmd:
      if( cmd != TCGETS && cmd != TIOCGPGRP) {
        CP_DBG_SHM(ci_log("%s: bad cmd=%x type=%d(%d) nr=%d",
                            __FUNCTION__, cmd, _IOC_TYPE(cmd), CICP_IOC_BASE,
                            _IOC_NR(cmd)));
      }
      rc = -EINVAL;
  }

  if( rc == 0 && (_IOC_DIR(cmd) & _IOC_READ) ) {
    if( copy_to_user(argp, &local_arg, _IOC_SIZE(cmd)) )
      return -EFAULT;
  }

  return rc;
}


static struct page* cicp_vm_op_nopage(struct vm_area_struct* vma, 
                                 unsigned long address,
                                 int* type)
{
  unsigned pfn;
  struct page *pg;
  
  if( ! cicp_nopage_found(vma->vm_private_data, address - vma->vm_start, &pfn) )
    return NOPAGE_SIGBUS;

  pg = pfn_to_page(pfn);
  get_page(pg);
#ifdef EFRM_VMA_HAS_NOPAGE
  if( type )  *type = VM_FAULT_MINOR;
#endif
  
  return pg;
}
#ifndef EFRM_VMA_HAS_NOPAGE
static int cicp_vm_op_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
  vmf->page = cicp_vm_op_nopage(vma, (unsigned long)vmf->virtual_address,
                                NULL);
  return ( vmf->page == NULL ) ? VM_FAULT_SIGBUS : 0;
}
#endif

static struct vm_operations_struct cicp_vm_ops = {
#ifdef EFRM_VMA_HAS_NOPAGE
  .nopage = cicp_vm_op_nopage
#else
  .fault = cicp_vm_op_fault
#endif
};

int
cicp_fop_mmap(struct file* file, struct vm_area_struct* vma)
{
  /* All mmaps are read-only */
  if( vma->vm_flags & VM_WRITE )
    return -EPERM;
  vma->vm_flags &= ~VM_MAYWRITE;

  vma->vm_ops = &cicp_vm_ops;
  vma->vm_private_data = file->private_data;

  return 0;
}

struct file_operations cicp_fops = {
  .owner   = THIS_MODULE,
  .open    = cicp_fop_open,
  .release = cicp_fop_release,
  .unlocked_ioctl = cicp_fop_ioctl,
  .compat_ioctl = cicp_fop_ioctl,
  .mmap    = cicp_fop_mmap,
};

static int cicp_dev_major = -1;
int cicp_chrdev_ctor(const char *name)
{
  int rc = register_chrdev(0, name, &cicp_fops);

  if( rc < 0 )
    return rc;
  cicp_dev_major = rc;
  return 0;
}
void cicp_chrdev_dtor(const char *name)
{
  ci_assert_ge(cicp_dev_major, 0);
  unregister_chrdev(cicp_dev_major, name);
}

