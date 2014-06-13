/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
**   Copyright: (c) Solarflare Communications
**      Author: sasha
**     Started: 2012/01/03
** Description: OnloadFS implementation
** </L5_PRIVATE>
\**************************************************************************/

#include <onload/fd_private.h>
#include <onload/debug.h>
#include <onload/tcp_helper_fns.h>
#include <onload/linux_onload.h>
#include "onload_internal.h"
#include <onload/linux_onload_internal.h>
#include "onload_kernel_compat.h"


static struct file_operations *oo_fops_by_type(int fd_type)
{
  switch( fd_type ) {
    case CI_PRIV_TYPE_NETIF: return &oo_fops;
    case CI_PRIV_TYPE_TCP_EP: return &linux_tcp_helper_fops_tcp;
    case CI_PRIV_TYPE_UDP_EP: return &linux_tcp_helper_fops_udp;
#if CI_CFG_USERSPACE_PIPE
    case CI_PRIV_TYPE_PIPE_READER: return &linux_tcp_helper_fops_pipe_reader;
    case CI_PRIV_TYPE_PIPE_WRITER: return &linux_tcp_helper_fops_pipe_writer;
#endif
    default:
      CI_DEBUG(ci_log("%s: error fd_type = %d",
                      __FUNCTION__, fd_type));
      return NULL;

  }
}




struct onload_inode {
  ci_private_t priv;
  struct inode vfs_inode;
};

static struct kmem_cache *onload_inode_cachep;
static struct vfsmount *onload_mnt;

static struct inode *onload_alloc_inode(struct super_block *sb)
{
  struct onload_inode *ei;

  ei = kmem_cache_alloc(onload_inode_cachep, GFP_KERNEL);
  if (!ei)
    return NULL;
  /*ci_log("%s: alloc %p", __func__, ei);*/

  return &ei->vfs_inode;
}

static void onload_destroy_inode(struct inode *inode)
{
  struct onload_inode *ei = container_of(inode, struct onload_inode,
                                         vfs_inode);
  /*ci_log("%s: free %p", __func__, ei);*/
  kmem_cache_free(onload_inode_cachep, ei);
}


static
#ifdef EFX_HAVE_D_DNAME
const
#endif
struct super_operations onloadfs_ops = {
  .alloc_inode   = onload_alloc_inode,
  .destroy_inode = onload_destroy_inode,
  .statfs        = simple_statfs,
};

static const char *priv_type_to_str(char fd_type)
{
  switch( fd_type ) {
    case CI_PRIV_TYPE_TCP_EP: return "tcp";
    case CI_PRIV_TYPE_UDP_EP: return "udp";
#if CI_CFG_USERSPACE_PIPE
    case CI_PRIV_TYPE_PIPE_READER: return "piper";
    case CI_PRIV_TYPE_PIPE_WRITER: return "pipew";
#endif
    default: return "?";
  }
  return NULL;
}
static int onloadfs_name(ci_private_t *priv, char *buffer, int buflen)
{
  int len;

  if( priv->fd_type == CI_PRIV_TYPE_NETIF)
    len = snprintf(buffer, buflen, "[stack:%d]", priv->thr->id);
#ifdef EFX_HAVE_D_DNAME
  /* without d_dname, this is called before listen(), so
   * we have no chance to print tcpl:N:N. */
  else if( priv->fd_type == CI_PRIV_TYPE_TCP_EP &&
           SP_TO_WAITABLE_OBJ(&priv->thr->netif,
                              priv->sock_id)->waitable.state ==
           CI_TCP_LISTEN)
    len = snprintf(buffer, buflen, "[tcpl:%d:%d]",
                   priv->thr->id, priv->sock_id);
#endif
  else
    len = snprintf(buffer, buflen, "[%s:%d:%d]",
                   priv_type_to_str(priv->fd_type), priv->thr->id,
                   priv->sock_id);
  buffer[buflen-1] = '\0';
  return len + 1;
}
#ifdef EFX_HAVE_D_DNAME
static char *onloadfs_dname(struct dentry *dentry, char *buffer, int buflen)
{
  struct onload_inode *ei = container_of(dentry->d_inode,
                                         struct onload_inode, vfs_inode);
  ci_private_t *priv = &ei->priv;
  int len;
  char temp[64];
  /* dynamic_dname() is not exported */

  len = snprintf(temp, sizeof(temp), "onload:");
  len += onloadfs_name(priv, temp + len, sizeof(temp) - len);
  if( len > sizeof(temp) || len > buflen )
    return ERR_PTR(-ENAMETOOLONG);

  buffer += buflen - len;
  return memcpy(buffer, temp, len);
}
#endif

#ifndef EFX_HAVE_STRUCT_PATH
static int onloadfs_delete_dentry(struct dentry *dentry)
{
#ifdef EFX_HAVE_D_DNAME
  /* see comments in linux/net/socket.c */
  dentry->d_flags |= DCACHE_UNHASHED;
  return 0;
#else
  return 1;
#endif
}

#endif

static
#ifdef EFX_HAVE_CONST_D_OP
const
#endif
struct dentry_operations onloadfs_dentry_operations = {
#ifdef EFX_HAVE_D_DNAME
  .d_dname  = onloadfs_dname,
#endif
#ifndef EFX_HAVE_STRUCT_PATH
  .d_delete = onloadfs_delete_dentry,
#endif
};

#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,37)
#define EFX_OLD_MOUNT_PSEUDO
#endif

#ifdef EFX_FSTYPE_HAS_MOUNT
static struct dentry *
onloadfs_mount(struct file_system_type *fs_type, int flags,
               const char *dev_name, void *data)
{
  return mount_pseudo(fs_type, "onload:", &onloadfs_ops,
#ifndef EFX_OLD_MOUNT_PSEUDO
                      &onloadfs_dentry_operations,
#endif
                      ONLOADFS_MAGIC);
}
#else
static
#ifdef EFX_NEED_VFSMOUNT_PARAM_IN_GET_SB
int
#else
struct super_block *
#endif
onloadfs_get_sb(struct file_system_type *fs_type, int flags,
                const char *dev_name, void *data
#ifdef EFX_NEED_VFSMOUNT_PARAM_IN_GET_SB
                , struct vfsmount *mnt
#endif
                )
{
  return get_sb_pseudo(fs_type, "onload:", &onloadfs_ops, ONLOADFS_MAGIC
#ifdef EFX_NEED_VFSMOUNT_PARAM_IN_GET_SB
                       , mnt
#endif
                       );
}
#endif


static struct file_system_type onload_fs_type = {
  .name    = "onloadfs",
#ifdef EFX_FSTYPE_HAS_MOUNT
  .mount   = onloadfs_mount,
#else
  .get_sb  = onloadfs_get_sb,
#endif
  .kill_sb = kill_anon_super,
};

static void init_once(
#if defined(EFX_HAVE_KMEM_CACHE_DTOR) || defined(EFX_HAVE_KMEM_CACHE_FLAGS)
                      void *foo, struct kmem_cache *cachep,
                      unsigned long flags
#else
#ifdef EFX_HAVE_KMEM_CACHE_CACHEP
                      struct kmem_cache *cachep,
#endif
                      void *foo
#endif
                      )
{
  struct onload_inode *ei = (struct onload_inode *)foo;
#if defined(EFX_HAVE_KMEM_CACHE_DTOR) || defined(EFX_HAVE_KMEM_CACHE_FLAGS)
# ifdef SLAB_CTOR_VERIFY
    if((flags & SLAB_CTOR_VERIFY) == 0)
#endif
# ifdef SLAB_CTOR_CONSTRUCTOR
    if(flags & SLAB_CTOR_CONSTRUCTOR)
# endif
#endif
  inode_init_once(&ei->vfs_inode);
}


int __init onloadfs_init(void)
{
  int err;

  onload_inode_cachep = kmem_cache_create("onloadfs_inode_cache",
                                          sizeof(struct onload_inode), 0, 0,
                                          init_once
#ifdef EFX_HAVE_KMEM_CACHE_DTOR
                                          , NULL
#endif
                                          );
  err = register_filesystem(&onload_fs_type);
  if( err != 0 ) {
    kmem_cache_destroy(onload_inode_cachep);
    return err;
  }
  onload_mnt = kern_mount(&onload_fs_type);
  if( IS_ERR(onload_mnt) ) {
    unregister_filesystem(&onload_fs_type);
    kmem_cache_destroy(onload_inode_cachep);
    return PTR_ERR(onload_mnt);
  }
  return 0;
}
void onloadfs_fini(void)
{
#ifdef EFX_HAVE_KERN_UMOUNT
  kern_unmount(onload_mnt);
#else
  mntput(onload_mnt);
#endif
  onload_mnt = NULL;
  unregister_filesystem(&onload_fs_type);
  kmem_cache_destroy(onload_inode_cachep);
}

#ifndef EFX_HAVE_ALLOC_FILE
static struct file *alloc_file(struct vfsmount *mnt, struct dentry *dentry,
                               mode_t mode, struct file_operations *fop)
{
  struct file *file = get_empty_filp();

  if( file == NULL )
    return NULL;

  file->f_dentry = dentry;
  file->f_vfsmnt = mntget(mnt);
  file->f_mapping = dentry->d_inode->i_mapping;
  file->f_mode = mode;
  file->f_op = fop;
  return file;
}
#endif
static int
onload_alloc_file(tcp_helper_resource_t *thr, oo_sp ep_id, int flags,
                  int fd_type)
{
  struct qstr name = { .name = "" };
#ifdef EFX_HAVE_STRUCT_PATH
  struct path path;
#define my_dentry path.dentry
#else
  struct dentry *dentry;
#define my_dentry dentry
#endif
  struct file *file;
  int fd;
  struct inode *inode;
  ci_private_t *priv;
  struct file_operations *fops;

  fops = oo_fops_by_type(fd_type);
  if( fops == NULL )
    return -EINVAL;
  ci_assert_equal(fops->owner, THIS_MODULE);

  inode = new_inode(onload_mnt->mnt_sb);
  if( inode == NULL )
    return -ENOMEM;
#ifdef EFX_FSTYPE_HAS_MOUNT
  inode->i_ino = get_next_ino();
#endif
  if( fd_type == CI_PRIV_TYPE_NETIF )
    inode->i_mode = S_IRWXUGO;
  if( fd_type == CI_PRIV_TYPE_TCP_EP || fd_type == CI_PRIV_TYPE_UDP_EP )
    inode->i_mode = 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21)
        /* in 2.6.18 this flag makes us "socket" and sendmsg crashes;
         * see sock_from_file() */
                    S_IFSOCK |
#endif
                    S_IRWXUGO;
  else
    inode->i_mode = S_IFIFO | S_IRWXUGO;
  inode->i_uid = current_fsuid();
  inode->i_gid = current_fsgid();
  priv = &container_of(inode, struct onload_inode, vfs_inode)->priv;
  priv->thr = thr;
  priv->sock_id = ep_id;
  priv->fd_type = fd_type;

  fd = get_unused_fd();
  if( fd < 0 ) {
    iput(inode);
    return fd;
  }
  /*ci_log("[%d]%s(%d:%d) return %d priv=%p", current->pid, __func__,
         thr->id, ep_id, fd, priv);*/

#ifdef EFX_FSTYPE_HAS_MOUNT
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,37)
  path.dentry = d_alloc(onload_mnt->mnt_sb->s_root, &name);
  if( path.dentry != NULL )
    path.dentry->d_op = &onloadfs_dentry_operations;
#else
  path.dentry = d_alloc_pseudo(onload_mnt->mnt_sb, &name);
#endif
#else /* EFX_FSTYPE_HAS_MOUNT */
#ifdef EFX_HAVE_D_DNAME
  my_dentry = d_alloc(onload_mnt->mnt_sb->s_root, &name);
#else
  {
    char str[32];
    name.len = onloadfs_name(&container_of(inode, struct onload_inode,
                                           vfs_inode)->priv,
                             str, sizeof(str));
    name.name = str;
    name.hash = inode->i_ino;
    my_dentry = d_alloc(onload_mnt->mnt_sb->s_root, &name);
  }
#endif
#endif /* EFX_FSTYPE_HAS_MOUNT */

  if( my_dentry == NULL ) {
    put_unused_fd(fd);
    iput(inode);
    return -ENOMEM;
  }

#if !defined(EFX_FSTYPE_HAS_MOUNT) || defined(EFX_OLD_MOUNT_PSEUDO)
  my_dentry->d_op = &onloadfs_dentry_operations;
#if !defined(EFX_HAVE_STRUCT_PATH) && defined(EFX_HAVE_D_DNAME)
  my_dentry->d_flags &= ~DCACHE_UNHASHED;
#endif
#endif
  d_instantiate(my_dentry, inode);
#ifndef EFX_HAVE_D_DNAME
  d_rehash(my_dentry);
#endif
  inode->i_fop = fops;

#ifdef EFX_HAVE_STRUCT_PATH
  path.mnt = mntget(onload_mnt);
  file = alloc_file(&path, FMODE_READ | FMODE_WRITE, fops);
#else
  file = alloc_file(onload_mnt, dentry, FMODE_READ | FMODE_WRITE, fops);
#endif
  if( file == NULL) {
#ifdef EFX_HAVE_STRUCT_PATH
    path_put(&path);
#else
    dput(dentry);
    iput(inode);
#endif
    put_unused_fd(fd);
    return -ENFILE;
  }

  priv->_filp = file;
  file->f_flags = O_RDWR | (flags & O_NONBLOCK);
  file->f_pos = 0;
  file->private_data = priv;

  if( flags & O_CLOEXEC ) {
    struct files_struct *files = current->files;
    struct fdtable *fdt;
    spin_lock(&files->file_lock);
    fdt = files_fdtable(files);
    rcu_assign_pointer(fdt->fd[fd], file);
    efx_set_close_on_exec(fd, fdt);
    spin_unlock(&files->file_lock);
  } else
    fd_install(fd, file);
  try_module_get(THIS_MODULE);

  ci_assert_equal(file->f_op, fops);
  return fd;
}

void onload_priv_free(ci_private_t *priv)
{
  if( priv->_filp->f_vfsmnt != onload_mnt)
    ci_free(priv);
  /* inode will free the priv automatically */
}


int
oo_create_fd(tcp_helper_endpoint_t* ep, int flags, int fd_type)
{
  int fd;
  tcp_helper_resource_t *trs = ep->thr;
  citp_waitable_obj *wo = SP_TO_WAITABLE_OBJ(&trs->netif, ep->id);

  efab_thr_ref(trs);
  fd = onload_alloc_file(trs, ep->id, flags, fd_type);
  if( fd < 0 ) {
    efab_thr_release(trs);
    OO_DEBUG_ERR(ci_log("%s: onload_alloc_file failed (%d)", __FUNCTION__, fd));
    return fd;
  }
  ci_atomic32_and(&wo-> waitable.sb_aflags,
                  ~(CI_SB_AFLAG_ORPHAN | CI_SB_AFLAG_TCP_IN_ACCEPTQ));

  return fd;
}

int
oo_create_stack_fd(tcp_helper_resource_t *thr)
{
  int fd;

  efab_thr_ref(thr);
  fd = onload_alloc_file(thr, OO_SP_NULL, O_CLOEXEC, CI_PRIV_TYPE_NETIF);
  if( fd < 0 ) {
    efab_thr_release(thr);
    OO_DEBUG_ERR(ci_log("%s: onload_alloc_file failed (%d)", __FUNCTION__, fd));
    return fd;
  }
  return fd;
}

int
onloadfs_get_dev_t(ci_private_t* priv, void* arg)
{
  ci_uint32 *p_dev = arg;
  *p_dev = onload_mnt->mnt_sb->s_dev;
  return 0;
}

/* Re-target existing file to the new endpoint.
 * Caller is responsible for refcounts of the old and the new thr. */
void
oo_move_file(ci_private_t* priv, tcp_helper_resource_t *new_thr,
             oo_sp new_sockid)
{
  priv->thr = new_thr;
  priv->sock_id = new_sockid;
#ifndef EFX_HAVE_D_DNAME
  {
    /* tell everybody that we've changed the name.
     * Assume the name is short (DNAME_INLINE_LEN_MIN=36). */
    struct dentry *dentry = priv->_filp->f_dentry;
    if( dname_external(dentry) ) {
      /* We do not want to handle memory free/allocation,
       * so just go out.
       * Unlucky user gets incorrect name in /proc - it is much better
       * than memory corruption. */
      return;
    }
    d_drop(dentry);
    dentry->d_name.len = onloadfs_name(priv, dentry->d_iname,
                                       sizeof(dentry->d_iname));
    d_rehash(dentry);
  }
#endif
}
