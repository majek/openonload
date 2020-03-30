/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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
#include <onload/dshm.h>


static struct file_operations *oo_fops_by_type(int fd_type)
{
  switch( fd_type ) {
    case CI_PRIV_TYPE_NETIF: return &oo_fops;
    case CI_PRIV_TYPE_TCP_EP: return &linux_tcp_helper_fops_tcp;
    case CI_PRIV_TYPE_UDP_EP: return &linux_tcp_helper_fops_udp;
    case CI_PRIV_TYPE_PASSTHROUGH_EP: return &linux_tcp_helper_fops_passthrough;
    case CI_PRIV_TYPE_ALIEN_EP: return &linux_tcp_helper_fops_alien;
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


static const struct super_operations onloadfs_ops = {
  .alloc_inode   = onload_alloc_inode,
  .destroy_inode = onload_destroy_inode,
  .statfs        = simple_statfs,
};

static const char *priv_type_to_str(char fd_type)
{
  switch( fd_type ) {
    case CI_PRIV_TYPE_TCP_EP: return "tcp";
    case CI_PRIV_TYPE_UDP_EP: return "udp";
    case CI_PRIV_TYPE_PASSTHROUGH_EP: return "os_sock";
    case CI_PRIV_TYPE_ALIEN_EP: return "moved";
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
  int sock_id = priv->sock_id;

  if( priv->fd_type == CI_PRIV_TYPE_NETIF)
    len = snprintf(buffer, buflen, "[stack:%d]", priv->thr->id);
  /* without d_dname, this is called before listen(), so
   * we have no chance to print tcpl:N:N. */
  else if( priv->fd_type == CI_PRIV_TYPE_TCP_EP && sock_id >= 0 &&
           SP_TO_WAITABLE_OBJ(&priv->thr->netif,
                              sock_id)->waitable.state ==
           CI_TCP_LISTEN)
    len = snprintf(buffer, buflen, "[tcpl:%d:%d]",
                   priv->thr->id, priv->sock_id);
  else
    len = snprintf(buffer, buflen, "[%s:%d:%d]",
                   priv_type_to_str(priv->fd_type), priv->thr->id,
                   priv->sock_id);
  buffer[buflen-1] = '\0';
  return len + 1;
}
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


static const struct dentry_operations onloadfs_dentry_operations = {
  .d_dname  = onloadfs_dname,
};

#ifdef EFRM_FSTYPE_HAS_MOUNT
static struct dentry *
onloadfs_mount(struct file_system_type *fs_type, int flags,
               const char *dev_name, void *data)
{
  return mount_pseudo(fs_type, "onload:", &onloadfs_ops,
                      &onloadfs_dentry_operations, ONLOADFS_MAGIC);
}
#else
static
#ifdef EFRM_NEED_VFSMOUNT_PARAM_IN_GET_SB
int
#else
struct super_block *
#endif
onloadfs_get_sb(struct file_system_type *fs_type, int flags,
                const char *dev_name, void *data
#ifdef EFRM_NEED_VFSMOUNT_PARAM_IN_GET_SB
                , struct vfsmount *mnt
#endif
                )
{
  return get_sb_pseudo(fs_type, "onload:", &onloadfs_ops, ONLOADFS_MAGIC
#ifdef EFRM_NEED_VFSMOUNT_PARAM_IN_GET_SB
                       , mnt
#endif
                       );
}
#endif


static struct file_system_type onload_fs_type = {
  .name    = "onloadfs",
#ifdef EFRM_FSTYPE_HAS_MOUNT
  .mount   = onloadfs_mount,
#else
  .get_sb  = onloadfs_get_sb,
#endif
  .kill_sb = kill_anon_super,
};

static void init_once(
#if defined(EFRM_HAVE_KMEM_CACHE_DTOR) || defined(EFRM_HAVE_KMEM_CACHE_FLAGS)
                      void *foo, struct kmem_cache *cachep,
                      unsigned long flags
#else
#ifdef EFRM_HAVE_KMEM_CACHE_CACHEP
                      struct kmem_cache *cachep,
#endif
                      void *foo
#endif
                      )
{
  struct onload_inode *ei = (struct onload_inode *)foo;
#if defined(EFRM_HAVE_KMEM_CACHE_DTOR) || defined(EFRM_HAVE_KMEM_CACHE_FLAGS)
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
#ifdef EFRM_HAVE_KMEM_CACHE_DTOR
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
#ifdef EFRM_HAVE_KERN_UMOUNT
  kern_unmount(onload_mnt);
#else
  mntput(onload_mnt);
#endif
  onload_mnt = NULL;
  unregister_filesystem(&onload_fs_type);
  kmem_cache_destroy(onload_inode_cachep);
}

#ifndef EFRM_HAVE_ALLOC_FILE_PSEUDO
/* Stolen from linux-4.19.  Tab intentation is stolen.
 * Space indented stuff is needed to work with linux<=4.18. */
static
struct file *alloc_file_pseudo(struct inode *inode, struct vfsmount *mnt,
				const char *name, int flags,
				const struct file_operations *fops)
{
	struct qstr this = QSTR_INIT(name, strlen(name));
	struct path path;
	struct file *file;

#ifdef EFRM_FSTYPE_HAS_MOUNT
	path.dentry = d_alloc_pseudo(mnt->mnt_sb, &this);
#else
        path.dentry = d_alloc(mnt->mnt_sb->s_root, &this);
#endif

	if (!path.dentry)
		return ERR_PTR(-ENOMEM);

#ifndef EFRM_FSTYPE_HAS_MOUNT
        path.dentry->d_op = &onloadfs_dentry_operations;
#endif

        /* It is definitely unneeded for linux>=3.19,
         * but probably needed in earlier cases. */
        inode->i_fop = fops;

	path.mnt = mntget(mnt);
	d_instantiate(path.dentry, inode);
        /* New alloc_file_pseudo() from linux-4.19
         * uses flags=O_RDWR or something like this.
         * Old alloc_file() from linux<=4.18 expects
         * flags=FMODE_READ | FMODE_WRITE.
         * We do not convert first to second, we always use read|write.
         */
#ifdef RHEL_MAJOR
#if RHEL_MAJOR == 8
        /* RHEL8 backported new prototype of alloc_file() to its
         * linux-4.18, but did not backport alloc_file_pseudo().  These two
         * variants of alloc_file() share the same prototype and can not be
         * detected by kernel_compat.sh. */
        file = alloc_file(&path, O_RDWR, fops);
#else
        file = alloc_file(&path, FMODE_READ | FMODE_WRITE, fops);
#endif
#else
        file = alloc_file(&path, FMODE_READ | FMODE_WRITE, fops);
#endif /*RHEL_MAJOR*/
	if (IS_ERR(file)) {
		ihold(inode);
		path_put(&path);
	}
        file->f_flags = O_RDWR | (flags & O_NONBLOCK);
	return file;
}
#endif

int
onload_alloc_file(tcp_helper_resource_t *thr, oo_sp ep_id,
                  int flags, int fd_type, ci_private_t **priv_p)
{
  struct file *file;
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
#ifdef EFRM_FSTYPE_HAS_MOUNT
  inode->i_ino = get_next_ino();
#endif
  /* We can't set S_IFSOCK, as the kernel would assume incorrectly that our
   * inode is preceded by a struct socket.  This is no real loss: we intercept
   * fstat() at user-level and report the flag there. */
  if( fd_type == CI_PRIV_TYPE_NETIF || fd_type == CI_PRIV_TYPE_TCP_EP ||
      fd_type == CI_PRIV_TYPE_UDP_EP )
    inode->i_mode = S_IRWXUGO;
  else
    inode->i_mode = S_IFIFO | S_IRUSR | S_IWUSR;
  inode->i_uid = current_fsuid();
  inode->i_gid = current_fsgid();
  priv = &container_of(inode, struct onload_inode, vfs_inode)->priv;
  priv->thr = thr;
  priv->sock_id = ep_id;
  priv->fd_type = fd_type;
  priv->priv_cp = NULL;


  file = alloc_file_pseudo(inode, onload_mnt, "",
                           O_RDWR | (flags & O_NONBLOCK), fops);
  if( IS_ERR(file) ) {
    iput(inode);
    return PTR_ERR(file);
  }

  priv->_filp = file;
  file->f_pos = 0;
  file->private_data = priv;

  try_module_get(THIS_MODULE);
  *priv_p = priv;
  return 0;
}

void onload_priv_free(ci_private_t *priv)
{
  if( priv->_filp->f_vfsmnt != onload_mnt ) {
    oo_dshm_free_handle_list(&priv->dshm_list);
    ci_free(priv);
  }
  /* inode will free the priv automatically */
}


int
oo_create_fd(tcp_helper_resource_t* thr, oo_sp ep_id, int flags, int fd_type,
             struct file** _filp)
{
  int fd, rc;
  ci_private_t *priv;

  fd = get_unused_fd_flags(flags);
  if( fd < 0 )
    return fd;

  if( _filp && *_filp ) {
    rcu_read_lock();
    rc = get_file_rcu(*_filp);
    rcu_read_unlock();
    if( rc == 0 ) {
      OO_DEBUG_TCPH(ci_log("%s: fd=%d reuses file", __FUNCTION__, fd));
      CITP_STATS_NETIF_INC(&thr->netif, sock_attach_fd_more_fail);
      rc = -ENOANO;
      goto ret_put_fd;
    }
    priv = (*_filp)->private_data;
    ci_assert_equal(priv->fd_type, CI_PRIV_TYPE_TCP_EP);
    CITP_STATS_NETIF_INC(&thr->netif, sock_attach_fd_more);
  }
  else {
    if( fd_type == -1 ) {
      rc = -EINVAL;
      goto ret_put_fd;
    }
    rc = onload_alloc_file(thr, ep_id, flags, fd_type, &priv);
    if( rc != 0 ) {
      OO_DEBUG_ERR(ci_log("%s: ERROR: onload_alloc_file failed (%d) "
                          "for [%d:%d]", __func__,
                          rc, thr->id, ep_id));
      goto ret_put_fd;
    }
    efab_thr_ref(thr);
  }

  fd_install(fd, priv->_filp);
  if( _filp )
    *_filp = priv->_filp;
  return fd;

ret_put_fd:
  put_unused_fd(fd);
  return rc;
}


int
onloadfs_get_dev_t(ci_private_t* priv, void* arg)
{
  ci_uint32 *p_dev = arg;
  *p_dev = (ci_uint32)onload_mnt->mnt_sb->s_dev;

  return 0;
}

