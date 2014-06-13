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
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: gel
**     Started: 2005/01/05
** Description: TCP helper resource OS socket calls (linux specific)
** </L5_PRIVATE>
\**************************************************************************/

#include <ci/internal/ip.h>
#include <onload/tcp_helper.h>
#include <onload/debug.h>
#include <onload/fd_private.h>
#include <onload/common.h>

#include <net/tcp.h>
#include <linux/compat.h>

#include <onload/tcp_helper_fns.h>
#include <onload/linux_onload.h>
#include <onload/linux_onload_internal.h>

#include "onload_kernel_compat.h"

#if CI_CFG_EPOLL_HANDOVER_WORKAROUND

DECLARE_RWSEM(handover_rwlock);

static int oo_fop_release_nothing(struct inode *inode, struct file *file)
{
  return 0;
}
static struct file_operations oo_fop_do_nothing =
{
  .owner = THIS_MODULE,
  .release  = oo_fop_release_nothing,
};

/* "safe" handover: if we are the only holder of the oo_file, we can
 * rewrite its fields to keep epoll references in the same state. */
static void oo_fd_handover_overwrite(struct file* oo_file, struct file* os_file)
{
  /* We keep the oo_file "opened", but rewrite all data from the
   * os_file.  In this way, epoll membership is kept untouched. */
  struct dentry *old_dentry = oo_file->f_dentry;
  struct vfsmount *old_vfsmnt = oo_file->f_vfsmnt;

  /* Copy data from os_file to oo_file */
  oo_file->private_data = os_file->private_data;
  oo_file->f_op = os_file->f_op;
  oo_file->f_dentry = os_file->f_dentry;
  oo_file->f_vfsmnt = os_file->f_vfsmnt;
  oo_file->f_owner.pid = os_file->f_owner.pid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
  oo_file->f_owner.pid_type = os_file->f_owner.pid_type;
#endif
  oo_file->f_owner.uid = os_file->f_owner.uid;
  oo_file->f_owner.euid = os_file->f_owner.euid;
  oo_file->f_owner.signum = os_file->f_owner.signum;
  oo_file->f_flags = os_file->f_flags;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
  oo_file->f_inode = os_file->f_inode;
#endif

  /* socket is now referencing the oo_file.
   * We never handover anything except socket! */
  ci_assert(S_ISSOCK(os_file->f_dentry->d_inode->i_mode));
  SOCKET_I(os_file->f_dentry->d_inode)->file = oo_file;

  /* Set up os_file before we "close" it */
  os_file->f_op = &oo_fop_do_nothing;
  os_file->f_dentry = old_dentry;
  os_file->f_vfsmnt = old_vfsmnt;
}
#endif


/*! Replace [old_filp] with [new_filp] in the current process's fdtable.
** Fails if [fd] is bad, or doesn't currently resolve to [old_filp].
*/
static int efab_fd_handover_replace(struct file* old_filp,
                                    struct file* new_filp, int fd)
{
  int rc = -ENOENT;

  spin_lock(&current->files->file_lock);
  if( fcheck(fd) == old_filp ) {
    get_file(new_filp);
    ci_fdtable_set_fd(ci_files_fdtable(current->files), fd, new_filp);
    rc = 0;
  }
  spin_unlock(&current->files->file_lock);

  if( rc == 0 )
    fput(old_filp);

  return rc;
}

/* Handover the user-level socket to the OS one.  This means that the FD
** that previously pointed at a ul socket will now point at the OS socket
** that backed it.  This gets called when we connect through a non-l5
** interface, or bind to a non-l5 interface.
*/
int efab_tcp_helper_handover(ci_private_t* priv, void *p_fd)
{
  tcp_helper_endpoint_t* ep;
  int fd = *(ci_int32*) p_fd;
  struct file *oo_file, *os_file;
  ci_private_t *fd_priv;
  int rc, line;

  /* We invoke this on the stack-fd rather than the socket-fd because if we
   * do the latter it is hard to know whether there are any other refs to
   * the socket.
   */
  if( priv->fd_type != CI_PRIV_TYPE_NETIF ) {
    line = __LINE__;
    goto unexpected_error;
  }
  /* Check fd is an Onload socket in the right stack with an OS socket. */
  oo_file = fget(fd);
  if( oo_file->f_op != &linux_tcp_helper_fops_tcp &&
      oo_file->f_op != &linux_tcp_helper_fops_udp ) {
    line = __LINE__;
    goto unexpected_error;
  }
  fd_priv = oo_file->private_data;
  ci_assert( CI_PRIV_TYPE_IS_ENDPOINT(fd_priv->fd_type) );
  if( priv->thr != fd_priv->thr ) {
    line = __LINE__;
    goto unexpected_error;
  }
  ep = ci_trs_ep_get(fd_priv->thr, fd_priv->sock_id);
  if( ep->os_socket == NULL ) {
    line = __LINE__;
    goto unexpected_error;
  }

  /* shut down fasync */
  if( ep->fasync_queue )
    fasync_helper(-1, oo_file, 0, &ep->fasync_queue);

  os_file = ep->os_socket->file;
  rc = efab_fd_handover_replace(oo_file, os_file, fd);
  if( rc != 0 ) {
    LOG_E(ci_log("%s: ERROR: %d:%d fd=%d: handover failed due to race",
                 __FUNCTION__, ep->thr->id, ep->id, fd));
    fput(oo_file);
    return rc;
  }


#if CI_CFG_EPOLL_HANDOVER_WORKAROUND
  if( file_count(oo_file) == 1
#ifdef NDEBUG /* we really want to test this code, so turn it on in DEBUG build */
      && ! list_empty(&oo_file->f_ep_links)
    /* This socket is a member of an epoll set.  To avoid dropping the
     * socket out of the epoll set, we overwrite oo_file with fields from
     * os_file and put oo_file back in the fdtable. */
#endif
      ) {
    ci_private_t *priv = (ci_private_t *) oo_file->private_data;

    down_write(&handover_rwlock);
    spin_lock(&current->files->file_lock);
    if( file_count(oo_file) == 1 && fcheck(fd) == os_file ) {
      oo_fd_handover_overwrite(oo_file, os_file);
      ci_fdtable_set_fd(ci_files_fdtable(current->files), fd, oo_file);
    }
    else {
      spin_unlock(&current->files->file_lock);
      up_write(&handover_rwlock);
      LOG_E(ci_log("%s: ERROR: %d:%d fd=%d: epoll handover failed; socket "
                   "likely dropped from epoll set",
                   __FUNCTION__, ep->thr->id, ep->id, fd));
      goto non_epoll;
    }
    spin_unlock(&current->files->file_lock);
    up_write(&handover_rwlock);

    /* Release the onload resources after we overwrite oo_file.
     * This needs to be done outside of spinlock. */
    generic_tcp_helper_close(priv);
    efab_thr_release(priv->thr);

    /* We are going to drop the old ref to os_file from fdtable. */
    ci_assert_equal(file_count(os_file), 1);
    /* simple fput(os_file) will drop socketfs inode - we do not want it! */
    os_file->f_op = &oo_fop_do_nothing;
    fput(os_file);
    return 0;
  }

non_epoll:
#endif

  /* If others have reference to our oo_file, they are lost for us.
   * file_count is incremented by:
   * - dup/dup2/... - another fd points to oo_file;
   * - fork - same fd in another process points to oo_file;
   * - syscall from another thread.
   *
   * This does not change anything for this file instance:
   * we complete our handover in normal manner; just warn DEBUG users.
   */
  if( file_count(oo_file) != 1 ) {
    LOG_E(ci_log("%s: ERROR: handover of %d:%d fd=%d duplicated by dup or fork "
                 "(refs=%d)", __FUNCTION__, ep->thr->id, ep->id, fd,
                 (int) file_count(oo_file)));
    /* fixme: implement "handover endpoint", so we can pass all socket
     * operations via our oo_file */
  }

  /* drop the last reference to the onload file */
  fput(oo_file);
  return 0;


 unexpected_error:
  OO_DEBUG_ERR(ci_log("%s: ERROR: unexpected error in HANDOVER at line %d",
                      __FUNCTION__, line));
  return -EINVAL;
}


#ifdef CONFIG_COMPAT

static int copy_compat_iovec_from_user(struct iovec* iovec,
                                       struct compat_iovec __user* uiovec,
                                       int iovlen)
{
  compat_uptr_t iov_base;
  compat_size_t iov_len;
  int i;

  for( i = 0; i < iovlen; ++i ) {
    if( get_user(iov_len, &uiovec[i].iov_len) ||
        get_user(iov_base, &uiovec[i].iov_base) )
      return -EFAULT;
    iovec[i].iov_base = compat_ptr(iov_base);
    iovec[i].iov_len = (__kernel_size_t) iov_len;
  }
  return 0;
}

#endif


/* 3.7 has get_unused_fd_flags exported! Hoorray!
 * 2.6.29 has get_unused_fd_flags macro to alloc_fd,
 *        alloc_fd non-exported
 * 2.6.24-26 has get_unused_fd_flags function, non-exported
 * 2.6.18 has no O_CLOEXEC
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)

int oo_install_file_to_fd(struct file *file, int flags)
{
  int fd = get_unused_fd_flags(flags);

  if(unlikely( fd < 0 ))
    return fd;

  get_file(file);
  fd_install(fd, file);

  return fd;
}

#else  /* LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0) */

int oo_install_file_to_fd(struct file *file, int flags)
{
  int fd = get_unused_fd();
  struct files_struct *files = current->files;
  struct fdtable *fdt;

  if(unlikely( fd < 0 ))
    return fd;

  get_file(file);

  /* This is almost the copy of fd_install, but with close_on_exec. */
  spin_lock(&files->file_lock);
  fdt = files_fdtable(files);
  rcu_assign_pointer(fdt->fd[fd], file);
  if( flags & O_CLOEXEC)
    efx_set_close_on_exec(fd, fdt);
  spin_unlock(&files->file_lock);

  return fd;
}

#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)

int sock_map_fd(struct socket *sock, int flags)
{
  struct file *file;
  int fd;

  if( (fd = get_unused_fd_flags(flags)) < 0 )
    return fd;
  if( IS_ERR(file = sock_alloc_file(sock, flags, NULL)) ) {
    put_unused_fd(fd);
    return PTR_ERR(file);
  }
  fd_install(fd, file);
  return fd;
}

#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
/* Implement sock_alloc_file() in terms of sock_map_fd() since the latter
 * is exported.
 */
struct file *sock_alloc_file(struct socket *sock, int flags, void *unused)
{
  int fd;
  struct file *file;

#ifdef SOCK_TYPE_MASK
  fd = sock_map_fd(sock, flags | SOCK_CLOEXEC);
#else
  fd = sock_map_fd(sock);
#endif
  if( fd < 0 )
    return ERR_PTR(fd);
  file = fget(fd);
  if( file == NULL ) {
    ci_log("%s: fd=%d closed under feet!", __func__, fd);
    return ERR_PTR(-EFAULT);
  }
  efab_linux_sys_close(fd);
  return file;
}
#endif

static int get_os_fd_from_ep(tcp_helper_endpoint_t *ep)
{
  struct file *os_file;

  if( oo_os_sock_get_from_ep(ep, &os_file) != 0 )
    return -EINVAL;

  return oo_install_file_to_fd(os_file, O_CLOEXEC);
}

/* This really sucks, but sometimes we can't get at the kernel state that we
 * need to from a module.  So, what we do is to return a temporary FD for the
 * OS socket that backs a user-level socket.  Intention is for the user-level
 * code to do the necessary operation(s) using the FD, then close it.
 */
int efab_tcp_helper_get_sock_fd(ci_private_t* priv, void *arg)
{
  oo_os_sock_fd_get_t *op = arg;
  tcp_helper_endpoint_t *ep;
  ci_int32 sock_id = op->sock_id;

  if( op->sock_id < 0 )
    sock_id = OO_SP_TO_INT(priv->sock_id);
  ep = ci_trs_get_valid_ep(priv->thr, sock_id);

  op->fd_out = get_os_fd_from_ep(ep);

  return op->fd_out >= 0 ? 0 : op->fd_out;
}


/* Get at the OS socket backing the u/l socket for fd.  NB. No need to
** get_file() here, since if the os_socket exists it is guaranteed to
** remain referenced until the u/l socket's [struct file] goes away.  And
** it can't go away while we're in this ioctl!.
*/
static struct socket *
get_linux_socket(tcp_helper_endpoint_t* ep)
{
  ci_os_file socketp;
  struct inode *inode;
  struct socket *sock;
  int rc;

  rc = oo_os_sock_get_from_ep(ep, &socketp);
  if( rc != 0 )
    return NULL;
  inode = socketp->f_dentry->d_inode;
  if( inode == NULL )
    return NULL;

  ci_assert(S_ISSOCK(inode->i_mode));
  sock = SOCKET_I(inode);
  ci_assert_equal(sock->file, socketp);
  return sock;
}

int efab_tcp_helper_os_sock_sendmsg(ci_private_t* priv, void *arg)
{
  oo_os_sock_sendmsg_t *op = arg;
  /* To make life a little simpler, we've packaged up the msghdr
   * in a 32/64 agnostic format.  But we still need to worry about
   * the iovec and cmsg.
   *
   * However, we do not handle cmsg compat case: user should call _raw
   * version of this ioctl.
   */
  tcp_helper_endpoint_t *ep;
  struct socket* sock;
  struct iovec local_iovec[UIO_FASTIOV];
  int iovec_bytes = 0, total_bytes;
  struct sockaddr_storage addr;
  struct msghdr msg;
  int i, rc;
  unsigned char local_ctl[sizeof(struct cmsghdr) + 20]
      __attribute__ ((aligned(sizeof(__kernel_size_t))));
  unsigned char *ctl_buf = local_ctl;

  ep = ci_trs_get_valid_ep(priv->thr, op->sock_id); 
  sock = get_linux_socket(ep);
  if( sock == NULL )
    return  -EINVAL;

  rc = -EMSGSIZE;
  msg.msg_iov = local_iovec;
  msg.msg_iovlen = op->msg_iovlen;

  if( op->msg_iovlen > UIO_MAXIOV )
    goto out;

  iovec_bytes = op->msg_iovlen * sizeof(local_iovec[0]);
  rc = -ENOMEM;
  if( op->msg_iovlen > UIO_FASTIOV )
    msg.msg_iov = sock_kmalloc(sock->sk, iovec_bytes, GFP_KERNEL);
    if( msg.msg_iov == NULL )
      goto out;

  if( op->msg_controllen ) {
#ifdef CONFIG_COMPAT
    /* do not handle compat; use _raw version instead */
    ci_assert_equal(op->sizeof_ptr, sizeof(void*));
#endif

    if( op->msg_controllen > INT_MAX ) {
      rc = -ENOBUFS;
      goto out;
    }
    if( op->msg_controllen > sizeof(local_ctl) ) {
      ctl_buf = sock_kmalloc(sock->sk, op->msg_controllen, GFP_KERNEL);
      if( ctl_buf == NULL )
        goto out;
    }
    if( copy_from_user(ctl_buf, CI_USER_PTR_GET(op->msg_control),
                       op->msg_controllen) ) {
      rc = -EFAULT;
      goto out;
    }
    msg.msg_control = ctl_buf;
    msg.msg_controllen = op->msg_controllen;
  }
  else {
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
  }

  msg.msg_namelen = op->msg_namelen;
  if( op->msg_namelen == 0 )
    msg.msg_name = NULL;
  else if( op->msg_namelen < 0 ||
           op->msg_namelen > sizeof(struct sockaddr_storage) ) {
    rc = -EINVAL;
    goto out;
  }
  else if( copy_from_user(&addr, CI_USER_PTR_GET(op->msg_name),
                          op->msg_namelen) ) {
    rc = -EFAULT;
    goto out;
  }
  else
    msg.msg_name = &addr;

  msg.msg_flags = op->flags;

  rc = -EFAULT;
#ifdef CONFIG_COMPAT
  if( op->sizeof_ptr != sizeof(void*) ) {
    if( copy_compat_iovec_from_user(msg.msg_iov, CI_USER_PTR_GET(op->msg_iov),
                                    op->msg_iovlen) != 0 )
      goto out;
  }
  else
#endif
    if( copy_from_user(msg.msg_iov, CI_USER_PTR_GET(op->msg_iov),
                       op->msg_iovlen * sizeof(msg.msg_iov[0])) != 0 )
      goto out;

  total_bytes = 0;
  for( i = 0; i < op->msg_iovlen; ++i )
    total_bytes += msg.msg_iov[i].iov_len;
  rc = -EMSGSIZE;
  if( total_bytes < 0 )
    goto out;

  rc = sock_sendmsg(sock, &msg, total_bytes);
  /* Clear OS TX flag if necessary  */
  oo_os_sock_status_bit_clear(SP_TO_SOCK(&ep->thr->netif, ep->id),
                              OO_OS_STATUS_TX,
                              ep->os_socket->file->f_op->poll(
                                    ep->os_socket->file, NULL) & POLLOUT);

 out:
  if( msg.msg_iov != local_iovec && msg.msg_iov != NULL)
    sock_kfree_s(sock->sk, msg.msg_iov, iovec_bytes);
  if( ctl_buf != local_ctl && ctl_buf != NULL)
    sock_kfree_s(sock->sk, ctl_buf, op->msg_controllen);
  return rc;
}

int efab_tcp_helper_os_sock_sendmsg_raw(ci_private_t* priv, void *arg)
{
  oo_os_sock_sendmsg_raw_t *op = arg;
  tcp_helper_endpoint_t *ep = ci_trs_get_valid_ep(priv->thr, op->sock_id);
  int fd, rc;
  unsigned flags = op->flags;

  ep = ci_trs_get_valid_ep(priv->thr, op->sock_id);
  fd = get_os_fd_from_ep(ep);

#ifdef CONFIG_COMPAT
  if( op->sizeof_ptr != sizeof(void*) )
    rc = efab_linux_sys_sendmsg32(fd, CI_USER_PTR_GET(op->msg),
                                  CI_USER_PTR_GET(op->socketcall_args),
                                  flags);
  else
#endif
  rc = efab_linux_sys_sendmsg(fd, CI_USER_PTR_GET(op->msg),
                              CI_USER_PTR_GET(op->socketcall_args), flags);

  /* Clear OS TX flag if necessary  */
  oo_os_sock_status_bit_clear(SP_TO_SOCK(&ep->thr->netif, ep->id),
                              OO_OS_STATUS_TX,
                              ep->os_socket->file->f_op->poll(
                                    ep->os_socket->file, NULL) & POLLOUT);
  efab_linux_sys_close(fd);
  return rc;
}


int efab_tcp_helper_os_sock_recvmsg(ci_private_t* priv, void *arg)
{
  oo_os_sock_recvmsg_t *op = arg;
  /*
   * To make life a little simpler, we've packaged up the msghdr in a 32/64
   * agnostic format.  But we still need to worry about the iovec etc.
   */
  tcp_helper_endpoint_t *ep;
  struct socket *sock;
  char sockaddr[sizeof(struct sockaddr_in6)];
  struct iovec local_iovec[UIO_FASTIOV];
  int iovec_bytes = 0, total_bytes;
  struct msghdr msg;
  int i, rc;

  ep = ci_trs_get_valid_ep(priv->thr, op->sock_id); 
  sock = get_linux_socket(ep);
  if( sock == NULL )
    return 0;

  rc = -EMSGSIZE;
  msg.msg_iov = local_iovec;
  msg.msg_iovlen = op->msg_iovlen;

  if( op->msg_iovlen > UIO_MAXIOV )
    goto out;

  iovec_bytes = op->msg_iovlen * sizeof(local_iovec[0]);
  rc = -ENOMEM;
  if( op->msg_iovlen > UIO_FASTIOV )
    msg.msg_iov = sock_kmalloc(sock->sk, iovec_bytes, GFP_KERNEL);
    if( msg.msg_iov == NULL )
      goto out;

  if( op->msg_namelen ) {
    msg.msg_name = sockaddr;
    msg.msg_namelen = sizeof(sockaddr);
  }
  else {
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
  }

  if( op->msg_controllen ) {
    msg.msg_control = CI_USER_PTR_GET(op->msg_control);
    msg.msg_controllen = op->msg_controllen;
  }
  else {
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
  }

  msg.msg_flags = 0;
  if( op->sizeof_ptr != sizeof(void*) )
    msg.msg_flags = MSG_CMSG_COMPAT;
#ifdef MSG_CMSG_CLOEXEC
  msg.msg_flags |= op->flags & MSG_CMSG_CLOEXEC;
#endif

  rc = -EFAULT;
#ifdef CONFIG_COMPAT
  if( op->sizeof_ptr != sizeof(void*) ) {
    if( copy_compat_iovec_from_user(msg.msg_iov, CI_USER_PTR_GET(op->msg_iov),
                                    op->msg_iovlen) != 0 )
      goto out;
  }
  else
#endif
    if( copy_from_user(msg.msg_iov, CI_USER_PTR_GET(op->msg_iov),
                       op->msg_iovlen * sizeof(msg.msg_iov[0])) != 0 )
      goto out;

  total_bytes = 0;
  for( i = 0; i < op->msg_iovlen; ++i )
    total_bytes += msg.msg_iov[i].iov_len;
  rc = -EMSGSIZE;
  if( total_bytes < 0 )
    goto out;

  if( sock->file->f_flags & O_NONBLOCK )
    op->flags |= MSG_DONTWAIT;
  rc = sock_recvmsg(sock, &msg, total_bytes, op->flags);
  /* Clear OS RX flag if we've got everything  */
  oo_os_sock_status_bit_clear(SP_TO_SOCK(&ep->thr->netif, ep->id),
                              OO_OS_STATUS_RX,
                              sock->file->f_op->poll(sock->file, NULL) &
                                                                    POLLIN);
  if( rc < 0 )
    goto out;

  if(  CI_USER_PTR_GET(op->msg_name) ) {
    if( op->msg_namelen > msg.msg_namelen )
      op->msg_namelen = msg.msg_namelen;
    if( copy_to_user(CI_USER_PTR_GET(op->msg_name),
                     sockaddr, op->msg_namelen) != 0 )
      rc = -EFAULT;
    else
      op->msg_namelen = msg.msg_namelen;
  }
  if( CI_USER_PTR_GET(op->msg_control) ) {
    op->msg_controllen = (unsigned long)msg.msg_control -
        (unsigned long)CI_USER_PTR_GET(op->msg_control);
    if( msg.msg_flags & MSG_ERRQUEUE ) {
      /* If errqueue is non-empty, we've already got correct so_error via
       * callback.  If errqueue is empty, we should clear SO_ERROR value. */
      spin_lock_bh(&sock->sk->sk_error_queue.lock);
      if( skb_queue_empty(&sock->sk->sk_error_queue) )
        SP_TO_SOCK_CMN(&ep->thr->netif, ep->id)->so_error = 0;
      spin_unlock_bh(&sock->sk->sk_error_queue.lock);
    }
  }
  op->flags = msg.msg_flags &~ MSG_CMSG_COMPAT;

 out:
  if( msg.msg_iov != local_iovec && msg.msg_iov != NULL)
    sock_kfree_s(sock->sk, msg.msg_iov, iovec_bytes);
  op->rc = rc;
  return rc > 0 ? 0 : rc;
}


#ifdef CI_LINUX_NO_MOVE_ADDR
/* This is no longer exported */
int
efab_move_addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr *kaddr)
{
	if (ulen < 0 || ulen > sizeof(struct sockaddr_storage))
		return -EINVAL;
	if (ulen == 0)
		return 0;
	if (copy_from_user(kaddr, uaddr, ulen))
		return -EFAULT;
	return 0;
}
#endif

/* This function does a 'bind' and (optionally) a getname on the OS socket.
 * It is semantically equivalent to:
 *   - fd = get_os_sock_fd()
 *   - sys_bind (fd, ...)
 *   - sys_getsockname
 *   - sys_close (fd)
 * except that we do it all in one system call
 */
extern int efab_tcp_helper_bind_os_sock (tcp_helper_resource_t *trs,
                                         oo_sp sock_id,
                                         struct sockaddr *addr,
                                         int addrlen, ci_uint16 *out_port)
{
  int rc;
  tcp_helper_endpoint_t *ep;
  struct socket *sock;

  ci_assert(trs);

  ep = ci_trs_get_valid_ep(trs, sock_id);
  if( ep == NULL )
    return -EINVAL;
  sock = get_linux_socket(ep);
  if( sock == NULL )
    return -EINVAL;

  rc = sock->ops->bind(sock, addr, addrlen);
  LOG_TV(ci_log("%s: rc=%d", __FUNCTION__, rc));

  if (rc >= 0) {
    /* We also return the port bound to
     * (which might be different to asked for if asked for 0)
     * This is the getsockname, as mentioned in description above
     */
    rc = sock->ops->getname(sock, addr, &addrlen, 0);

    *out_port = ((struct sockaddr_in*)addr)->sin_port;
  }

  return rc;
}


int efab_tcp_helper_listen_os_sock(tcp_helper_resource_t* trs,
                                   oo_sp sock_id, int backlog)
{
  int rc = -EINVAL;
  tcp_helper_endpoint_t *ep;
  struct socket *sock;

  ci_assert (trs);

  ep = ci_trs_get_valid_ep(trs, sock_id); 
  sock = get_linux_socket(ep);
  if( sock == NULL )
    return -EINVAL;

  /* Install callback into OS socket:
   * - do not do it twice: listen() may be called again after shutdown()
   * - do it before calling the real listen() to avoid race */
  if( ep->os_sock_pt.whead == NULL )
    efab_tcp_helper_os_pollwait_register(ep);

  rc = sock->ops->listen (sock, backlog);
  LOG_TV(ci_log("%s: rc=%d", __FUNCTION__, rc));

  return rc;
}

extern int efab_tcp_helper_shutdown_os_sock (tcp_helper_endpoint_t *ep,
                                             ci_int32 how)
{
  int rc = -EINVAL;
  struct socket *sock;

  ci_assert (ep);

  sock = get_linux_socket(ep);
  if( sock == NULL )
    return -EINVAL;

  rc = sock->ops->shutdown (sock, how);
  LOG_TV(ci_log("%s: shutdown(%d) rc=%d", __FUNCTION__, how, rc));

  return rc;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19) && !defined(RHEL_MAJOR)
static int kernel_accept(struct socket *sock, struct socket **newsock, int flags)
{
	struct sock *sk = sock->sk;
	int err;

	err = sock_create_lite(sk->sk_family, sk->sk_type, sk->sk_protocol,
			       newsock);
	if (err < 0)
		return err;

	err = sock->ops->accept(sock, *newsock, flags);
	if (err < 0) {
		sock_release(*newsock);
		*newsock = NULL;
		return err;
	}

	(*newsock)->ops = sock->ops;
	__module_get((*newsock)->ops->owner);
	return 0;
}
#endif

extern int
efab_tcp_helper_os_sock_accept(ci_private_t* priv, void *arg)
{
  oo_os_sock_accept_t *op = arg;
  tcp_helper_endpoint_t *ep = ci_trs_get_valid_ep(priv->thr, op->sock_id);
  ci_sock_cmn *s = SP_TO_SOCK(&ep->thr->netif, ep->id);
  struct socket *sock = get_linux_socket(ep);
  struct socket *newsock;
  int rc;

  rc = kernel_accept(sock, &newsock, op->flags);

  /* Clear OS RX flag if we've got everything  */
  oo_os_sock_status_bit_clear(s, OO_OS_STATUS_RX,
                 ep->os_socket->file->f_op->poll(ep->os_socket->file,
                                                 NULL) & POLLIN);

  if( rc != 0 )
    return rc;
  newsock->type = sock->type;

  if( CI_USER_PTR_GET(op->addr) != NULL ) {
    char address[sizeof(struct sockaddr_in6)];
    int len, ulen;

    rc = newsock->ops->getname(newsock, (struct sockaddr *)address, &len, 2);
    if( rc != 0 )
      return -ECONNABORTED;
    rc = get_user(ulen, (int *)CI_USER_PTR_GET(op->addrlen));
    if( rc != 0 )
      return rc;
    if( ulen < 0 )
      return -EINVAL;
    if( ulen ) {
      if( copy_to_user(CI_USER_PTR_GET(op->addr), address,
                       min(ulen, len)) )
        return -EFAULT;
    }

    __put_user(len, (int *)CI_USER_PTR_GET(op->addrlen));
  }


#ifdef SOCK_TYPE_MASK
  /* This is 'off' on linux, unless set via environment */
  if( NI_OPTS(&ep->thr->netif).accept_inherit_nonblock && op->flags == 0 &&
      s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK)
    op->flags |= SOCK_NONBLOCK;
  op->rc = sock_map_fd(newsock, op->flags);
#else
  op->rc = sock_map_fd(newsock);
#endif
  if( op->rc < 0 ) {
    sock_release(newsock);
    return op->rc;
  }

#ifndef SOCK_TYPE_MASK
  /* This is 'off' on linux, unless set via environment */
  if( NI_OPTS(&ep->thr->netif).accept_inherit_nonblock) {
    /* We can not use newsock, because it may be already closed by another
     * thread. */
    struct file *file = fget(op->rc);
    if( file == NULL )
      return 0;
    lock_kernel();
    if( s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK )
      file->f_flags |= O_NONBLOCK;
    if( s->b.sb_aflags & CI_SB_AFLAG_O_NDELAY )
      file->f_flags |= O_NDELAY;
    unlock_kernel();
  }
#endif

  return 0;
}



extern int efab_tcp_helper_connect_os_sock(ci_private_t *priv, void *arg)
{
  oo_tcp_sockaddr_with_len_t *op = arg;
  ci_sock_cmn* s;
  size_t addrlen;
  int rc;
  tcp_helper_endpoint_t *ep;
  struct socket* sock;
  struct sockaddr_storage k_address_buf;
  struct sockaddr *k_address = (struct sockaddr *)&k_address_buf;

  ci_assert (priv && op);
  if (!CI_PRIV_TYPE_IS_ENDPOINT(priv->fd_type))
    return -EINVAL;
  ci_assert(priv->thr);

  addrlen = op->addrlen;

  /* Get at the OS socket backing the u/l socket for fd */
  ep = ci_trs_get_valid_ep(priv->thr, priv->sock_id); 
  sock = get_linux_socket(ep);
  if( sock == NULL )
    return -EINVAL;
  s = SP_TO_SOCK(&priv->thr->netif, ep->id);

  rc = move_addr_to_kernel(CI_USER_PTR_GET(op->address), addrlen, k_address);
  if (rc >=0) {
    /* We should sync non-blocking state between UL socket and kernel
     * socket. */
    if ((s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK))
      sock->file->f_flags |= O_NONBLOCK;
    rc = sock->ops->connect(sock, k_address, addrlen, sock->file->f_flags);
  }

  return rc;
}


int efab_tcp_helper_set_tcp_close_os_sock(tcp_helper_resource_t *thr,
                                          oo_sp sock_id)
{
  tcp_helper_endpoint_t* ep;
  struct socket* sock;

  ep = ci_trs_get_valid_ep(thr, sock_id);
  if( ep == NULL )
    return -EINVAL;
  sock = get_linux_socket(ep);
  if( sock == NULL )
    return  -EINVAL;
  tcp_set_state(sock->sk, TCP_CLOSE);
  return 0;
}


extern int efab_tcp_helper_getsockopt(tcp_helper_resource_t* trs,
				      oo_sp sock_id, int level, int optname,
				      char* optval, int* optlen )
{
  tcp_helper_endpoint_t* ep;
  struct socket* sock;
  int rc = -EINVAL;

  ep = ci_trs_get_valid_ep(trs, sock_id);
  sock = get_linux_socket(ep);
  if( sock == NULL )
    return  -EINVAL;
  rc = sock->ops->getsockopt(sock, level, optname, optval, optlen);
  LOG_SV(ci_log("%s: rc=%d", __FUNCTION__, rc));
  return rc;
}


extern int efab_tcp_helper_setsockopt(tcp_helper_resource_t* trs,
				      oo_sp sock_id, int level, 
				      int optname, char* optval, int optlen )
{
  tcp_helper_endpoint_t* ep;
  struct socket* sock;
  int rc = -EINVAL;

  /* Get at the OS socket backing the u/l socket for fd.  NB. No need to
  ** get_file() here, since if the os_socket exists it is guaranteed to
  ** remain referenced until the u/l socket's [struct file] goes away.  And
  ** it can't go away while we're in setsockopt.
  */
  ep = ci_trs_get_valid_ep(trs, sock_id);
  sock = get_linux_socket(ep);
  if( sock == NULL )
    return  -EINVAL;
  rc = sock->ops->setsockopt(sock, level, optname, optval, optlen);
  LOG_SV(ci_log("%s: rc=%d", __FUNCTION__, rc));

  return rc;
}
