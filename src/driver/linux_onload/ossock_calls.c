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

#if CI_CFG_EPOLL_HANDOVER_WORKAROUND
static int oo_fop_release_nothing(struct inode *inode, struct file *file)
{
  return 0;
}
static struct file_operations oo_fop_do_nothing =
{
  .owner = THIS_MODULE,
  .release  = oo_fop_release_nothing,
};
#endif

int efab_fd_handover(struct file* old_filp, struct file* new_filp, int fd)
{
  int rc;

  ci_assert(old_filp != NULL);
  ci_assert(new_filp != NULL);

  spin_lock(&current->files->file_lock);
#if CI_CFG_EPOLL_HANDOVER_WORKAROUND
  if( !list_empty(&old_filp->f_ep_links) &&
      file_count(old_filp) == 1 && file_count(new_filp) == 1 &&
      fcheck(fd) == old_filp ) {
    /* we are the only holder of this file,
     * and we can rewrite old_filp->fops & friends.
     * So, we keep the old_filp "opened", but rewrite all data from the
     * new_filp.  In this way, epoll membership is kept untouched. */
    ci_private_t *priv = old_filp->private_data;
    struct dentry *old_dentry = old_filp->f_dentry;
    struct vfsmount *old_vfsmnt = old_filp->f_vfsmnt;
    ci_private_t priv_copy = *priv;

    /* Copy data from new_filp to old_filp */
    old_filp->private_data = new_filp->private_data;
    old_filp->f_op = new_filp->f_op;
    old_filp->f_dentry = new_filp->f_dentry;
    old_filp->f_vfsmnt = new_filp->f_vfsmnt;
    old_filp->f_owner = new_filp->f_owner;

    /* socket is now referencing the old_filp.
     * We never handover anything except socket! */
    ci_assert(S_ISSOCK(new_filp->f_dentry->d_inode->i_mode));
    SOCKET_I(new_filp->f_dentry->d_inode)->file = old_filp;

    /* Set up new_filp before we "close" it */
    new_filp->f_op = &oo_fop_do_nothing;
    new_filp->f_dentry = old_dentry;
    new_filp->f_vfsmnt = old_vfsmnt;

    spin_unlock(&current->files->file_lock);
    fput(new_filp); /* just release the struct file itself */

    /* now we should release endpoint structure */
    generic_tcp_helper_close(&priv_copy);
    if (priv_copy.thr != NULL) {
      TCP_HELPER_RESOURCE_ASSERT_VALID(priv_copy.thr, 0);
      efab_thr_release(priv_copy.thr);
    }
    return 0;
  }
#endif

  /* Replace old_filp by new_filp in fdtable; breaks dup/fork and epoll. */

  /* If others have reference to our old_filp, they are lost for us.
   * file_count is incremented by:
   * - dup/dup2/... - another fd points to old_filp;
   * - fork - same fd in another process points to old_filp;
   * - in multithreaded app, file_count=2, and nobody has references to
   *   old_filp.  I failed to find how Linux makes this.
   */
  if( file_count(old_filp) != 1 &&
      (file_count(old_filp) != 2 || ! thread_group_empty(current) ) ) {
    LOG_U(ci_log("%s: handover socket fd=%d which is already duplicated "
                 "by dup or fork: file_count=%lu", __func__,
                 fd, (unsigned long)file_count(old_filp)));
    /* fixme: implement "handover endpoint", so we can pass all socket
     * operations via our old_filp */
  }

  if( fcheck(fd) == old_filp ) {
    get_file(new_filp);
    ci_fdtable_set_fd(ci_files_fdtable(current->files), fd, new_filp);
    rc = 0;
  }
  else {
    rc = -ENOENT;
  }
  spin_unlock(&current->files->file_lock);
  if( rc == 0 )
    fput(old_filp);
  return rc;
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

int oo_install_file_to_fd_cloexec(struct file *file)
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
  FD_SET(fd, fdt->close_on_exec);
  spin_unlock(&files->file_lock);

  return fd;
}

static int get_os_fd_from_ep(tcp_helper_endpoint_t *ep)
{
  if( ep->os_socket == NULL || ep->os_socket->file == NULL )
    return -EINVAL;

  return oo_install_file_to_fd_cloexec(ep->os_socket->file);
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
get_linux_socket(struct oo_file_ref *os_socket)
{
  ci_os_file socketp;
  struct inode *inode;
  struct socket *sock;

  if( os_socket == NULL )
    return NULL;
  socketp = os_socket->file;
  if( socketp == NULL )
    return NULL;
  inode = socketp->f_dentry->d_inode;
  if( inode == NULL )
    return NULL;

  ci_assert(S_ISSOCK(inode->i_mode));
  sock = SOCKET_I(inode);
  ci_assert (sock->file == socketp);
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
  sock = get_linux_socket(ep->os_socket);
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

#ifdef CONFIG_COMPAT
  if( op->sizeof_ptr != sizeof(void*) )
    flags |= MSG_CMSG_COMPAT;
#endif
  ep = ci_trs_get_valid_ep(priv->thr, op->sock_id);
  fd = get_os_fd_from_ep(ep);
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
  sock = get_linux_socket(ep->os_socket);
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
  sock = get_linux_socket(ep->os_socket);
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
  sock = get_linux_socket(ep->os_socket);
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

  sock = get_linux_socket(ep->os_socket);
  if( sock == NULL )
    return -EINVAL;

  rc = sock->ops->shutdown (sock, how);
  LOG_TV(ci_log("%s: shutdown(%d) rc=%d", __FUNCTION__, how, rc));

  return rc;
}

extern int
efab_tcp_helper_os_sock_accept(ci_private_t* priv, void *arg)
{
  oo_os_sock_accept_t *op = arg;
  tcp_helper_endpoint_t *ep = ci_trs_get_valid_ep(priv->thr, op->sock_id);
  ci_sock_cmn *s = SP_TO_SOCK(&ep->thr->netif, ep->id);
  int fd;

  fd = get_os_fd_from_ep(ep);

  /* In theory, we can call sock->ops->accept(), but next we should somehow
   * set up file.  There are a lot of non-exported functions in the way
   * (such as sock_alloc_fd(), sock_attach_fd()), so let's go easy way
   * and call sys_accept. */
  op->rc = efab_linux_sys_accept4(fd, CI_USER_PTR_GET(op->addr),
                                  CI_USER_PTR_GET(op->addrlen),
                                  CI_USER_PTR_GET(op->socketcall_args),
                                  op->flags);

  /* Clear OS RX flag if we've got everything  */
  oo_os_sock_status_bit_clear(s, OO_OS_STATUS_RX,
                 ep->os_socket->file->f_op->poll(ep->os_socket->file,
                                                 NULL) & POLLIN);

  efab_linux_sys_close(fd);

  if( op->rc >= 0 ) {
    struct file *filp = fget(op->rc);

    /* This is 'off' on linux, unless set via environment */
    if( NI_OPTS(&ep->thr->netif).accept_inherit_nonblock) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
      spin_lock(&filp->f_lock);
#else
      lock_kernel();
#endif
      if( s->b.sb_aflags & CI_SB_AFLAG_O_NONBLOCK )
        filp->f_flags |= O_NONBLOCK;
      else
        filp->f_flags &= ~O_NONBLOCK;
      if( s->b.sb_aflags & CI_SB_AFLAG_O_NDELAY )
        filp->f_flags |= O_NDELAY;
      else
        filp->f_flags &= ~O_NDELAY;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
      spin_unlock(&filp->f_lock);
#else
      lock_kernel();
#endif
    }

    /* This is 'on' on linux, unless set via environment */
    if( NI_OPTS(&ep->thr->netif).accept_inherit_nodelay &&
        (s->s_aflags & CI_SOCK_AFLAG_NODELAY) ) {
      int nodelay = 1;
      struct socket *sock = SOCKET_I(filp->f_dentry->d_inode);
      sock->ops->setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
                            (char *)&nodelay, sizeof(nodelay));
      /* yes, we ignore rc */
    }
    fput(filp);
  }

  return op->rc >= 0 ? 0 : op->rc;
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
  sock = get_linux_socket(ep->os_socket);
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

int
efab_tcp_helper_poll_os_sock(tcp_helper_resource_t* trs,
                             oo_sp sock_id, ci_uint16* p_mask_out)
{
  /* TODO: This should be moved into afonload. */

  tcp_helper_endpoint_t* ep;
  ci_netif* ni = &trs->netif;

  ci_assert(trs);
  ci_assert(p_mask_out);

  if( ! IS_VALID_SOCK_P(ni, sock_id) )  return -EINVAL;

  ep = ci_trs_get_valid_ep(trs, sock_id);
  if( ep->os_socket != NULL ) {
    struct file* file = ep->os_socket->file;
    ci_assert(file->f_op != NULL);
    ci_assert(file->f_op->poll != NULL);
    *p_mask_out = file->f_op->poll(file, 0);
    return 0;
  }

  OO_DEBUG_ERR(ci_log("%s: %d:%d no O/S socket", __FUNCTION__,
                      NI_ID(ni), OO_SP_FMT(sock_id)));
  return -ENOENT;
}


int efab_tcp_helper_set_tcp_close_os_sock(tcp_helper_resource_t *thr,
                                          oo_sp sock_id)
{
  tcp_helper_endpoint_t* ep;
  struct socket* sock;

  ep = ci_trs_get_valid_ep(thr, sock_id);
  if( ep == NULL )
    return -EINVAL;
  sock = get_linux_socket(ep->os_socket);
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
  sock = get_linux_socket(ep->os_socket);
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
  sock = get_linux_socket(ep->os_socket);
  if( sock == NULL )
    return  -EINVAL;
  rc = sock->ops->setsockopt(sock, level, optname, optval, optlen);
  LOG_SV(ci_log("%s: rc=%d", __FUNCTION__, rc));

  return rc;
}
