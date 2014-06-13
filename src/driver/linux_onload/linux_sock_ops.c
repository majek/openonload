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
*//*! \file linux_sock_ops.c Socket operations interception for Linux
** <L5_PRIVATE L5_SOURCE>
** \author  mjs
**  \brief  Package - driver/linux	Linux driver support
**   \date  2005/02/14
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux */
 

/*--------------------------------------------------------------------
 *
 * CI headers
 *
 *--------------------------------------------------------------------*/

#include <ci/driver/internal.h>
#include <onload/linux_sock_ops.h>

/*--------------------------------------------------------------------
 *
 * Account for differences between 2.4 and 2.6
 *
 *--------------------------------------------------------------------*/

#include <net/sock.h>
/*! \TODO - sock_alloc() is good for 2.6.4 but maybe not later versions? */
#define SOCK_ALLOC()            sock_alloc()
#define SOCK_FROM_INODE(inode)  SOCKET_I(inode)

/*--------------------------------------------------------------------
 *
 * Tracing / debugging
 *
 *--------------------------------------------------------------------*/

#define SOCK_OP_TRACE(x...) ci_log("@@@ trapped socket syscall: " x)

//#define SOCK_OP_ATTACH_DEBUG(x...) ci_log("### " x)
#define SOCK_OP_ATTACH_DEBUG(x...) (void)0

#define SOCK_OP_DEFAULT_ERROR  CI_CFG_SOCKET_SYSCALL_ERROR


/*--------------------------------------------------------------------
 *
 * The intercepted socket operations
 *
 *--------------------------------------------------------------------*/

#if CI_CFG_SOCKET_SYSCALL_INTERCEPT
  
int
_efab_linux_sock_release(struct socket *sock)
{
  /* Called on sock_release(), which we call ourselves from the cleanup code
   * (see efab_linux_cleanup_sock_ops() below).  There's nothing to do here.
   */
  return 0;
}

int
_efab_linux_sock_bind(struct socket *sock, struct sockaddr *umyaddr,
                      int sockaddr_len)
{
  SOCK_OP_TRACE("bind");
  return SOCK_OP_DEFAULT_ERROR;
}

int
_efab_linux_sock_connect(struct socket *sock, struct sockaddr *uservaddr,
                         int sockaddr_len, int flags)
{
  SOCK_OP_TRACE("connect");
  return SOCK_OP_DEFAULT_ERROR;
}

int
_efab_linux_sock_socketpair(struct socket *sock1, struct socket *sock2)
{
  SOCK_OP_TRACE("socketpair");
  return SOCK_OP_DEFAULT_ERROR;
}

int
_efab_linux_sock_accept(struct socket *sock, struct socket *newsock,
                        int flags)
{
  SOCK_OP_TRACE("accept");
  return SOCK_OP_DEFAULT_ERROR;
}

int
_efab_linux_sock_getname(struct socket *sock, struct sockaddr *uaddr,
                         int *usockaddr_len, int peer)
{
  SOCK_OP_TRACE("getname");
  return SOCK_OP_DEFAULT_ERROR;
}

int
_efab_linux_sock_listen(struct socket *sock, int len)
{
  SOCK_OP_TRACE("listen");
  return SOCK_OP_DEFAULT_ERROR;
}

int
_efab_linux_sock_shutdown(struct socket *sock, int flags)
{
  SOCK_OP_TRACE("shutdown");
  return SOCK_OP_DEFAULT_ERROR;
}

int
_efab_linux_sock_setsockopt(struct socket *sock, int level, int optname,
                            char *optval, int optlen)
{
  SOCK_OP_TRACE("setsockopt");
  return SOCK_OP_DEFAULT_ERROR;
}

int
_efab_linux_sock_getsockopt(struct socket *sock, int level, int optname,
                            char *optval, int *optlen)
{
  SOCK_OP_TRACE("getsockopt");
  return SOCK_OP_DEFAULT_ERROR;
}

int
_efab_linux_sock_sendmsg(struct kiocb *iocb, struct socket *sock,
                         struct msghdr *m, size_t total_len)
{
  SOCK_OP_TRACE("sendmsg");
  return SOCK_OP_DEFAULT_ERROR;
}

int
_efab_linux_sock_recvmsg(struct kiocb *iocb, struct socket *sock,
                         struct msghdr *m, size_t total_len, int flags)
{
  SOCK_OP_TRACE("recvmsg");
  return SOCK_OP_DEFAULT_ERROR;
}

unsigned int
_efab_linux_sock_poll(struct file *file, struct socket *sock,
                      struct poll_table_struct *wait)
{
  /* This is only ever called by indirecting through the file operations, so
   * nothing should ever get here.
   */
  SOCK_OP_TRACE("poll (trapped by socket ops, not file ops - ???)");
  ci_assert(0);
  return SOCK_OP_DEFAULT_ERROR;
}

int
_efab_linux_sock_ioctl(struct socket *sock, unsigned int cmd,
                       unsigned long arg)
{
  /* This is only ever called by indirecting through the file operations, so
   * nothing should ever get here.
   */
  SOCK_OP_TRACE("ioctl (trapped by socket ops, not file ops - ???)");
  ci_assert(0);
  return SOCK_OP_DEFAULT_ERROR;
}

int
_efab_linux_sock_mmap(struct file *file, struct socket *sock,
                      struct vm_area_struct * vma)
{
  /* This is only ever called by indirecting through the file operations, so
   * nothing should ever get here.
   */
  SOCK_OP_TRACE("mmap (trapped by socket ops, not file ops - ???)");
  ci_assert(0);
  return SOCK_OP_DEFAULT_ERROR;
}

ssize_t
_efab_linux_sock_sendpage(struct socket *sock, struct page *page, int offset,
                          size_t size, int flags)
{
  /* This is only ever called by indirecting through the file operations, so
   * nothing should ever get here.
   */
  SOCK_OP_TRACE("sendpage (trapped by socket ops, not file ops - ???)");
  ci_assert(0);
  return SOCK_OP_DEFAULT_ERROR;
}


static struct proto_ops _efab_linux_sock_ops = {

  /* Shouldn't matter what is in here, but PF_UNSPEC seems reasonable.
   */
  CI_STRUCT_MBR(family,     PF_UNSPEC                  ),

  /* The kernel expects all of these to be implemented -- it does not check
   * that they are non-NULL before merrily dereferencing them...
   */
  CI_STRUCT_MBR(release,    _efab_linux_sock_release   ),
  CI_STRUCT_MBR(bind,       _efab_linux_sock_bind      ),
  CI_STRUCT_MBR(connect,    _efab_linux_sock_connect   ),
  CI_STRUCT_MBR(socketpair, _efab_linux_sock_socketpair),
  CI_STRUCT_MBR(accept,     _efab_linux_sock_accept    ),
  CI_STRUCT_MBR(getname,    _efab_linux_sock_getname   ),
  CI_STRUCT_MBR(poll,       _efab_linux_sock_poll      ),
  CI_STRUCT_MBR(ioctl,      _efab_linux_sock_ioctl     ),
  CI_STRUCT_MBR(listen,     _efab_linux_sock_listen    ),
  CI_STRUCT_MBR(shutdown,   _efab_linux_sock_shutdown  ),
  CI_STRUCT_MBR(setsockopt, _efab_linux_sock_setsockopt),
  CI_STRUCT_MBR(getsockopt, _efab_linux_sock_getsockopt),
  CI_STRUCT_MBR(sendmsg,    _efab_linux_sock_sendmsg   ),
  CI_STRUCT_MBR(recvmsg,    _efab_linux_sock_recvmsg   ),
  CI_STRUCT_MBR(mmap,       _efab_linux_sock_mmap      ),
  CI_STRUCT_MBR(sendpage,   _efab_linux_sock_sendpage  ),

  /* A couple more entries, kvec_read and kvec_write, appeared at some point
   * (around 2.4.21?), but, unlike the others, the kernel will check and
   * handle the case where they are NULL.  So we can just ignore them.
   */
};


/****************************************************************************
 *
 * efab_linux_attach_sock_ops: hook socket operations in to a new char fd
 *
 ****************************************************************************/

void
efab_linux_attach_sock_ops(struct file *filp)
{
  /*! \TODO - more error handling is needed here */
  
  struct socket *my_sock = SOCK_ALLOC();
  SOCK_OP_ATTACH_DEBUG("allocated socket %p", my_sock);
  if (my_sock) {
    /* Set up a socket-like struct file.  We don't *want* to attach it to a fd,
     * but we don't have much option because sock_map_file() isn't exported.
     * So, we'll just have to remove the installed fd ourselves afterwards...
     */
    struct file *sock_filp = 0;
    int fd = sock_map_fd(my_sock);
    SOCK_OP_ATTACH_DEBUG("mapped socket to fd %d", fd);
    if (fd >= 0) {
      int rc;
      sock_filp = fget(fd);
      SOCK_OP_ATTACH_DEBUG("got sock_filp %p", sock_filp);
      SOCK_OP_ATTACH_DEBUG("refcnt on sock_filp (expect 2) is %d",
                           atomic_read(&sock_filp->f_count));
      rc = sys_close(fd);
      SOCK_OP_ATTACH_DEBUG("sys_close(%d) gave rc=%d", fd, rc);
      SOCK_OP_ATTACH_DEBUG("refcnt on sock_filp (expect 1) is %d",
                           atomic_read(&sock_filp->f_count));
    }
    if (sock_filp) {
      /* We now have:
       *
       *   filp -> dentry for /dev/efab<n> -> char device inode
       *
       *   sock_filp -> dentry for socket -> socket inode
       *
       * The theory is that we swap the dentry (and vfsmnt) pointers over:
       *
       *   sock_filp -> dentry for /dev/efab<n> -> char device inode
       *
       *   filp -> dentry for socket -> socket inode
       *
       * then destroy the sock_filp (which now points to the char device
       * dentry and inode) which we don't want.  There are a couple of
       * details, though: 1) we must ensure that the socket inode can be
       * identified as one of ours, and 2) before we destroy the sock_filp,
       * we manually unhook the file_operations to ensure that it doesn't
       * try to do socket-like cleanup on a dentry/inode that isn't a socket
       * any more.
       *
       * Yes, this is all really horrible...
       */
      
      /* Drop the reference count on the original filp dentry and vfsmnt. */
      struct dentry *filp_dentry = filp->f_dentry;
      struct vfsmount *filp_vfsmnt = filp->f_vfsmnt;
      SOCK_OP_ATTACH_DEBUG("Original filp: dentry=%p vfsmnt=%p",
                            filp->f_dentry, filp->f_vfsmnt);
      /* Update the socket inode to look like our device.  We have to set
       * the mode back to S_IFCHR instead of S_IFSOCK because i_rdev is not
       * initialised for sockets, and hence might possibly contain our device
       * ID (I've seen this at least a couple of times!) for an OS socket,
       * which would confuse our fdtable code...
       */
      sock_filp->f_dentry->d_inode->i_mode = filp->f_dentry->d_inode->i_mode;
      sock_filp->f_dentry->d_inode->i_rdev = filp->f_dentry->d_inode->i_rdev;
      /* Attach the socket filp dentry and vfsmnt to the original filp. */
      filp->f_dentry = sock_filp->f_dentry;
      filp->f_vfsmnt = sock_filp->f_vfsmnt;
      SOCK_OP_ATTACH_DEBUG("Socket filp: dentry=%p vfsmnt=%p",
                           sock_filp->f_dentry, sock_filp->f_vfsmnt);
      /* Now put the original ones into the socket filp.  We can't just set
       * them to NULL and handle them ourselves, as fput() will dereference
       * them (at least the dentry).
       */
      sock_filp->f_dentry = filp_dentry;
      sock_filp->f_vfsmnt = filp_vfsmnt;
      /* Get rid of the file ops in the the socket filp, to ensure that it
       * doesn't do anything weird when we fput() it.
       */
      fops_put(sock_filp->f_op);
      sock_filp->f_op = NULL;
      /* Now it should be safe to remove the socket filp (and hence a reference
       * to the original dentry/vfsmount).
       */
      SOCK_OP_ATTACH_DEBUG("refcnt on sock_filp (expect 1) is %d",
                           atomic_read(&sock_filp->f_count));
      fput(sock_filp);
      /* The final thing to do is attach our socket operations, and the
       * original file pointer, to the struct socket.
       */
      my_sock->ops = &_efab_linux_sock_ops;
      my_sock->file = filp;
    }
  }

}


/****************************************************************************
 *
 * efab_linux_cleanup_sock_ops: clean up socket hook state
 *
 ****************************************************************************/

void
efab_linux_cleanup_sock_ops(struct inode *inode)
{
  /* This inode should look like a socket (as it should be one that we mangled
   * earlier), and we have to call sock_release().
   */

  /* If we want to re-enable this code, we need to find a way to do it
   * without using i_sock
   */
#warning "i_sock does not exist in more recent kernels"

  if (inode->i_sock) {
    struct socket *sock = SOCKET_I(inode); /* = socki_lookup() */
    SOCK_OP_ATTACH_DEBUG("Closing socket inode %p (sock=%p, sock->file=%p)",
                         inode, sock, sock->file);
    sock_release(sock);
  } else {
    ci_log("Mysterious close of non-socket inode %p - ???", inode);
  }
}


#endif /* CI_CFG_SOCKET_SYSCALL_INTERCEPT */


/**************************************************************************** 
 * 
 * efab_linux_dump_inode: debugging support for dumping inode info
 * 
 ****************************************************************************/ 

int
efab_linux_dump_inode(int fd) 
{
  struct file *filp;
  filp = fget(fd);
  if (filp && filp->f_dentry) {
    struct inode *inode = filp->f_dentry->d_inode;
    
    ci_log("dump inode: fd %d => filp=%p -> dentry %p", fd, filp,
           filp->f_dentry);
    ci_log("  inode at %p", inode);
    ci_log("    i_ino=%lu  i_rdev=%08x",
           inode->i_ino, inode->i_rdev);
    ci_log("    i_op=%p  i_fop=%p  i_sb=%p  i_state=%08lx",
           inode->i_op, inode->i_fop, inode->i_sb, inode->i_state);
    fput(filp);
  } else {
    ci_log("dump_inode: couldn't get struct file for fd %d", fd);
  }
  return 0;
}


/*! \cidoxg_end */
