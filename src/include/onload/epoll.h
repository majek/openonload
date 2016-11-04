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
*//*! \file epoll_calls.c
** <L5_PRIVATE L5_HEADER >
** \author  oktet sasha
**  \brief  /dev/onload_epoll char device ioctl data
**   \date  2011/03/07
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_EPOLL_H__
#define __ONLOAD_EPOLL_H__

#include <ci/internal/transport_config_opt.h>

#if CI_CFG_USERSPACE_EPOLL

//#include <onload/primitive_types.h>
#include <onload/common.h>
#ifdef __KERNEL__
#include <linux/eventpoll.h>
#else
#include <sys/epoll.h>
#endif

/* Array of such structures is used to pass postponed epoll_ctl operations */
struct oo_epoll_item {
  ci_fixed_descriptor_t op;
  ci_fixed_descriptor_t fd;
  ci_uint64             fdi_seq; /**< ignored in kernel */
  struct epoll_event    event;
  /* [unused_pad] is needed to ensure that oo_epoll_item is the same size
   * in 32 and 64-bit builds.
   */
  ci_uint32             unused_pad;
};

/* epoll_wait/epoll_pwait */
struct oo_epoll2_action_arg {
  ci_fixed_descriptor_t kepfd;     /**< INOUT kernel epoll fd */
  ci_user_ptr_t         epoll_ctl; /**< struct oo_epoll_item * */
  ci_user_ptr_t         sigmask;   /**< const sigset_t * */
  ci_user_ptr_t         events;    /**< struct epoll_event * */
  ci_uint64             spin_cycles;
  ci_uint32             maxevents;
  ci_int32              timeout;
  ci_int32              rc;        /**< OUT return code */
  ci_uint32             epoll_ctl_n;
};

struct oo_epoll1_ctl_arg {
  ci_fixed_descriptor_t epfd;      /**< epoll descriptor for all fds */
  ci_fixed_descriptor_t fd;
  ci_user_ptr_t         event;
  ci_int32              op;

};

struct oo_epoll1_wait_arg {
  ci_user_ptr_t         events;    /**< struct epoll_event * */
  ci_fixed_descriptor_t epfd;      /**< epoll descriptor for all fds */
  ci_uint32             maxevents;
  ci_int32              rc;        /**< OUT return code */
};

struct oo_epoll1_set_home_arg {
  ci_fixed_descriptor_t sockfd;      /**< descriptor for fd in stack */
  ci_int32              ready_list;  /**< id of ready list to use */
  /* [unused_pad] is needed to ensure that oo_epoll_item is the same size
   * in 32 and 64-bit builds.
   */
  ci_uint32             unused_pad;
};

struct oo_epoll1_block_on_arg {
  ci_uint64     sigmask;
  ci_fixed_descriptor_t epoll_fd;
  ci_uint32     timeout_ms;
  ci_uint32     flags; /* INOUT */
#define OO_EPOLL1_EVENT_ON_HOME  1 /* OUT */
#define OO_EPOLL1_EVENT_ON_OTHER 2 /* OUT */
#define OO_EPOLL1_HAS_SIGMASK    4 /* IN */
};

struct oo_epoll1_shared {
  ci_fixed_descriptor_t epfd; /**< OS epoll fd; UL should use it for
                                   closing only */
  ci_uint32             flag; /**< seq << 1 | event */
#define OO_EPOLL1_FLAG_EVENT     1
#define OO_EPOLL1_FLAG_SEQ_SHIFT 1
};

#define OO_EPOLL_IOC_BASE 99
enum {
  OO_EPOLL2_OP_INIT,
#define OO_EPOLL2_IOC_INIT \
  _IOW(OO_EPOLL_IOC_BASE, OO_EPOLL2_OP_INIT, ci_fixed_descriptor_t)
  OO_EPOLL2_OP_ACTION,
#define OO_EPOLL2_IOC_ACTION \
  _IOWR(OO_EPOLL_IOC_BASE, OO_EPOLL2_OP_ACTION, struct oo_epoll2_action_arg)
  OO_EPOLL1_OP_CTL,
#define OO_EPOLL1_IOC_CTL \
  _IOW(OO_EPOLL_IOC_BASE, OO_EPOLL1_OP_CTL, struct oo_epoll1_ctl_arg)
  OO_EPOLL1_OP_WAIT,
#define OO_EPOLL1_IOC_WAIT \
  _IOWR(OO_EPOLL_IOC_BASE, OO_EPOLL1_OP_WAIT, struct oo_epoll1_wait_arg)
  OO_EPOLL1_OP_ADD_STACK,
#define OO_EPOLL1_IOC_ADD_STACK \
  _IOW(OO_EPOLL_IOC_BASE, OO_EPOLL1_OP_ADD_STACK, ci_fixed_descriptor_t)
  OO_EPOLL1_OP_PRIME,
#define OO_EPOLL1_IOC_PRIME \
  _IO(OO_EPOLL_IOC_BASE, OO_EPOLL1_OP_PRIME)
  OO_EPOLL_OP_CLONE,
#define OO_EPOLL_IOC_CLONE \
  _IOWR(OO_EPOLL_IOC_BASE, OO_EPOLL_OP_CLONE, ci_clone_fd_t)
  OO_EPOLL1_OP_SET_HOME_STACK,
#define OO_EPOLL1_IOC_SET_HOME_STACK \
  _IOW(OO_EPOLL_IOC_BASE, OO_EPOLL1_OP_SET_HOME_STACK, \
       struct oo_epoll1_set_home_arg)
  OO_EPOLL1_OP_REMOVE_HOME_STACK,
#define OO_EPOLL1_IOC_REMOVE_HOME_STACK \
  _IO(OO_EPOLL_IOC_BASE, OO_EPOLL1_OP_REMOVE_HOME_STACK)
  OO_EPOLL1_OP_BLOCK_ON,
#define OO_EPOLL1_IOC_BLOCK_ON \
  _IOWR(OO_EPOLL_IOC_BASE, OO_EPOLL1_OP_BLOCK_ON, \
        struct oo_epoll1_block_on_arg)
  OO_EPOLL1_OP_MOVE_FD,
#define OO_EPOLL1_IOC_MOVE_FD \
  _IOW(OO_EPOLL_IOC_BASE, OO_EPOLL1_OP_MOVE_FD, ci_fixed_descriptor_t)
};

#endif /* CI_CFG_USERSPACE_EPOLL */
#endif /* __ONLOAD_EPOLL_H__ */

