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


#ifndef __LINUX_CPLANE_INTERNAL_H__
#define __LINUX_CPLANE_INTERNAL_H__

#include <cplane/internal.h>
#include <linux/module.h>

/* for EFX_USE_CANCEL_DELAYED_WORK_SYNC */
#include <driver/linux_net/kernel_compat.h>
/* for EFRM_SOCK_CREATE_KERN_HAS_NET, EFRM_HAVE_TEAMING */
#include <driver/linux_affinity/autocompat.h>

#include <linux/workqueue.h>
#include <linux/net.h>

#ifndef EFX_USE_CANCEL_DELAYED_WORK_SYNC
/* When we need cancel_delayed_work_sync(), the work item can be
 * re-scheduled only once.  We always drop the "running" flag before
 * cancel_delayed_work_sync() call. */
#define cancel_delayed_work_sync(wi)    \
  do {                                  \
    cancel_delayed_work(wi);            \
    flush_scheduled_work();             \
    cancel_delayed_work(wi);            \
  } while(0)
#endif

#ifndef EFRM_SOCK_CREATE_KERN_HAS_NET
struct net;
static inline int my_sock_create_kern(struct net *net, int family, int type,
                                  int proto, struct socket **res)
{
  return sock_create_kern(family, type, proto, res);
}
#define sock_create_kern my_sock_create_kern
#endif


extern int ci_bonding_init(void);
extern void ci_bonding_fini(void);

struct cicp_mibs_kern_s;
#ifdef EFRM_HAVE_TEAMING
extern int ci_teaming_init(struct cicp_mibs_kern_s* cplane);
extern void ci_teaming_fini(struct cicp_mibs_kern_s* cplane);
#else
static inline int ci_teaming_init(struct cicp_mibs_kern_s* cplane)
{ return 0; }
static inline void ci_teaming_fini(struct cicp_mibs_kern_s* cplane)
{ }
#endif

extern int cicp_chrdev_ctor(const char *name);
extern void cicp_chrdev_dtor(const char *name);
#endif /* __LINUX_CPLANE_INTERNAL_H__ */
