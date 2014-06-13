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
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  ok_sasha
**  \brief  Linux driver mmap internal interfaces
**   \date  2007/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal */

#ifndef __ONLOAD_LINUX_MMAP_H__
#define __ONLOAD_LINUX_MMAP_H__

#include <ci/tools.h>
#include <onload/tcp_helper.h>
#include <onload/signals.h>

/* Trampolining requires us to maintain per-process state for each app using us
 * -- the address of the trampoline handler that we need to return to.  We do
 * this by maintaining a hash-table for MMs that are mapped onto our resources
 * (if a process is using our stack, if must have mapped the mm)
 */
struct mm_signal_data {
  __sighandler_t    handler_postpone1;
  __sighandler_t    handler_postpone3;
  void             *sarestorer;
  __sighandler_t    handlers[OO_SIGHANGLER_DFL_MAX+1];
  ci_user_ptr_t     user_data;
  ci_uint32/*bool*/ sa_onstack_intercept;
};


struct mm_hash {
  ci_dllink         link;
  struct mm_struct *mm;

  ci_user_ptr_t     trampoline_entry;
  ci_user_ptr_t     trampoline_exclude;
  CI_DEBUG(ci_user_ptr_t trampoline_ul_fail;)

  struct mm_signal_data signal_data;

  unsigned          ref;
  unsigned          magic;
};

/* A lock to protect the hash-table.  If we really wanted to go mad we could
 * have one lock per entry in the table.  But the hash-table is infrequently
 * updated, so a single r/w lock should suffice.
 */
extern rwlock_t oo_mm_tbl_lock;

extern void oo_mm_tbl_init(void);

extern struct mm_hash* oo_mm_tbl_lookup(struct mm_struct*);

int oo_fop_mmap(struct file* file, struct vm_area_struct* vma);


#endif /* __ONLOAD_LINUX_MMAP_H__ */
