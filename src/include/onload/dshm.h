/*
** Copyright 2005-2018  Solarflare Communications Inc.
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

/**
 * \file Kernel interface to "donation" shared memory.
 */

#ifndef __OO_DSHM_H__
#define __OO_DSHM_H__

#ifdef __cplusplus
extern "C" {
#endif


enum {
  OO_DSHM_CLASS_ZF_STACK,
  OO_DSHM_CLASS_ZF_PACKETS,
  OO_DSHM_CLASS_COUNT,
};


#ifdef __KERNEL__

extern int
oo_dshm_register_impl(ci_int32 shm_class, ci_user_ptr_t user_addr,
                      ci_uint32 length, ci_int32* buffer_id_out,
                      ci_dllist* handle_list);

extern int
oo_dshm_list_impl(ci_int32 shm_class, ci_user_ptr_t buffer_ids,
                  ci_uint32* count_in_out);

extern void
oo_dshm_init(void);

extern void
oo_dshm_fini(void);

extern int
oo_dshm_free_handle_list(ci_dllist*);

#ifdef OO_MMAP_TYPE_DSHM
extern int
oo_dshm_mmap_impl(struct vm_area_struct*);
#endif

#endif


#ifdef __cplusplus
}
#endif

#endif /* ! defined(__OO_DSHM_H__) */

