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
 * *//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  ds
**  \brief  Efabcfg driver interface.
**   \date  2005/11/17
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_include_ci_driver_efab  */

#ifndef __CI_DRIVER_EFAB_EFABCFG_H__
#define __CI_DRIVER_EFAB_EFABCFG_H__


#include <ci/internal/efabcfg.h>


extern int ci_cfg_handle_query_ioctl(struct ci_private_s *unused, void *arg);
extern int ci_cfg_handle_set_ioctl(struct ci_private_s *unused, void *arg);
extern int ci_cfg_handle_unset_ioctl(struct ci_private_s *unused, void *arg);
extern int ci_cfg_handle_get_ioctl(struct ci_private_s *unused, void *arg);


extern int ci_cfg_apply_patches(ci_uint8 *buf[CICFG_BLOB_ID_COUNT],
                                size_t bufsize[CICFG_BLOB_ID_COUNT],
                                ci_cfg_uid_t uid,
                                const char *proc_name,
                                const ci_cfg_hdr_t *hdr);


extern ci_cfg_ioctl_desc_err_t
ci_cfg_database_query(ci_uint8 *buf[CICFG_BLOB_ID_COUNT],
                      size_t bufsize[CICFG_BLOB_ID_COUNT],
                      ci_cfg_uid_t *uid,
                      const char *proc_name);


/*! get the process name of the current process */
extern const char *ci_cfg_proc_name_get(char** pointer_to_free);


/*! get the effective user id of the current process */
extern ci_cfg_uid_t ci_cfg_uid_get(void);

 
/*! get a pointer to installed database odject*/
extern ci_cfg_hdr_t * ci_cfg_get(void);


/*! install a database object */
extern int ci_cfg_set(ci_cfg_hdr_t *db, ci_uint32 len);


/*! allocate memory for the database object; by allocating the memory ourselves
 * we know which method to use to free it
 */
ci_inline void* ci_cfg_malloc(size_t n)
{
  return (void*) ci_vmalloc(n);
}


/*! free the database object; the memory should have been allocated with
 * ci_cfg_malloc
 */
ci_inline void ci_cfg_free(void *p)
{
  ci_vfree(p);
}


extern int ci_cfg_rd_trylock(void);
extern void ci_cfg_rd_unlock(void);

extern int ci_cfg_wr_trynlock(void);
extern void ci_cfg_wr_unlock(void);

/* Common IOCTL handlers for both linux and windows */
void ci_cfg_handle_set_ioctl_common(ci_cfg_ioctl_desc_t *pdesc);
void ci_cfg_handle_query_ioctl_common(ci_cfg_ioctl_desc_t *pdesc);
void ci_cfg_handle_get_ioctl_common(ci_cfg_ioctl_desc_t *pdesc);

/* Functions potentially needed for ioctl handlers - different impl in unix/windows */
extern int ci_cfg_is_sysadmin(void);

#endif /*__CI_DRIVER_EFAB_EFABCFG_H__*/
