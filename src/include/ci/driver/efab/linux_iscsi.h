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
*//*! \file linux_scsi.h
** <L5_PRIVATE L5_HEADER >
** \author  mjs
**  \brief  ISCSI interface to SCSI devices
**   \date  2005/07/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab */

#ifndef __CI_DRIVER_EFAB_LINUX_ISCSI_H__
#define __CI_DRIVER_EFAB_LINUX_ISCSI_H__

#ifndef __ci_driver__
#error "This is a driver module."
#endif

/* ============================================================================
 *  iSCSI OS abstraction implementation header for Linux (2.6)
 * ============================================================================
 */

#include <ci/internal/transport_config_opt.h>
#include <onload/primitive_types.h>
#include <ci/iscsi/sis_interface.h>

#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <linux/proc_fs.h>

typedef struct scsi_cmnd *ci_iscsi_cmd_handle;

/* For iSCSI protocol layer to store a private pointer with a command */
ci_inline void ci_iscsi_cmd_handle_set_priv(ci_iscsi_cmd_handle handle,
                                            void *priv)
{
  handle->host_scribble = priv;
}

/* For iSCSI protocol layer to retrieve a private pointer with a command */
ci_inline void *ci_iscsi_cmd_handle_get_priv(ci_iscsi_cmd_handle handle)
{
  return handle->host_scribble;
}

ci_inline void ci_iscsi_cmd_handle_invalidate(ci_iscsi_cmd_handle *handlep)
{
  *handlep = NULL;
}

ci_inline int ci_iscsi_cmd_handle_is_valid(ci_iscsi_cmd_handle handle)
{
  return handle != NULL;
}

/* Keep a pointer to each of the scsi_devices served by this session,
 * so that they can be removed. */
#define CI_ISCSI_MAX_LUNS           8
typedef struct
{
  struct scsi_device *sdevs[CI_ISCSI_MAX_LUNS];
} ci_iscsi_scsi_handle;

ci_inline void ci_iscsi_scsi_handle_invalidate(ci_iscsi_scsi_handle *handle)
{
  int lun;
  for(lun=0; lun<CI_ISCSI_MAX_LUNS; lun++)
    handle->sdevs[lun] = 0;
}

/* ============================================================================
 *  Registration with the char driver.
 * ============================================================================
 */

typedef struct {
  struct module *iscsi_module;
  int (*iscsi_ctor)(void);
  int (*iscsi_ctrl_ctor)(void);
  void (*iscsi_ctrl_dtor)(void);
  void (*iscsi_dtor)(void);
  int (*iscsi_ioctl)(struct file *, ci_iscsi_control_params *);
} efab_iscsi_driver_t;

extern int efab_register_iscsi_driver(efab_iscsi_driver_t *iscsi);
extern void efab_unregister_iscsi_driver(efab_iscsi_driver_t *iscsi);

extern int ci_iscsi_stats_ctor(void);
extern int ci_iscsi_stats_dtor(void);


#endif

/*! \cidoxg_end */

