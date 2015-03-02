/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
** <L5_PRIVATE L5_SOURCE>
** \author  slp
**  \brief  iscsi helpers in onload driver
**     $Id$
**   \date  2002/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux_onload */
 
/*--------------------------------------------------------------------
 *
 * CI headers
 *
 *--------------------------------------------------------------------*/

#include <ci/driver/internal.h>
#include <ci/driver/efab/linux_iscsi.h>
#include <onload/fd_private.h>


static int ok_for_iscsi;
static struct module *ci_iscsi_module;
static struct semaphore ci_iscsi_ioctl_mutex;
static int (*ci_iscsi_ctor_fn)(void);
static int (*ci_iscsi_handle_ioctl_fn)(struct file *, ci_iscsi_control_params *);
static int (*ci_iscsi_control_ctor_fn)(void) = 0;
static void (*ci_iscsi_control_dtor_fn)(void) = 0;
static void (*ci_iscsi_dtor_fn)(void) = 0;


void
efab_prepare_for_iscsi(void)
{
  /* Initialise iSCSI ioctl mutex */
  sema_init(&ci_iscsi_ioctl_mutex, 1);

  /* The iSCSI driver cannot be loaded until this function returns
   * success. */
  ci_assert_equal(ci_iscsi_ctor_fn, NULL);
  ok_for_iscsi = 1;
}

void
efab_cleanup_in_iscsi(void)
{
  ci_assert_equal(ci_iscsi_ctor_fn, NULL);
}



static int ci_protect_module(struct module *m)
{
  return try_module_get(m);
}
static void ci_unprotect_module(struct module *m)
{

  module_put(m);
}

int
ioctl_iscsi_control_op (ci_private_t *priv, void *arg)
{
  ci_iscsi_control_params *params = arg;
  int rc;
  struct module *iscsi_module;

  if( !ci_is_sysadmin() )  return -EPERM;

  iscsi_module = ci_iscsi_module;
  if(iscsi_module != NULL && ci_protect_module(iscsi_module))
  {
    if (down_interruptible(&ci_iscsi_ioctl_mutex) != 0)  return -EINTR;

    rc = ci_iscsi_handle_ioctl_fn(priv->_filp, params);

    ci_assert(down_trylock(&ci_iscsi_ioctl_mutex));
    up(&ci_iscsi_ioctl_mutex);

    ci_unprotect_module(iscsi_module);
  }
  else
  {
    return -EUNATCH;
  }

  return rc;
}

/* ISCSI setup code: set up ctor and dtor after control_ctor and control_dtor */
int efab_register_iscsi_driver(efab_iscsi_driver_t *iscsi)
{
  int ctor_here;
  int rc = 0;
  ci_assert(iscsi);
  ci_assert(iscsi->iscsi_ctor);
  ci_assert(iscsi->iscsi_ctrl_ctor);
  ci_assert(iscsi->iscsi_dtor);
  ci_assert(iscsi->iscsi_ctrl_dtor);
  ci_assert(iscsi->iscsi_ioctl);
  ci_assert_equal(ci_iscsi_module, NULL);
  ctor_here = ok_for_iscsi; /* Does this need to be atomic? */

  ci_iscsi_control_ctor_fn = iscsi->iscsi_ctrl_ctor;
  ci_iscsi_ctor_fn = iscsi->iscsi_ctor;

  ci_iscsi_control_dtor_fn = iscsi->iscsi_ctrl_dtor;
  ci_iscsi_dtor_fn = iscsi->iscsi_dtor;

  ci_iscsi_handle_ioctl_fn = iscsi->iscsi_ioctl;
  ci_iscsi_module = iscsi->iscsi_module;

  if ( ctor_here ) {
    rc = ci_iscsi_ctor_fn();
    if (rc == 0)
      rc = ci_iscsi_control_ctor_fn();
  }
  return rc;
} 

void efab_unregister_iscsi_driver(efab_iscsi_driver_t *iscsi)
{
  (void)iscsi; /* We could in principle check the right thing is being unregistered. */
  ci_assert_equal(ci_iscsi_module, iscsi->iscsi_module);
  ci_iscsi_module = NULL;
  ci_iscsi_handle_ioctl_fn = NULL;
  ci_iscsi_control_dtor_fn();
  ci_iscsi_dtor_fn();
  ci_iscsi_ctor_fn = 0;
}
EXPORT_SYMBOL(efab_register_iscsi_driver);
EXPORT_SYMBOL(efab_unregister_iscsi_driver);

/*! \cidoxg_end */
