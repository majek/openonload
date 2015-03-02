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
** \author  stg
**  \brief  Access to sys calls
**   \date  2007/05/16
**    \cop  (c) Solarflare Communications Inc
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ef */


/* This is required to get pread() and pwrite() defined in <unistd.h> */
#define _GNU_SOURCE
# include <aio.h>

#include <ci/tools.h>
#include <ci/internal/transport_config_opt.h>
//??#include "ef_vi_internal.h"
//??#include "ef_vi_internal2.h"

#include <onload/syscall_unix.h>
/* define the ci_sys_ pointers */
# define CI_MK_DECL(ret, fn, args)  ret (*ci_sys_##fn) args = fn
# include <onload/declare_syscalls.h.tmpl>

/* define the ci_libc_ pointers */
# define CI_MK_DECL(ret, fn, args)  ret (*ci_libc_##fn) args = fn
# include <onload/declare_libccalls.h.tmpl>


/*! \cidoxg_end */
