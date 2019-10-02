/*
** Copyright 2005-2019  Solarflare Communications Inc.
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
** \author  cgg & ds
**  \brief  Decls & defs for the configuration database libraries.
**   \date  2005/11/17
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */

#ifndef __CI_INTERNAL_EFABCFG_H__
#define __CI_INTERNAL_EFABCFG_H__

#include <ci/compat.h>
#include <ci/tools.h>
#include <ci/internal/ip.h>
#include <ci/internal/citp_opts.h>
#include <onload/common.h>

#if !defined(__KERNEL__)
#include <onload/ul.h>
#endif

#include <ci/internal/ip.h>
#include <ci/internal/citp_opts.h>
#include <ci/internal/user_opts.h>


typedef struct {
  citp_opts_t          citp_opts;
  ci_netif_config_opts netif_opts;
  ci_user_opts_t       user_opts;
} ci_cfg_opts_t;


#define CITP_OPTS (ci_cfg_opts.citp_opts)
extern ci_cfg_opts_t ci_cfg_opts CI_HV;
extern int ci_cfg_query(void);

/* Needed to support list of port numbers in EF_ options */
struct ci_port_list {
  ci_dllink link;
  ci_uint16 port;
};


#endif  /* __CI_INTERNAL_EFABCFG_H__ */

/*! \cidoxg_end */
