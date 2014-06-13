/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
** <L5_PRIVATE L5_HEADER>
** \author ds
**  \brief Header file for citp_opts_t struct.
**   \date 5/12/2005 
**    \cop (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci */

#ifndef __CITP_OPTS_H__
#define __CITP_OPTS_H__


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
  /* These fields are defined in a separate file that is also used by the 
  ** configuration subsystem
  */
#define _CI_CFG_BITFIELD
#define _CI_CFG_BITFIELD1  :1
#define _CI_CFG_BITFIELD2  :2
#define _CI_CFG_BITFIELD3  :3
#define _CI_CFG_BITFIELD4  :4
#define _CI_CFG_BITFIELD8  :8
#define _CI_CFG_BITFIELD16 :16
#define _CI_CFG_BITFIELDA8 CI_ALIGN(8)
    
#undef CI_CFG_OPTFILE_VERSION
#undef CI_CFG_OPT
#undef CI_CFG_OPTGROUP

#define CI_CFG_OPTFILE_VERSION(version)
#define CI_CFG_OPTGROUP(group, category, expertise)
#define CI_CFG_OPT(env, name, type, doc, bits, group, default, min, max, presentation) \
        type name _CI_CFG_BITFIELD##bits;

#include <ci/internal/opts_citp_def.h>
} CI_ALIGN(8) citp_opts_t; /* This alignment is needed for running
                            * 32bits apps on 64bits kernel.  Aligning
                            * it where the struct is actually used
                            * didn't help but this seems to.
                            */


#ifdef __cplusplus
}
#endif


#endif  /* __CITP_OPTS_H__ */

/*! \cidoxg_end */
