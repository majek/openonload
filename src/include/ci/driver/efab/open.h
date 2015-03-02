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
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Public types and defs for driver & h/w interface.
**   \date  2002/02/04
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab  */
#ifndef __CI_DRIVER_EFAB_OPEN_H__
#define __CI_DRIVER_EFAB_OPEN_H__

#ifndef __CI_TOOLS_H__
# include <ci/tools.h>
#endif


# ifdef __KERNEL__
     struct efhw_nic_s;
     typedef struct efhw_nic_s* ci_fd_t;
#  define CI_FD_BAD ((ci_fd_t)(NULL))
     typedef int ci_descriptor_t;
# else /* Userland */
     typedef int ci_fd_t;
#    define CI_FD_BAD ((ci_fd_t)(-1))
     typedef int ci_descriptor_t;
# endif

/* identical in UL & kernel */
#    define  from_descriptor( desc ) desc
#    define  to_descriptor( desc ) ((ci_descriptor_t)(desc))
#    define  IS_VALID_DESCRIPTOR(fd) ((fd)>=0)
#    define  DESCRIPTOR_FMT "%d"

#define  DESCRIPTOR_PRI_ARG(fd) fd


/*----------------------------------------------------------------------------
 *
 * Open hardware API - Internally this is compile time selectable 
 *
 *---------------------------------------------------------------------------*/


#endif  /* __CI_DRIVER_EFAB_OPEN_H__ */
/*! \cidoxg_end */
