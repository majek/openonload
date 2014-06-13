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
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Support for user-level select().
**   \date  2011/02/21
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __UL_SELECT_H__
#define __UL_SELECT_H__


struct oo_ul_select_state {
  fd_set *rdu, *wru, *exu;
  fd_set *rdk, *wrk, *exk;
  fd_set *rdi, *wri, *exi;
  int       nfds_inited;
  int       nfds_split;
  int       is_ul_fd;
  int       is_kernel_fd;
  ci_uint64 now_frc;
  unsigned  ul_select_spin;
};


#endif  /* __UL_SELECT_H__ */
