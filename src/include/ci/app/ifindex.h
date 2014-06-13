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
** \author  djr
**  \brief  An interface to translate between ifindex and interface name.
**   \date  2008/12/18
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_app */
#ifndef __CI_APP_IFINDEX_H__
#define __CI_APP_IFINDEX_H__


extern int ci_net_interface_ifindex_to_name(int ifindex, char* name_buf,
                                            int name_buf_len);

/* Translates [name] to an ifindex.  [name] may either be an integer (which
 * is returned) or an interface name such as "eth2".  Returns a -ve error
 * code on failure.
 */
extern int ci_net_interface_name_to_ifindex(const char* name);


#endif  /* __CI_APP_IFINDEX_H__ */
/*! \cidoxg_end */
