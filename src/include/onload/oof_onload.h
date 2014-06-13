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

#ifndef __ONLOAD_OOF_ONLOAD_H__
#define __ONLOAD_OOF_ONLOAD_H__


struct efab_tcp_driver_s;


extern int  oof_onload_ctor(struct efab_tcp_driver_s*, unsigned local_addr_max);
extern void oof_onload_dtor(struct efab_tcp_driver_s*);


#endif  /* __ONLOAD_OOF_ONLOAD_H__ */
