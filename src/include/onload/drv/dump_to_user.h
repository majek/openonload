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

#ifndef __ONLOAD_DRV_DUMP_TO_USER_H__
#define __ONLOAD_DRV_DUMP_TO_USER_H__


typedef void (*oo_dump_log_fn_t)(void* log_fn_arg, const char* fmt, ...);

typedef void (*oo_dump_fn_t)(void* oo_dump_fn_arg, oo_dump_log_fn_t log,
                             void* log_arg);

extern int oo_dump_to_user(oo_dump_fn_t, void* dump_fn_arg,
                           void* user_buf, int user_buf_len);


#endif  /* __ONLOAD_DRV_DUMP_TO_USER_H__ */
