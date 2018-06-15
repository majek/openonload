/*
** Copyright 2005-2018  Solarflare Communications Inc.
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

#ifndef __ONLOAD_CPLANE_MODULE_PARAMS_H__
#define __ONLOAD_CPLANE_MODULE_PARAMS_H__

#include <linux/moduleparam.h>

#include <driver/linux_onload/onload_kernel_compat.h>

/* Module parameters */
extern int cplane_init_timeout;
extern bool cplane_spawn_server;
extern char* cplane_server_path;
extern char* cplane_server_params;
extern int cplane_server_grace_timeout;
extern int cplane_route_request_limit;
extern int cplane_route_request_timeout_ms;

extern int cplane_server_path_set(const char* val,
                                  ONLOAD_MPC_CONST struct kernel_param*);
extern int cplane_server_path_get(char* buffer,
                                  ONLOAD_MPC_CONST struct kernel_param*);
extern int cplane_server_params_set(const char* val,
                                    ONLOAD_MPC_CONST struct kernel_param*);
extern int cplane_server_params_get(char* buffer,
                                    ONLOAD_MPC_CONST struct kernel_param*);
extern int 
cplane_server_grace_timeout_set(const char* val,
                                ONLOAD_MPC_CONST struct kernel_param* kp);
extern int 
cplane_route_request_timeout_set(const char* val,
                                 ONLOAD_MPC_CONST struct kernel_param* kp);

#endif /* __ONLOAD_CPLANE_MODULE_PARAMS_H__ */
