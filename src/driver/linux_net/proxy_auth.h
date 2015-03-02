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

/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2014-2015 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_PROXY_AUTH_H
#define EFX_PROXY_AUTH_H

#include "nic.h"
#include "net_driver.h"

typedef int efx_proxy_auth_send_request(struct efx_nic *efx, u64 uhandle,
		   u16 pf, u16 vf, u16 rid,
		   const void *request_buffer, size_t request_len);

typedef void efx_proxy_auth_stopped(struct efx_nic *efx);

int efx_proxy_auth_configure_one(struct efx_nic *efx,
		size_t request_size, size_t response_size, unsigned int op,
		u32 handled_privileges, u32 default_result,
		efx_proxy_auth_send_request *request_func,
		efx_proxy_auth_stopped *stopped_func);

int efx_proxy_auth_configure_list(struct efx_nic *efx,
		size_t request_size, size_t response_size,
		unsigned int *op_list, unsigned int op_count,
		u32 handled_privileges, u32 default_result,
		efx_proxy_auth_send_request *request_func,
		efx_proxy_auth_stopped *stopped_func);

int efx_proxy_auth_stop(struct efx_nic *efx, bool unloading);
int efx_proxy_auth_detached(struct efx_nic *efx);
int efx_proxy_auth_attach(struct efx_nic *efx);
void efx_proxy_auth_stop_work(struct work_struct *data);

int efx_proxy_auth_handle_request(struct efx_nic *efx, u32 index);

int efx_proxy_auth_handle_response(struct proxy_admin_state *pa,
		u64 uhandle, u32 result, u32 granted_privileges,
		void *response_buffer, size_t response_size,
		void (*complete_cb)(int, void*), void *cb_context);
#endif
