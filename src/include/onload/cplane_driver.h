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

/* Driver-specific cplane interface. */
#ifndef __ONLOAD_CPLANE_DRIVER_H__
#define __ONLOAD_CPLANE_DRIVER_H__

#include <linux/mm.h>

#define DEFAULT_CPLANE_SERVER_PATH "/sbin/onload_cp_server"

struct ci_private_s;
struct oo_cplane_handle;
extern int oo_cplane_mmap(struct ci_private_s* priv,
                          struct vm_area_struct* vma);
extern int oo_cp_get_mib_size(struct ci_private_s *priv, void *arg);
extern int oo_cp_fwd_resolve_rsop(struct ci_private_s *priv, void *arg);
extern int oo_cp_fwd_resolve_complete(struct ci_private_s *priv, void *arg);
extern int oo_cp_arp_resolve_rsop(struct ci_private_s *priv, void *arg);
extern int oo_cp_arp_confirm_rsop(struct ci_private_s *priv, void *arg);
extern int oo_cp_get_active_hwport_mask(struct oo_cplane_handle* cp,
                                        ci_ifid_t ifindex,
                                        cicp_hwport_mask_t *hwport_mask);
extern int oo_cp_driver_ctor(void);
extern int oo_cp_driver_dtor(void);

extern struct oo_cplane_handle*
cp_acquire_from_netns(struct net* netns);
extern struct oo_cplane_handle*
cp_acquire_from_netns_if_exists(const struct net* netns);
extern void cp_release(struct oo_cplane_handle* cp);

extern int
cp_acquire_from_priv_if_server(struct ci_private_s* priv,
                               struct oo_cplane_handle** out);

struct cicppl_instance;
extern int /* rc */
cicpplos_ctor(struct cicppl_instance* cppl);
extern void
cicpplos_dtor(struct cicppl_instance *cppl);

extern int oo_cp_wait_for_server_rsop(struct ci_private_s*, void* arg);
extern int oo_cp_link_rsop(struct ci_private_s*, void* arg);
extern int oo_cp_ready(struct ci_private_s*, void* version);
extern int oo_cp_check_version(struct ci_private_s*, void* arg);


extern int oo_cp_get_server_pid(struct oo_cplane_handle* cp);
extern int oo_cp_print_rsop(struct ci_private_s *priv, void *arg);
extern int oo_cp_llap_change_notify_all(struct oo_cplane_handle* main_cp);
extern int oo_cp_oof_sync_start(struct oo_cplane_handle* cp);
extern int oo_cp_oof_sync_wait(struct oo_cplane_handle* cp);
extern int cp_sync_tables_start(struct oo_cplane_handle* cp,
                                cp_version_t* ver_out);
extern int cp_sync_tables_wait(struct oo_cplane_handle* cp,
                               cp_version_t old_ver);

#endif /* __ONLOAD_CPLANE_DRIVER_H__ */
