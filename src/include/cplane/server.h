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

/* This header describes the interface between the open source parts
 * of Onload and the binary-only control plane server.
 *
 * We use an md5sum over certain headers to ensure that userland and
 * kernel drivers are built against a compatible interface. The
 * control plane server and its clients will verify this hash against
 * the kernel module and refuse to start if there is a version
 * mismatch.
 *
 * Users should therefore not modify these headers because the
 * supplied control plane server will refuse to operate with the
 * resulting module.
 */

#ifndef __ONLOAD_CPLANE_SERVER_H__
#define __ONLOAD_CPLANE_SERVER_H__

/* onload_cp_server can be spawned by the kernel, so the kernel needs to know
 * some things about the command line arguments that the server takes.  We
 * define such things here. */
#define CPLANE_SERVER_NS_CMDLINE_OPT "network-namespace-file"
#define CPLANE_SERVER_DAEMONISE_CMDLINE_OPT "daemonise"
#define CPLANE_SERVER_HWPORT_NUM_OPT "hwport-max"
#define CPLANE_SERVER_IPADDR_NUM_OPT "ipif-max"
#define CPLANE_SERVER_FORCE_BONDING_NETLINK "force-bonding-netlink"
#define CPLANE_SERVER_BOOTSTRAP "bootstrap"
#define CPLANE_SERVER_NO_IPV6 "no-ipv6"
#define CPLANE_SERVER_UID "uid"
#define CPLANE_SERVER_GID "gid"

/* To make a string from a macro number (such as CI_CFG_MAX_HWPORTS), use
 * STRINGIFY(CI_CFG_MAX_HWPORTS). */
#define OO_STRINGIFY1(x) #x
#define OO_STRINGIFY(x) OO_STRINGIFY1(x)

/* Mask for forward request id, as used between server and module. */
#define CP_FWD_FLAG_REQ_MASK 0x03ffffff


#include <cplane/mib.h> /* for cp_fwd_key */
/* message from in-kernel cplane helper to the cplane server */
struct cp_helper_msg {
  struct cp_fwd_key key;
  ci_uint32 id;
};

#endif /* defined(__ONLOAD_CPLANE_SERVER_H__) */
