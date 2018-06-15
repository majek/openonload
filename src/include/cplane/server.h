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

/* To make a string from a macro number (such as CI_CFG_MAX_HWPORTS), use
 * STRINGIFY(CI_CFG_MAX_HWPORTS). */
#define OO_STRINGIFY1(x) #x
#define OO_STRINGIFY(x) OO_STRINGIFY1(x)

/* Mask for forward request id, as used between server and module. */
#define CP_FWD_FLAG_REQ      0x80000000
#define CP_FWD_FLAG_REQ_MASK 0x03ffffff

/* When the server receives this signal, it dumps its internal state using
 * ci_log(), which by default goes to syslog.  The OO_IOC_CP_PRINT ioctl
 * causes this signal to be sent to the current server.  This is used by
 * onload_mibdump. */
#define CP_SERVER_PRINT_STATE_SIGNAL  SIGUSR1


#include <cplane/mib.h> /* for cp_fwd_key */
static inline struct cp_fwd_key* cp_siginfo2key(siginfo_t* info)
{
/* Linux sometimes overwrites ._kill._pid field when sending a signal. */
#define CP_SIGINFO_REQ_OFFSET 64
  CI_BUILD_ASSERT(sizeof(info->_sifields) >=
                  sizeof(struct cp_fwd_key) + CP_SIGINFO_REQ_OFFSET);
  return (void*)((ci_uintptr_t)&info->_sifields + CP_SIGINFO_REQ_OFFSET);
}

#endif /* defined(__ONLOAD_CPLANE_SERVER_H__) */
