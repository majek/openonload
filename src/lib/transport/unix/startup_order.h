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


/* First of all, allow to use ci_log */
STARTUP_ITEM(CITP_INIT_LOGGING, citp_setup_logging_early)

/* resolve ci_sys_* symbols: now we fake-hanlde the intercepted calls.
 * The only calls we really handle here are exec*() */
STARTUP_ITEM(CITP_INIT_SYSCALLS, citp_syscall_init)

/* We can't easily fake-fandle execl*() functions, so we should prepare
 * to handle them properly ASAP. */
STARTUP_ITEM(CITP_INIT_ENVIRON, citp_environ_init)

/* read efabcfg database */
STARTUP_ITEM(CITP_INIT_CFG, citp_cfg_init)
/* init CITP_OPTS, including CITP_OPTS.log_level:
 * logging fully-functional now. */
STARTUP_ITEM(CITP_INIT_TRANSPORT, citp_transport_init)
/* onload extension library */
STARTUP_ITEM(CITP_INIT_ONLOADEXT, oo_extensions_init)
/* fork hooks should be ready (but disabled) before fdtable and netif */
STARTUP_ITEM(CITP_INIT_FORK_HOOKS, ci_setup_fork)
/* fdtable */
STARTUP_ITEM(CITP_INIT_FDTABLE, citp_fdtable_ctor)

#ifdef ONLOAD_OFE
STARTUP_ITEM(CITP_INIT_OFE, citp_ofe_ctor)
#endif

/* init citp_netif_info */
STARTUP_ITEM(CITP_INIT_NETIF, citp_netif_init_ctor)

/* handle TCP and UDP protocols: now we are going to properly handle all
 * the intercepted functions. */
STARTUP_ITEM(CITP_INIT_PROTO, citp_transport_register)
