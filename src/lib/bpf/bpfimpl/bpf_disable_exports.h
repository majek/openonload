/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef BPFIMPL_DISABLE_EXPORTS_H
#define BPFIMPL_DISABLE_EXPORTS_H

/* On more recent kernels enables the use of __DISABLE_EXPORTS to disable
 * exports, however, there's a gap between kernels introducing symbols that
 * we don't want to duplicate and the introduction of __DISABLE_EXPORTS, so
 * we instead replace export.h with our version for files that would otherwise
 * export duplicate symbols.
 */

/* Avoid inclusion of real export.h */
#define _LINUX_EXPORT_H

#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)

/* This is defined in the real export.h and is used by <linux/netlink.h> in
 * inline functions to create a netlink socket and perform a dump.  This
 * isn't used by the bpf functionality, so we can just stub it.
 */
#define THIS_MODULE NULL

#endif /* BPFIMPL_DISABLE_EXPORTS_H */
