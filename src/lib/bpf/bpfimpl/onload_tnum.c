/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include "bpfimpl_kernel_config.h"

#ifndef __KERNEL__
# include <ci/kcompat.h>
# pragma GCC diagnostic ignored "-Wformat"
#endif /* !__KERNEL__ */

#include "bpf_disable_exports.h"
#include "kernel/tnum.c"
