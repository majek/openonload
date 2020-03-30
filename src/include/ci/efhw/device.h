/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __CI_EFHW_DEVICE_H__
#define __CI_EFHW_DEVICE_H__

enum efhw_arch {
	EFHW_ARCH_FALCON,
	EFHW_ARCH_EF10,
};

/*----------------------------------------------------------------------------
 *
 * NIC type
 *
 *---------------------------------------------------------------------------*/

enum efhw_function {
	EFHW_FUNCTION_PF,
	EFHW_FUNCTION_VF,
};

struct efhw_device_type {
	int  arch;            /* enum efhw_arch */
	char variant;         /* 'A', 'B', ... */
	int  revision;        /* 0, 1, ... */
	int  function;        /* enum efhw_function */
};

#endif
