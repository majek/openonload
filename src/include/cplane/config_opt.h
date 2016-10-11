/*
** Copyright 2005-2016  Solarflare Communications Inc.
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

/* Compile-time cplane configuration */
#ifndef __CPLANE_CONFIG_OPT_H__
#define __CPLANE_CONFIG_OPT_H__

/* Maximum number of networks interfaces that can be registered with the
 * cplane driver.
 */
#define CPLANE_MAX_REGISTER_INTERFACES 32

/* Teaming/bonding support */
#define CPLANE_TEAMING 1

/* Number of deferred MAC-requiring packets */
#define CPLANE_PROT_PKTBUF_COUNT 128

/* Maximum length of a network interface name */
#define CPLANE_LLAP_NAME_MAX 16

#endif /* __CPLANE_CONFIG_OPT_H__ */
