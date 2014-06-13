/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
 * This file provides internal API for license challenge.
 *
 * Copyright 2013:      Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#ifndef __EFRM_LICENSING_H__
#define __EFRM_LICENSING_H__

/* **********************************************
** Warning: these values are well-known.
*/

#define EFRM_LICENSE_CHALLENGE_CHALLENGE_LEN (64)
#define EFRM_LICENSE_CHALLENGE_SIGNATURE_LEN (64)

/* ********************************************** */

/* struct passed into efrm_license_challenge(). */
struct efrm_license_challenge_s {
  /* IN: Single feature to challenge. Select a well known feature id. */
  uint32_t  feature;

  /* OUT: U32 repr of standard Linux time. */
  uint32_t  expiry;

  /* IN: challenge data */
  uint8_t challenge[EFRM_LICENSE_CHALLENGE_CHALLENGE_LEN];

  /* OUT: signature (on success). */
  uint8_t signature[EFRM_LICENSE_CHALLENGE_SIGNATURE_LEN];
};

struct efrm_resource;

/* (licensing.c)
 * Check if the given feature is licensed in the NIC and respond to the
 * challenge. */
extern int efrm_license_challenge(struct efrm_resource *rs, 
                                  struct efrm_license_challenge_s *s);

#endif /* __EFRM_LICENSING_H__ */

