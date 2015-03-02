/*
** Copyright 2005-2015  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

/****************************************************************************
 * Copyright 2013-2015: Solarflare Communications Inc,
 *                      7505 Irvine Center Drive, Suite 100
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
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

#ifndef __EFAB_CLUSTER_PROTOCOL_H__
#define __EFAB_CLUSTER_PROTOCOL_H__

/* Internal interfaces, so exclude from doxygen documentation */
/*! \cond internal */

/* WARNING!!! This file is not part of the public ef_vi API and should
 * not be included by any applications. */

/* src/tool/solar_clusterd will need updating if you update any of the
 * definitions below
 */

/*
 *  \brief  Cluster Daemon Protocol
 *   \date  2013/11/28
 */


#define CLUSTERD_PROTOCOL_VERSION 1

/*
 * Default file names and location.
 * For example, /tmp/solar_clusterd-root/solar_clusterd.log
 */
#define DEFAULT_CLUSTERD_DIR       "/tmp/solar_clusterd-"
#define DEFAULT_CLUSTERD_SOCK_NAME "solar_clusterd"

#define MSGLEN_MAX 255

enum cluster_req {
  CLUSTERD_VERSION_REQ,
  CLUSTERD_VERSION_RESP,
  CLUSTERD_ALLOC_CLUSTER_REQ,
  CLUSTERD_ALLOC_CLUSTER_RESP,
};

enum cluster_result_code {
  CLUSTERD_ERR_SUCCESS,
  CLUSTERD_ERR_FAIL,
  CLUSTERD_ERR_BAD_REQUEST,
};

/*! \endcond internal */

#endif /* __EFAB_CLUSTER_PROTOCOL_H__ */
