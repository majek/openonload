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

#ifndef WIRE_ORDER_H
#define WIRE_ORDER_H

/* Default port the server runs on */
#define DEFAULT_PORT              2048

/* Default size of the listen queue */
#define DEFAULT_LISTEN_BACKLOG    100

/* Default number of events to request in onload_ordered_epoll_wait() */
#define DEFAULT_MAX_EPOLL_EVENTS  10

/* Flags for configuring the server setup. */
#define WIRE_ORDER_CFG_FLAGS_UDP 1

#define WIRE_ORDER_CFG_LEN 8
#define WIRE_ORDER_CFG_FLAGS_OFST 0
#define WIRE_ORDER_CFG_N_SOCKS_OFST 4

#endif /* WIRE_ORDER_H */
