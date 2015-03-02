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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Support for user-level poll() and select().
**   \date  2009/02/22
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __UL_POLL_H__
#define __UL_POLL_H__

#if CI_CFG_USERSPACE_SELECT

#define OO_POLL_MAX_KFDS   1024

#define OO_POLL_MAX_OSP    16

#define KEEP_POLLING(what, now, start)                                  \
  (what && (((now) = ci_frc64_get()) - (start) < citp.spin_cycles))


struct oo_ul_poll_state {
  /* Timestamp for the beginning of the current poll.  Used to avoid doing
   * ci_netif_poll() on stacks too frequently.
   */
  ci_uint64             this_poll_frc;

  /* The argument to poll(). */
  struct pollfd*__restrict__ pfds;

  /* Number of entries in [pfds] with revents set. */
  int                   n_ul_ready;

  /* Number of user-level sockets in [pfds]. */
  int                   n_ul_fds;

  /* Number of entries in [kfds] and [kfd_map]. */
  int                   nkfds;

  /* Maps entry number in [kfds] onto entry number in [pfds]. */
  int                   kfd_map[OO_POLL_MAX_KFDS];

  /* Use this to do sys_poll() on non-onload fds. */
  struct pollfd         kfds[OO_POLL_MAX_KFDS];

  /* Should it spin */
  unsigned              ul_poll_spin;

#if CI_CFG_SPIN_STATS
  /* Have we incremented statistics for this spin round? */
  int stat_incremented;
#endif
};

#endif /* CI_CFG_USERSPACE_SELECT */

#endif  /* __UL_POLL_H__ */
