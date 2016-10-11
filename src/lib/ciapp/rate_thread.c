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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Thread function to measure rate of change.
**   \date  2004/12/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */
#include <ci/app.h>

void* ci_rate_thread_fn(void* p_ci_rate_thread_cfg)
{
  ci_rate_thread_cfg* cfg = (ci_rate_thread_cfg*) p_ci_rate_thread_cfg;
  struct timeval t_now, t_prev;
  unsigned val_now = 0, val_prev = 0, ms;

  gettimeofday(&t_prev, 0);
  if( cfg->pval )  val_prev = *cfg->pval;

  while( 1 ) {
    ci_sleep(cfg->interval_msec);
    if( cfg->stop )  break;

    gettimeofday(&t_now, 0);
    if( cfg->pval )  val_now = *cfg->pval;

    ms = (t_now.tv_sec - t_prev.tv_sec) * 1000;
    ms += (t_now.tv_usec - t_prev.tv_usec) / 1000;

    cfg->action(cfg, val_now, val_prev, ms);

    t_prev = t_now;
    val_prev = val_now;
  }

  return 0;
}

/*! \cidoxg_end */
