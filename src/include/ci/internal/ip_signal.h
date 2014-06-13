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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  mjs
**  \brief  Decls needed for async signal management.
**   \date  2005/03/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */
#ifndef __CI_INTERNAL_IP_SIGNAL_H__
#define __CI_INTERNAL_IP_SIGNAL_H__

#include <onload/signals.h>
#include <onload/ul/per_thread.h>
#include <ci/internal/tls.h>


typedef struct oo_sig_thread_state citp_signal_info;


extern void citp_signal_run_pending(citp_signal_info* info) CI_HF;

ci_inline citp_signal_info *citp_signal_get_specific_inited(void)
{
  struct oo_per_thread* pt = __oo_per_thread_get();
  return &pt->sig;
}


#endif  /* __CI_INTERNAL_IP_SIGNAL_H__ */
/*! \cidoxg_end */
