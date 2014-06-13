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
** \author  kjm
**  \brief  State for stack<->socket mapping configuration
**   \date  2010/12/12
**    \cop  (c) Solarflare Communications Ltd.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_UL_STACKNAME_H__
#define __ONLOAD_UL_STACKNAME_H__

#include <ci/internal/tls.h>
#include <onload/extensions.h>


struct oo_stackname_state {
  enum onload_stackname_who who;
  enum onload_stackname_scope context;
  char stackname[CI_CFG_STACK_NAME_LEN];
  char scoped_stackname[CI_CFG_STACK_NAME_LEN];

  /* Used to indicate that global state has changed since cached
   * per-thread state was updated 
   */ 
  unsigned sequence; 
};


extern void oo_stackname_init(void) CI_HF;

extern void oo_stackname_get(char **stackname) CI_HF;

extern void oo_stackname_thread_init(struct oo_stackname_state*) CI_HF;

extern void 
oo_stackname_update(struct oo_stackname_state *cache) CI_HF;


#endif /* __ONLOAD_UL_STACKNAME_H__ */
