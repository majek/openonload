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
** <L5_PRIVATE L5_HEADER >
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_STACKS_H__
#define __CI_TOOLS_STACKS_H__


/*! Comment? */
typedef struct {
  int*  stack_base;
  int*  stack_top;
  int*  stack_ptr;
} ci_int_stack_t;

typedef ci_int_stack_t ci_int_stack;


/*! Comment? */
typedef struct {
  void**  stack_base;
  void**  stack_top;
  void**  stack_ptr;
} ci_ptr_stack_t;

typedef ci_ptr_stack_t ci_ptr_stack;


#endif  /* __CI_TOOLS_STACKS_H__ */

/*! \cidoxg_end */
