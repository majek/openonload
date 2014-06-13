/*
** Copyright 2005-2012  Solarflare Communications Inc.
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

#ifndef __CI_TOOLS_BUFRANGE_H__
#define __CI_TOOLS_BUFRANGE_H__


typedef struct {
  char*  start;
  char*  ptr;
  char*  end;
} ci_bufrange;


ci_inline void ci_bufrange_init(ci_bufrange* mb, void* b, int size)
{ mb->end = (mb->ptr = mb->start = (char*) b) + size; }

ci_inline void ci_bufrange_init_empty(ci_bufrange* mb, void* b)
{ mb->start = mb->ptr = mb->end = (char*) b; }

/* NB. Maintains alignment of <ptr>. */
ci_inline void ci_bufrange_empty(ci_bufrange* mb)
{ mb->start = mb->end = mb->ptr; }


ci_inline int ci_bufrange_gone(ci_bufrange* mb)
{ return (int)(mb->ptr - mb->start); }

ci_inline int ci_bufrange_left(ci_bufrange* mb)
{ return (int)(mb->end - mb->ptr); }

ci_inline int ci_bufrange_size(ci_bufrange* mb)
{ return (int)(mb->end - mb->start); }


ci_inline void ci_bufrange_advance(ci_bufrange* mb, int n)
{ mb->ptr += n; }

ci_inline void ci_bufrange_giveback(ci_bufrange* mb, int n)
{ mb->ptr -= n; }


#if CI_INCLUDE_ASSERT_VALID
  extern void ci_bufrange_assert_valid(ci_bufrange*);
#else
# define ci_bufrange_assert_valid(br)
#endif


#endif  /* __CI_TOOLS_BUFRANGE_H__ */

/*! \cidoxg_end */
