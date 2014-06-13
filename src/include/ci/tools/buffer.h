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
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_BUFFER_H__
#define __CI_TOOLS_BUFFER_H__


typedef struct {
  char*  ptr;
  char*  end;
} ci_buffer;


ci_inline void ci_buffer_init(ci_buffer* mb, const void* b, int size)
{ mb->end = (mb->ptr = (char*) b) + size; }

ci_inline void ci_buffer_init2(ci_buffer* mb, const void* from, const void* to)
{ mb->ptr = (char*) from; mb->end = (char*) to; }


/* NB. Maintains alignment of <ptr>. */
ci_inline void ci_buffer_empty(ci_buffer* mb)
{ mb->end = mb->ptr; }


ci_inline int ci_buffer_is_empty(ci_buffer* mb)
{ return mb->ptr == mb->end; }

ci_inline int ci_buffer_not_empty(ci_buffer* mb)
{ return mb->ptr != mb->end; }

ci_inline int ci_buffer_size(ci_buffer* mb)
{ return (int)(mb->end - mb->ptr); }

ci_inline int ci_buffer_left(ci_buffer* mb)
{ return (int)(mb->end - mb->ptr); }


ci_inline void ci_buffer_advance(ci_buffer* mb, int n)
{ mb->ptr += n; }


#if CI_INCLUDE_ASSERT_VALID
  extern void ci_buffer_assert_valid(ci_buffer*);
#else
# define ci_buffer_assert_valid(b)
#endif


#endif  /* __CI_TOOLS_BUFFER_H__ */

/*! \cidoxg_end */
