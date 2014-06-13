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
** \author  djr
**  \brief  Fixed width, cross-platform, timeval
**   \date  2008/08/14
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */
#ifndef __CI_TOOLS_TIMEVAL_H__
#define __CI_TOOLS_TIMEVAL_H__


/* Fixed width type equivalent of struct timeval */
typedef struct ci_timeval_s {
  ci_int32 tv_sec;
  ci_int32 tv_usec;
} ci_timeval_t;


#endif  /* __CI_TOOLS_TIMEVAL_H__ */
/*! \cidoxg_end */
