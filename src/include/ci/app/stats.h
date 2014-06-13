/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
** <L5_PRIVATE L5_HEADER>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_app */

#ifndef __CI_APP_STATS_H__
#define __CI_APP_STATS_H__


/*! Comment? */
extern void ci_iarray_mean_and_limits(const int* start, const int* end,
			       int* mean_out, int* min_out, int* max_out);

/*! Comment? */
extern void ci_iarray_variance(const int* start, const int* end,
				int mean, ci_int64* variance_out);

/*! Comment? */
extern int ci_qsort_compare_int(const void*, const void*);

/*! Comment? */
extern void ci_iarray_median(const int* s, const int* e, int* median_out);

/*! Comment? */
extern void ci_iarray_mode(const int* start, const int* end, int* mode_out);


#if CI_INCLUDE_ASSERT_VALID
	/*! Comment? */
  extern void ci_iarray_assert_valid(const int* start, const int* end);
	/*! Comment? */
  extern void ci_iarray_assert_sorted(const int* start, const int* end);
#else
# define ci_iarray_assert_valid(s,e)
# define ci_iarray_assert_sorted(s,e)
#endif


#endif  /* __CI_APP_STATS_H__ */

/*! \cidoxg_end */
