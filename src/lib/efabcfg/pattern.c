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
** \author  ds
**  \brief  Pattern matching function for efabcfg lib
**   \date  2005/11/18
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/


/*****************************************************************************
 *                                                                           *
 *          Headers                                                          *
 *          =======							     *
 *                                                                           *
 *****************************************************************************/

/* warning: */
/*#include <stdlib.h>*/ /* don't include in linux - name clashes */
/*#include <wchar.h>*/ /* don't include this on windows - off_t duplication */

#include <ci/internal/efabcfg.h> /* also sets USE_TOMBLOWER */

/*****************************************************************************
 *                                                                           *
 *          Configuration                                                    *
 *          =============						     *
 *                                                                           *
 *****************************************************************************/

#ifdef USE_TOMBLOWER

#ifdef MAX_PATH
#define PAT_PATH_MAXBYTES MAX_PATH
#else
#define PAT_PATH_MAXBYTES 256
#endif

#endif /* USE_TOMBLOWER */

/*****************************************************************************
 *                                                                           *
 *          Debugging                                                        *
 *          =========							     *
 *                                                                           *
 *****************************************************************************/

#ifdef IGNORE
#undef IGNORE
#endif

#ifdef DO
#undef DO
#endif

#define IGNORE(_x)
#define DO(_x) _x

/* #define DEBUGMATCH DO */

#ifndef DEBUGMATCH
#define DEBUGMATCH IGNORE
#endif

/*****************************************************************************
 *                                                                           *
 *          Match simple pattern                                             *
 *          ====================					     *
 *                                                                           *
 *****************************************************************************/

#define find_substring(string, substr) strstr(string, substr)

/*! Find pattern denoted by [pattern, match_type] in str
 *  \TODO: for $ check we should do a backward substring find not forward
 */
static int
pattern_matches(const char *pattern, const char *str, ci_uint8 match_type)
{   char *match = find_substring(str, pattern);
    int ok = (match != NULL);
    if (ok)
    {   if (0 != (match_type & CICFG_MATCH_START) && match != str)
	    ok = 0;
        if (0 != (match_type & CICFG_MATCH_END) &&
	    match + strlen(pattern) != str + strlen(str))
	    ok = 0;
    }
    DEBUGMATCH(ci_log("app '%s' %s %s'%s'%s (match is ...'%s')",
		      str, ok?"matches": "does not match",
		      0 != (match_type & CICFG_MATCH_START)? "^":"",
		      pattern,
		      0 != (match_type & CICFG_MATCH_END)? "$":"",
		      match==NULL?"<NO MATCH>": match);)
    return ok;
}




extern int
ci_cfg_pattern_matches(const char *pattern, const char *str,
                       ci_uint8 match_type)
{
#ifdef USE_TOMBLOWER
  static char lower_pattern[PAT_PATH_MAXBYTES+MB_LEN_MAX+1];
  static char lower_str[PAT_PATH_MAXBYTES+MB_LEN_MAX+1];
  
  if (tomblower(&lower_pattern[0], sizeof(lower_pattern), pattern) >= 0 &&
      tomblower(&lower_str[0], sizeof(lower_str), str) >= 0)
  {
    return pattern_matches(&lower_pattern[0], &lower_str[0], match_type);
  } else
  {
    ci_log("config: application name or pattern too long, app '%s' pat '%s'",
           str, pattern);
    return 0;
  }
#else
  return pattern_matches(pattern, str, match_type);
#endif
}

