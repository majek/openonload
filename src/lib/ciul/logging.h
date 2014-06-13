/*
** Copyright 2005-2012  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  stg
**  \brief  Logging functions.
**   \date  2007/05/18
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_ul */
#ifndef __EF_VI_LOGGING_H__
#define __EF_VI_LOGGING_H__


#if !defined(NDEBUG) && !defined(__KERNEL__)
extern int ef_log_level;
#endif
extern void ef_log(const char* fmt, ...);

#ifdef __KERNEL__
# define EF_VI_LOG(l,x)
#else
# define EF_VI_LOG(l,x)	do{ if(unlikely(ef_log_level>=(l))) {x;} }while(0)
#endif

#ifdef NDEBUG
# define LOG(x)
# define LOGV(x)
# define LOGVV(x)
# define LOGVVV(x)
#else
# define LOG(x)         do { x; } while(0)
# define LOGV(x)	EF_VI_LOG(1,x)
# define LOGVV(x)	EF_VI_LOG(2,x)
# define LOGVVV(x)	EF_VI_LOG(3,x)
#endif


#endif  /* __EF_VI_LOGGING_H__ */
