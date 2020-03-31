/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  kjm
**  \brief  Handle thread-local storage across different gcc versions
**   \date  2010/12/10
**    \cop  (c) Solarflare Communications Ltd. 
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */
#ifndef __CI_INTERNAL_TLS_H__
#define __CI_INTERNAL_TLS_H__

/* __thread keyword exists in gcc >=3.3  */
#if defined (__GNUC__) && \
    ((__GNUC__ == 3 && __GNUC_MINOR__ >= 3) || __GNUC__ > 3)
/* have __thread keyword */
#define HAVE_CC__THREAD 1
#else
/* use pthread_getspecific() and friends */
#undef HAVE_CC__THREAD
#endif

#ifndef HAVE_CC__THREAD
/*! Any invalid pthread key, to force ENTER_LIB() in the interposing library
**  to call citp_signal_init_specific() in the case where the library is
**  entered before _init() has been called, which happens occasionally due to
**  dynamic linker badness.  (Note that for both LinuxThreads and NPTL,
**  pthread_key_t is an unsigned int, and the valid range of keys is 0..1023.)
*/
#define INVALID_PTHREAD_KEY_ID 0xffffffff
#endif


#endif  /* __CI_INTERNAL_TLS_H__ */
/*! \cidoxg_end */
