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
** <L5_PRIVATE L5_SOURCE>
** \author  sasha
**  \brief  Operations for signal interception
**   \date  2011/09/08
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <ci/internal/ip_signal.h>
#include <ci/internal/ip_log.h>


/*! \TODO - remove (useful for debugging though) */
#define LOG_SIG(x)

/*! Signal handlers storage.  Indexed by signum-1.
 * Read by UL, written by kernel only. */
struct oo_sigaction citp_signal_data[NSIG];




/*! Run a signal handler
** \param  signum   Signal number
** \param  info     Saved info for sa_sigaction handler
** \param  context  Saved context for sa_sigaction handler
** \return sa_restart flag value
*/
static int
citp_signal_run_app_handler(int sig, siginfo_t *info, void *context)
{
  struct oo_sigaction *p_data = &citp_signal_data[sig-1];
  struct oo_sigaction act;
  ci_int32 type1, type2;
  int ret;

  do {
    type1 = p_data->type;
    act = *p_data;
    type2 = p_data->type;
  } while( type1 != type2 ||
           (type1 & OO_SIGHANGLER_TYPE_MASK) == OO_SIGHANGLER_BUSY );

  /* When the signal was delivered and set pending, it was intercepted.
   * Now it is not.
   * It is possible if, for example, user-provided handler is replaced by
   * SIG_DFL for SIGABORT.
   *
   * We just run old handler in this case, so we drop
   * OO_SIGHANGLER_IGN_BIT.
   */
  act.type &= OO_SIGHANGLER_TYPE_MASK;

  ret = act.flags & SA_RESTART;
  LOG_SIG(log("%s: signal %d type %d run handler %p flags %x",
              __FUNCTION__, sig, act.type, CI_USER_PTR_GET(act.handler),
              act.flags));

  if( act.type != OO_SIGHANGLER_USER || (act.flags & SA_SIGINFO) ) {
    /* All non-user hadnlers are installed with SA_SIGINFO;
     * act.flags is used to store user value in this case */
    sa_sigaction_t handler = CI_USER_PTR_GET(act.handler);
    ci_assert(handler);
    ci_assert(info);
    ci_assert(context);
    ci_assert_nequal(handler, citp_signal_intercept_3);
    (*handler)(sig, info, context);
  } else {
    __sighandler_t handler = CI_USER_PTR_GET(act.handler);
    ci_assert_nequal(handler, citp_signal_intercept_1);
    ci_assert(handler);
    (*handler)(sig);
  }
  LOG_SIG(log("%s: returned from handler for signal %d: ret=%x", __FUNCTION__,
              sig, ret));

  return ret;
}


/*! Run any pending signal handlers
** \param  our_info  Thread-specific context for current thread
*/
void citp_signal_run_pending(citp_signal_info *our_info)
{
  /* preserve errno across calls to this function, as it's often
     called at error time as a result of EXIT_LIB */
  int old_errno = errno;

  LOG_SIG(log("%s: start", __FUNCTION__));
  ci_wmb();
  while (our_info->run_pending) {
    int signum;
    
    our_info->run_pending = 0;
    ci_wmb();
    for( signum = 1; signum < NSIG + 1; signum++ ) {
      if (our_info->signals[signum].pending) {
        siginfo_t *saved_info = our_info->signals[signum].saved_info;
        void *saved_context = our_info->signals[signum].saved_context;
        ci_mb();
        our_info->signals[signum].pending = 0;
        our_info->need_restart =
            !!citp_signal_run_app_handler(signum, saved_info, saved_context);
      }
    }
  }
  LOG_SIG(log("%s: end", __FUNCTION__));
  errno = old_errno;
}


/*! Mark a signal as pending
** \param  signum   Signal number
** \param  info     Saved info for sa_sigaction handler
** \param  context  Saved context for sa_sigaction handler
** \param  our_info Our signal info
*/
ci_inline void citp_signal_set_pending(int signum, siginfo_t *info,
                                       void *context,
                                       citp_signal_info *our_info) {
  if (!our_info->signals[signum].pending) {
    LOG_SIG(log("%s: signal %d pending", __FUNCTION__, signum));
    our_info->signals[signum].saved_info = info;
    our_info->signals[signum].saved_context = context;
    ci_wmb();
    our_info->signals[signum].pending = 1;
    ci_wmb();
    our_info->run_pending = 1;
  } else {
    LOG_SIG(log("%s: ignoring already pending signal %d", __FUNCTION__,
                signum));
  }
}

/*! Run signal handler immediatedly, just now.
** \param  signum   Signal number
** \param  info     Saved info for sa_sigaction handler
** \param  context  Saved context for sa_sigaction handler
** \param  our_info Our signal info
*/
ci_inline void citp_signal_run_now(int signum, siginfo_t *info,
                                   void *context,
                                   citp_signal_info *our_info)
{
  int need_restart;

  LOG_SIG(log("%s: SIGNAL %d - run immediately", __FUNCTION__, signum));

  /* Try to keep order: old signals first, and need_restart is from the
   * last one */
  if (our_info && our_info->run_pending)
    citp_signal_run_pending(our_info);

  need_restart = citp_signal_run_app_handler(signum, info, context);

  /* Set need_restart flag in accordance with sa_restart.
   * The last signal wins, so we set need_restart to 1 if necessary.
   */
  if (our_info) {
    LOG_SIG(log("%s: SIGNAL %d - set need restart flag to %d", __FUNCTION__,
                signum, need_restart));
    our_info->need_restart = !!need_restart;
  }
}

/*! Handler we register for sigaction() sa_sigaction interception
** \param  signum   Signal number
** \param  info     Additional information passed in by the kernel
** \param  context  Context passed in by the kernel
*/
void citp_signal_intercept_3(int signum, siginfo_t *info, void *context)
{
  citp_signal_info *our_info = citp_signal_get_specific_inited();
  /* Note: our thread-specific data is initialised on the way in to the our
   * library if necessary, so if our_info is NULL, we can assume that this
   * thread is not currently running inside the library.  (This can happen
   * if a signal is delivered to a thread which has been created after the
   * intercept handler has been installed, but before that thread uses any
   * of the interposing library functions.)
   */
  if (our_info && our_info->inside_lib)
    citp_signal_set_pending(signum, info, context, our_info);
  else
    citp_signal_run_now(signum, info, context, our_info);
}

/*! Handler we register for sigaction() sa_sigaction interception
** \param  signum   Signal number
*/
void citp_signal_intercept_1(int signum)
{
  citp_signal_intercept_3(signum, NULL, NULL);
}


/* SIG_DFL simulator for signals like SIGINT, SIGTERM: it is postponed
 * properly to safe shared stacks. */
static void citp_signal_terminate(int signum, siginfo_t *info, void *context)
{
  int fd;

  /* get any Onload fd to call ioctl */
  ef_onload_driver_open(&fd, 1);

  /* Die now:
   * _exit sets incorrect status in waitpid(), so we should try to exit via
   * signal.  Use _exit() if there is no other way. */
  if( fd >= 0 )
    oo_resource_op(fd, OO_IOC_DIE_SIGNAL, &signum);
  else
    _exit(128 + signum);
}

/*! sa_restorer used by libc (SA_SIGINFO case!) */
static void *citp_signal_sarestorer;
static int citp_signal_sarestorer_inited = 0;

#ifndef SA_RESTORER
/* kernel+libc keep it private, but we need it */
#define SA_RESTORER 0x04000000
#endif
/* Get sa_restorer which is set by libc. */
void *citp_signal_sarestorer_get(void)
{
  int sig = SIGINT;
  struct sigaction act;
  int rc;

  if( citp_signal_sarestorer_inited )
    return citp_signal_sarestorer;

  LOG_SIG(log("%s: citp_signal_intercept_1=%p, citp_signal_intercept_3=%p, "
              "citp_signal_terminate=%p", __func__,
              citp_signal_intercept_1, citp_signal_intercept_3,
              citp_signal_terminate));
  for( sig = 1; sig < _NSIG; sig++ ) {
    LOG_SIG(log("find sa_restorer via signal %d", sig));
    /* If the handler was already set by libc, we get sa_restorer just now */
    rc = sigaction(sig, NULL, &act);
    if( rc != 0 )
      continue;
    if( act.sa_restorer != NULL && (act.sa_flags & SA_SIGINFO) ) {
      citp_signal_sarestorer = act.sa_restorer;
      LOG_SIG(ci_log("%s: initially citp_signal_sarestorer=%p", __func__,
                     citp_signal_sarestorer));
      citp_signal_sarestorer_inited = 1;
      return citp_signal_sarestorer;
    }

    /* Do not set SA_SIGINFO for user handlers! */
    if( act.sa_handler != SIG_IGN && act.sa_handler != SIG_DFL )
      continue;

    LOG_SIG(ci_log("%s: non-siginfo sa_restorer=%p", __func__,
                   act.sa_restorer));
    /* Let's go via libc and set sa_restorer */
    act.sa_flags |= SA_SIGINFO;
    rc = sigaction(sig, &act, NULL);
    if( rc != 0 )
      continue;
    /* And now we get sa_restorer as it was set by libc! */
    rc = sigaction(sig, NULL, &act);
    if( rc == 0 ) {
      citp_signal_sarestorer_inited = 1;
      LOG_SIG(ci_log("%s: set/get flags %x citp_signal_sarestorer=%p",
                     __func__, act.sa_flags, act.sa_restorer));
      if( !(act.sa_flags & SA_RESTORER) )
        return NULL;
      citp_signal_sarestorer = act.sa_restorer;
      return citp_signal_sarestorer;
    }
  }

  return NULL;
}

/*! Our signal handlers for various interception types */
sa_sigaction_t citp_signal_handlers[OO_SIGHANGLER_DFL_MAX+1] = {
citp_signal_terminate  /*OO_SIGHANGLER_TERM*/,
NULL, NULL /*OO_SIGHANGLER_STOP, OO_SIGHANGLER_CORE - TODO */
};


/*! \cidoxg_end */
