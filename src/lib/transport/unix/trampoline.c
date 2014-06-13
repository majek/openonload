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

#include <internal.h>

#if defined(__linux__) && !defined(NO_TRAMPOLINE)


# include <onload/common.h>
# include <ci/internal/trampoline.h>
# include <asm/unistd.h>
#include <onload/ul/tcp_helper.h>
#include <onload/signals.h>


/* This is the code that receives the trampoline.  In certain cirumstances 
 * (such as when it sees a close on one of our FDs) the kernel (ie. our module)
 * assumes that for some reason the interposing library didn't catch it.  The
 * module munges the return address to "trampoline_entry", and returns from
 * syscall, thus jumping back into here.  (The module knows about our
 * trampoline entry point because we pass it down in tcp_helper_alloc).
 *
 *  There are currently two cases when we receive a trampoline:
 *  1) When the module detects a close system-call that wasn't intercepted as
 *     we'd normally hope to.
 *  2) An internal module error (i.e. assert fail).  Rather than kernel panic,
 *     unwinds to here, to give more meaningful and useful diagnostics.
 *
 * Note: this entry point itself is in some assembler at the bottom of this
 * function -- the handler needs to be a bit of assembler because the calling
 * covention/stack is all screwy at this point.
 *
 * Note 2: the handler needs to take care not to set errno, and to return errs
 * as -ve return values.  This is because the handler is emulating the system
 * call, not the library call.
 */
long
ci_trampoline_handler(unsigned opcode, unsigned data) {
  int rc = 0;
  int saved_errno = errno;

  switch (opcode) {
    case CI_TRAMP_OPCODE_ERROR:
      __ci_fail ("*** Deliberate user-level fail on syscall exit: 0x%x", data);
      while (1) sleep (1000);  /* Code never gets here, but just in case! */

    case CI_TRAMP_OPCODE_CLOSE:
      /* Reflect the trampoline bounce to the user-mode close */
      if (onload_close(data))
        rc = -errno;
      break;

    default:
      ci_log ("Unknown trampoline (%d)", opcode);
      ci_assert (0);
  }

  /* Restore errno and return -ve error code */
  errno = saved_errno;
  return rc;
}

static void
ci_trampoline_ul_fail(void)
{
  __ci_fail ("*** Deliberate user-level fail on syscall exit");
}

extern void ci_trampoline_handler_entry (void);

int
citp_init_trampoline(ci_fd_t fd)
{
  int rc;
  int i;
  ci_tramp_reg_args_t args;

  CI_USER_PTR_SET (args.trampoline_entry, ci_trampoline_handler_entry);
  CI_USER_PTR_SET (args.trampoline_exclude, ci_tcp_helper_close_no_trampoline_retaddr);
  CI_USER_PTR_SET (args.trampoline_ul_fail, ci_trampoline_ul_fail);

  args.max_signum = NSIG;
  CI_USER_PTR_SET(args.signal_handler_postpone1, citp_signal_intercept_1);
  CI_USER_PTR_SET(args.signal_handler_postpone3, citp_signal_intercept_3);
  for( i = 0; i <= OO_SIGHANGLER_DFL_MAX; i++ )
    CI_USER_PTR_SET(args.signal_handlers[i], citp_signal_handlers[i]);
  CI_USER_PTR_SET(args.signal_data, citp_signal_data);
  CI_USER_PTR_SET(args.signal_sarestorer, citp_signal_sarestorer_get());
  args.sa_onstack_intercept = CITP_OPTS.sa_onstack_intercept;

  rc = ci_sys_ioctl (fd, OO_IOC_IOCTL_TRAMP_REG, &args);

  if(rc == -1)
    ci_log ("Error %d registering trampoline handler", errno);

  return rc;
}


#else

/* Dummy stubs to make non-Linux UNIXes (e.g. Solaris) compile */
int
citp_init_trampoline (ci_fd_t fd)
{
  return 0;
}

int
ci_trampoline_handler(unsigned opcode, unsigned data)
{
  (void)opcode;
  (void)data;
  return 0;
}


#endif /* __linux */
