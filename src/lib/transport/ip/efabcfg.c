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
** <L5_PRIVATE L5_SOURCE>
** \author  ds
**  \brief  efabcfg UL helper functions
**   \date  2006/01/31
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <ci/internal/efabcfg.h>


#ifdef DO
#undef DO
#endif

#ifdef IGNORE
#undef IGNORE
#endif

#define DPRINTF ci_log

#define DO(_x) _x
#define IGNORE(_x)

/*#define DEBUG_INTERCEPT DO*/

#ifdef NDEBUG
#undef DEBUG_INTERCEPT
#endif

#ifndef DEBUG_INTERCEPT
#define DEBUG_INTERCEPT IGNORE
#endif


# undef  CI_CFG_OPT
# define CI_CFG_OPT(env, name, type, doc, type_m, group, default, max, min, presn) \
    CI_STRUCT_MBR(name, default),
ci_cfg_opts_t ci_cfg_opts = {
  {
    #include <ci/internal/opts_citp_def.h>
  },
  {
    #include <ci/internal/opts_netif_def.h>
  },
  {
    #include <ci/internal/opts_user_def.h>
  } 
};
# undef CI_CFG_OPT


/*! Read the efabcfg database and set the global ci_cfg_opts struct
 *  The return value only makes sense when we are not intercepting.
 *  If the rc isn't zero, then a hard configuration error was encountered
 *  and we shouldn't attempt to intercept whatever the state of the
 *  environment variables.
 *  \param proc_name_utf8 process name to pass to pass to the configuration
 *                        system database query ioctl
 *  \param ref_cfgerr     place to store one of the CICFG_DESC_* failure codes
 */
int ci_cfg_query(char *proc_name_utf8, int *ref_cfgerr)
{
  ci_ioctl_cfg_query_t q;
  ci_cfg_ioctl_desc_t desc;
  ef_driver_handle fd;
  int rc, i = 0;

  *ref_cfgerr = 0;

  /* Install "modified" netif opts default values, the rest
   * (citp_opts, user_opts) don't need any modification of their "original"
   * default values.
   */
  ci_netif_config_opts_defaults(&ci_cfg_opts.netif_opts);

  memset(&desc, 0, sizeof(desc));
  CI_USER_PTR_SET(desc.ptr, &q);
  desc.len = sizeof(q);

  CI_USER_PTR_SET(q.uid_n_proc.uid_ptr, 0);
  q.uid_n_proc.uid_len = 0;
  CI_USER_PTR_SET(q.uid_n_proc.proc_name_ptr, proc_name_utf8);
  q.uid_n_proc.proc_name_len = proc_name_utf8
                               ? (strlen(proc_name_utf8)+1) : 0;
  q.opts = ci_cfg_opts;

  rc = ef_onload_driver_open(&fd, OO_STACK_DEV, 1);
  if( rc < 0 ) {
    LOG_E(ci_log("%s: ef_onload_driver_open() failed (rc=%d)",
                 __FUNCTION__, rc);
          if( rc == -ENOENT )
            ci_log("%s: Is /dev/onload missing?", __FUNCTION__);
          else if( rc == -ENXIO )
            ci_log("%s: Is the onload module loaded?", __FUNCTION__);
          );
    goto dont_intercept_warn;
  }

  rc = oo_config_query(fd, &desc);
  while(CI_UNLIKELY( rc == 0 && desc.err == CICFG_DESC_EAGAIN && i < 5 )) {
    /* In case of EAGAIN, give up the timeslice and try 5 more times. */
    CI_DEBUG(ci_log("%s: you should only ever see this message if you are "
                    "installing a configuration database in the char driver",
                    __FUNCTION__));
    rc = oo_config_query(fd, &desc);
    i++;
  }

  ef_onload_driver_close(fd);

  /* Check for hard error, if this fails we can't override interception
   * options with environment variables e.g. EF_INTERCEPT, EF_TCP.  If the
   * driver has not been configured, leave the compile-time defaults in
   * place.
   */
  if( rc || (desc.err && desc.err != CICFG_DESC_ENOTINST) ) {
    if( rc == 0 && desc.err == CICFG_DESC_EPROCEXCL )
      goto dont_intercept;
    LOG_E(ci_log("%s: oo_config_query() failed (rc=%d, err=%d)",
                 __FUNCTION__, rc, desc.err));
    if( rc == 0 )
      rc = -EINVAL;
    goto dont_intercept_warn;
  }

  /* copy the options returned by the driver */
  if( ! desc.err )
    ci_cfg_opts = q.opts;

  /* adjust the netif options again... */
  ci_netif_config_opts_getenv(&ci_cfg_opts.netif_opts);
  ci_netif_config_opts_rangecheck(&ci_cfg_opts.netif_opts);
  LOG_S(ci_netif_config_opts_dump(&ci_cfg_opts.netif_opts));

  /* can we intercept? */
  if (ci_cfg_opts.citp_opts.intercept == 0) {
    rc = 0;
    goto dont_intercept;
  }

  DEBUG_INTERCEPT(DPRINTF("config: acceleration enabled - '%s'",
			  proc_name_utf8););
  return 0;

 dont_intercept_warn:
  ci_log("%s: WARNING: OpenOnload acceleration disabled.", __FUNCTION__);
 dont_intercept:
  ci_cfg_dont_intercept(&CITP_OPTS);
  DEBUG_INTERCEPT(DPRINTF("config: acceleration disabled - '%s'",
			  proc_name_utf8););
  return rc;
}

/*! \cidoxg_end */
