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
** <L5_PRIVATE L5_HEADER >
** \author  ds
**  \brief  efabcfg linux specific kernel code
**   \date  2005/12/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/


#include <onload/efabcfg.h>


extern const char * ci_cfg_proc_name_get(char **pointer_to_free)
{
  char *cmd;
  unsigned long cmd_len;
  const char *p;

  cmd_len = current->mm->arg_end - current->mm->arg_start;
  cmd = ci_alloc(cmd_len+1);
  if( cmd == NULL )
    return NULL;

  if( copy_from_user(cmd, (const char *)(current->mm->arg_start), 
                     cmd_len) != 0 ) {
    ci_free(cmd);
    return NULL;
  }

  *pointer_to_free = cmd;
  cmd[cmd_len] = '\0';
  p = strrchr(cmd, '/');

  /* For the time being return the last path element of the arg_start version
     Later we will convert this in to something as close to a canonical
     full path name as possible.
   */
  if (p == NULL)
    p = cmd;
  else
    p++;
  
  /*
   * Notes:
   * comm seems to have a short name (16 bytes) of the process name
   * arg_start has the command as the user typed it in
   *
   * Example: tests/ip/simple/interactive,
   *          comm gives interactive
   *          arg_start gives tests/ip/simple/interactive
   *
   * When using links (hard or soft) both show the link name.
   * When using a bash alias the alias name doesn't show.
   * When using a bash function the function name doesn't show.
   * When the hash-bling (#!) facility of unix comm and arg_start give you
   * different results. comm gives the name of the file and arg_start gives
   * the name of the interpreter after the #! character sequence.
   */
  return p;
}


extern ci_cfg_uid_t ci_cfg_uid_get(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
  return (current->euid);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
  return current_euid();
#else
  return __kuid_val(current_euid());
#endif
}


int ci_cfg_is_sysadmin(void)
{
  /* Allow access for superuser only */
  return capable(CAP_SYS_ADMIN);
}

