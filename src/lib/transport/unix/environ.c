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
** \author  mjs
**  \brief  Operations for environment handling
**   \date  2005/02/15
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_unix */
 
#define _GNU_SOURCE /* For dladdr() */
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <dlfcn.h>

#include <internal.h>

static char *empty_env[] = { NULL };
static char **saved_env;
static unsigned int saved_env_count;

/*! Identiry LD_PRELOAD variable */
static int env_is_ld_preload(const char *var)
{
  ci_assert(var);
  return (strncmp(var, "LD_PRELOAD=", 11) == 0);
}

/*! Identify our environment variables (including LD_PRELOAD).
** \param  var      Variable definition to test
** \return          True or false
*/
static int is_our_env_var(const char *var)
{
  ci_assert(var);
  return (env_is_ld_preload(var)
          || (strncmp(var, "EF_", 3) == 0)
          || (strncmp(var, "CI_", 3) == 0)
          || (strncmp(var, "TP_", 3) == 0));
}


/*! Build an argv[] from a va_list.  If env_ptr is not NULL, it is assumed that
**  an environment pointer is expected after the NULL arg at the end of the
**  list.
** \param  arg      First argument
** \param  args     Remaining arguments
** \param  env_ptr  Output environment pointer, or NULL
** \return          The constructed argv[] array
*/
char **citp_environ_handle_args(const char *arg, va_list args, char ***env_ptr)
{
  size_t argv_size = 32;
  unsigned int n = 0;
  char **argv = malloc(argv_size * sizeof(const char *));

  if (argv == NULL) {
    Log_E(log("malloc() for exec argument collection failed"));
    return NULL;
  }
  argv[n] = (char *)arg;
  while (argv[n++])
  {
    if (n == argv_size) {
      argv_size <<= 1;
      argv = realloc(argv, argv_size);
      if (argv == NULL) {
        Log_E(log("realloc() for exec argument collection failed"));
        return NULL;
      }
    }
    argv[n] = va_arg(args, char *);
  }
  if (env_ptr) {
    *env_ptr = va_arg(args, char **);
  }
  return argv;
}


/*! Check to see if our LD_PRELOAD is still present.  If not, assume that we
**  need to restore both LD_PRELOAD and any other EF_xxx or CI_xxx variables
**  that were saved at initialisation.
** \param  env      Original environment
** \return          New environment with LD_PRELOAD etc. guaranteed present
**
** \TODO  We don't cope with LD_PRELOADs containing multiple components yet...
*/
char **citp_environ_check_preload(char **env)
{
  char **env_ptr;
  char *ld_preload = NULL;
  unsigned int env_count = 0;
  
  if (saved_env_count == 0) {
    return env;
  }
  
  if (!env) {
    env = empty_env;
  }
  env_ptr = env; 
  while (*env_ptr != NULL) {
    if (strncmp(*env_ptr, "LD_PRELOAD=", 11) == 0) {
        ld_preload = *env_ptr;
    }
    env_ptr++;
    env_count++;
  }
  env_ptr++;
  if (ld_preload) {
    /* If LD_PRELOAD is still set, we assume that any other changes that may
     * have been made to EF_xxx or CI_xxx vars are deliberate, so we just
     * return the original environment.
     */
    return env;
  } else {
    char **new_env = malloc((sizeof(char *) * (env_count+saved_env_count+1)));
    char **old_env_ptr = env;
    char **new_env_ptr = new_env;
    unsigned int n;

    if (new_env) {
      for (n = 0; n < saved_env_count ; n++) {
        *new_env_ptr++ = saved_env[n];
        Log_V(log("%s: restored %s", __FUNCTION__, saved_env[n]));
      }
      while (*old_env_ptr != NULL) {
        if (!is_our_env_var(*old_env_ptr)) {
          *new_env_ptr++ = *old_env_ptr;
        }
        old_env_ptr++;
      }
      *new_env_ptr = NULL;
      return new_env;
    } else {
      Log_E(log("malloc() for new environment failed"));
      return env;
    }      
  }
}

/* Find the path to the onload library we are running */
static const char *citp_find_loaded_library(void)
{
  Dl_info   my_dl;

  dladdr(citp_find_loaded_library, &my_dl);
  return my_dl.dli_fname;
}

/*! Initialise - called on startup to save away any relevant current
**  environment variables.
** \return          0 for success, -1 for failure
*/
int citp_environ_init(void)
{
  char **env_ptr;
  size_t mem_needed = 0;
  unsigned int n;
  char *string_buf, *p;

  const char *lib_path = NULL;
  const char *ld_preload_value = NULL;

  env_ptr = __environ ? __environ : empty_env;
  saved_env_count = 0;
  while (*env_ptr != NULL) {
    if (is_our_env_var(*env_ptr)) {
      mem_needed += strlen(*env_ptr) + 1;
      saved_env_count++;
      if (env_is_ld_preload(*env_ptr))
        ld_preload_value = *env_ptr + 11;
    }
    /* temporary hack for djr */
    if (strcmp(*env_ptr, "EF_NO_PRELOAD_RESTORE=1") == 0) {
        Log_V(log("Environment restore disabled"));
        saved_env_count = 0;
        return 0;
    }
    /* end temporary hack */
    env_ptr++;
  }
  if (saved_env_count == 0) {
    Log_V(log("Invoked without LD_PRELOAD?  Environment restore disabled."));
    return 0;
  }

  /* Add ourself to LD_PRELOAD if we've been asked to. */
  if (getenv("EF_LD_PRELOAD")) {
    const char *full_path = citp_find_loaded_library();

    ci_assert(full_path);
    ci_assert(strrchr(full_path, '/'));
    lib_path = strrchr(full_path, '/') + 1;

    /* Correct LD_PRELOAD value should be the same as lib_path, or at least
     * start with lib_path+':'. */
    if ((!ld_preload_value ||
       (strlen(ld_preload_value) < strlen(lib_path) ||
       (strncmp(ld_preload_value, lib_path,
                strlen(lib_path)) != 0) ||
       ((ld_preload_value[strlen(lib_path)] != ':') &&
        (ld_preload_value[strlen(lib_path)] != '\0'))
      ))) {

      mem_needed += strlen(lib_path); /* Add our library */
      if (!ld_preload_value) {
        mem_needed += 12; /* Add "LD_PRELOAD=" line */
        saved_env_count++;
      }
      if (ld_preload_value && ld_preload_value[0] == '\0')
        ld_preload_value = NULL; /* Do not set ":" at the end */
      if (ld_preload_value)
        mem_needed++; /* Add ':' separator */
      Log_V(log("%s: LD_PRELOAD=\"%s\", but we are loaded as %s",
                __FUNCTION__, ld_preload_value ? : "", full_path));
    }
    else
      lib_path = NULL;
  }

  saved_env = malloc((saved_env_count + 1) * sizeof(char *));
  string_buf = malloc(mem_needed);
  if ((saved_env == NULL) || (string_buf == NULL)) {
    Log_E(log("malloc() for environment save area failed"));
    return -1;
  }
  
  env_ptr = __environ ? __environ : empty_env;
  p = string_buf;
  n = 0;
  while (*env_ptr != NULL) {
    if (lib_path && env_is_ld_preload(*env_ptr)) {
      char *ptr = p;
      strcpy(p, "LD_PRELOAD=");
      p += 11;
      strcpy(p, lib_path);
      p += strlen(lib_path);
      if (ld_preload_value) {
        strcpy(p, ":");
        strcpy(p + 1, ld_preload_value);
        p += strlen(ld_preload_value) + 1;
      }
      p += 1;
      saved_env[n++] = ptr;
      Log_V(log("%s: saved %s", __FUNCTION__, ptr));
      lib_path = NULL;
    } else if (is_our_env_var(*env_ptr)) {
      strcpy(p, *env_ptr); /* Safe, we know we have enough memory */
      saved_env[n++] = p;
      Log_V(log("%s: saved %s", __FUNCTION__, p));
      p += (strlen(*env_ptr) + 1);
    }
    env_ptr++;
  }
  if (lib_path) {
    /* There were no LD_PRELOAD, so we should add it */
    char *ptr = p;
    strcpy(p, "LD_PRELOAD=");
    p += 11;
    strcpy(p, lib_path);
    p += strlen(lib_path) + 1;
    saved_env[n++] = ptr;
    Log_V(log("%s: added and saved %s", __FUNCTION__, ptr));
  }
  saved_env[n] = NULL;
  ci_assert_equal(n, saved_env_count);
  ci_assert_equal(p, &string_buf[mem_needed]);
  
  return 0;
}



/*! \cidoxg_end */
