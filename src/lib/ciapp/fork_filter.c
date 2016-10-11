/*
** Copyright 2005-2016  Solarflare Communications Inc.
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
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */


#include <ci/app.h>
#include <unistd.h>


int ci_fork_filter(char* const argv[])
{
  int fd[2], rc;

  CI_TRY_RET(pipe(fd));
  CI_TRY_RET(rc = fork());

  if( rc == 0 ) {	/* child */
    CI_TRY_RET(dup2(fd[1], STDOUT_FILENO));
    CI_TRY_RET(close(fd[0]));
    CI_TRY_RET(close(fd[1]));
    CI_TRY_RET(execvp(argv[0], argv));
  }
  else {		/* parent */
    CI_TRY_RET(dup2(fd[0], STDIN_FILENO));
    CI_TRY_RET(close(fd[0]));
    CI_TRY_RET(close(fd[1]));
  }

  return 0;
}


/*! \cidoxg_end */
