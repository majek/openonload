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

/*
 * Build the file using the following command:
 *   $ gcc -oonload_is_present -lonload_ext onload_is_present.c
 *
 * Test by running the following two commands:
 *   $ ./onload_is_present
 *   Program running without Onload
 *   $ onload ./onload_is_present
 *   Program running with Onload
 *   $
 */
#include <stdio.h>

#include <onload/extensions.h>

int main(void)
{
  if( onload_is_present() )
    printf("Program running with Onload\n");
  else
    printf("Program running without Onload\n");

  return 0;
}
