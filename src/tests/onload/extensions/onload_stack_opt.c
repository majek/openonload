/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
 *   $ gcc -oonload_stack_opt -lonload_ext onload_stack_opt.c
 *
 * Test by running the following two commands:
 *   $ onload ./onload_stack_opt
 *   
 * This will wait for 10 seconds so you can test using the following line:
 *   $ onload_stackdump lots | grep -e 'EF_SPIN_USEC' -e '^UDP'
 *
 * This shows how to set a variable but it will not enable spinning because
 * others, such as EF_UDP_RECV_SPIN, must be set to enable it for individual
 * calls.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <onload/extensions.h>

static int createSocket(int port)
{
  int s;
  struct sockaddr_in servaddr;

  s = socket(AF_INET, SOCK_DGRAM, 0);

  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family      = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port        = htons(port);

  bind(s, (struct sockaddr *) &servaddr, sizeof(servaddr));

  return s;
}

int main(void)
{
  int rc;
  int s1;
  int s2;
  int s3;

  /* create a 'default' stack */
  s1 = createSocket(20001);

  /* specify a spin time */
  rc = onload_stack_opt_set_int("EF_SPIN_USEC", 1000000);
  if( rc )
    printf("Error setting stack option: %d", -rc);

  /* set a name to create a new stack */
  if( onload_set_stackname(ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL, "s_name1") )
    perror("Error setting stackname:");

  /* create a socket thereby creating a new stack */
  s2 = createSocket(20002);

  /* reset the options for future stacks back to those at start */
  onload_stack_opt_reset();

  /* set a name to create another new stack */
  if( onload_set_stackname(ONLOAD_ALL_THREADS, ONLOAD_SCOPE_GLOBAL, "s_name2") )
    perror("Error setting stackname:");

  /* create a socket in the new stack */
  s3 = createSocket(20003);

  sleep(10);

  close(s1);
  close(s2);
  close(s3);
}
