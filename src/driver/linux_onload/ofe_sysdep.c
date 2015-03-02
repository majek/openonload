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


#include "onload_kernel_compat.h"
#include "ofe/types.h"
#include "libofe/onload.h"
#include "ci/efrm/licensing.h"

#define CI_LCOP_CHALLENGE_FEATURE_OFE       (8)

int ofe_get_page_shift(void)
{
  return PAGE_SHIFT;
}

char* ofe_strdup(const char* str)
{
  return kstrdup(str, GFP_KERNEL);
}
void ofe_dup_free(const char* str)
{
  kfree(str);
}
void* ofe_alloc(int size)
{
  return kmalloc(size, GFP_KERNEL);
}
void ofe_free(void* mem)
{
  kfree(mem);
}
void* ofe_alloc_huge(int size)
{
  return vmalloc(size);
}
void ofe_free_huge(void* mem)
{
  vfree(mem);
}

#ifdef EFRM_HAVE_KSTRTOUL
int
ofe_strtoul(const char* str, unsigned long* res_out)
{ 
  return kstrtoul(str, 0, res_out);
}   
#else
/* simple_strtoul and kstrtoul are not the same.
 * And yes, we ignore this difference. */
int
ofe_strtoul(const char* str, unsigned long* res_out)
{ 
  char* end;
  *res_out = simple_strtoul(str, &end, 0);
  while (isspace(*end))
    ++end; 
  if( *end != '\0' )
    return -EINVAL;
  return 0;  
}
#endif

#include <linux/inet.h>

#ifndef EFRM_HAVE_IN4_PTON
static int in4_pton(const char* src, int srclen, u8* dst, int delim,
                    const char** end)
{                   
  /* NB. Not a proper implementation of in4_pton().  Just enough to support
   * ofe_inet_pton() below.
   */
  int b1,b2,b3,b4;
  u32 addr_he;
  char c;
  if( sscanf(src, "%u.%u.%u.%u%c", &b1, &b2, &b3, &b4, &c) != 4 )
    return 0;
  addr_he = (((((b1 << 8) | b2) << 8) | b3) << 8) | b4;
  *((u32*) dst) = htonl(addr_he);
  *end = src + strlen(src);
  return 1;
} 
#endif


#ifndef EFRM_HAVE_IN6_PTON
static int in6_pton(const char* src, int srclen, u8* dst, int delim,
                    const char** end)
{                   
  /* NB. Not a proper implementation of in6_pton().  Just enough to support
   * ofe_inet_pton() below.
   */
  return 0;
}
#endif


int ofe_isspace(int c)
{
  return isspace(c);
}   

int ofe_sscanf(const char* str, const char* fmt, ...)
{
  va_list args;
  int rc;
  va_start(args, fmt);
  rc = vsscanf(str, fmt, args);
  va_end(args);
  return rc;
}

#ifndef EFRM_HAVE_STRCASECMP
int strcasecmp(const char *s1, const char *s2)
{
	int c1, c2;

	do {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
	} while (c1 == c2 && c1 != 0);
	return c1 - c2;
}
#endif


int ofe_inet_pton(int af, const char* src, void* dst)
{
  if( af == AF_INET ) {
    const char* end = NULL;
    if( in4_pton(src, -1, dst, -1, &end) == 1 && *end == '\0' )
      return 1;
    else
      return 0;
  }
  else if( af == AF_INET6 ) {
    const char* end = NULL;
    if( in6_pton(src, -1, dst, -1, &end) == 1 && *end == '\0' )
      return 1;
    else
      return 0;
  }
  else {
    return -1;
  }
}

u16 ofe_ntohs(u16 netshort)
{
  return ntohs(netshort);
} 
u32 ofe_ntohl(u32 netlong)
{
  return ntohl(netlong);
} 
u16 ofe_htons(u16 hostshort)
{
  return htons(hostshort);
}
u32 ofe_htonl(u32 hostlong)
{
  return htonl(hostlong);
}

int
ofe_license_challenge(void* nic_data, 
                      struct ofe_license_challenge* challenge)
{
  struct efrm_license_challenge_s s;
  int rc;

  s.feature = CI_LCOP_CHALLENGE_FEATURE_OFE;
  /*ci_assert_equal(sizeof(s.challenge), sizeof(challenge->challenge));*/
  memcpy(s.challenge, challenge->challenge, sizeof(s.challenge));
  rc = efrm_license_challenge(nic_data, &s);
  if( rc != 0 )
    return rc;
  challenge->expiry = s.expiry;
  /*ci_assert_equal(sizeof(s.signature), sizeof(challenge->signature));*/
  memcpy(challenge->signature, s.signature, sizeof(s.signature));
  return 0;
}
