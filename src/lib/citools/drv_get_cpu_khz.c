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
 ** \author  
 **  \brief  
 **   \date  
 **    \cop  (c) Level 5 Networks Limited.
 ** </L5_PRIVATE>
 *//*
 \**************************************************************************/
 
 /*! \cidoxg_lib_citools */
 
#include "citools_internal.h"


/*
 * 'cpu_speed' is a char driver module parameter passed in from userland.
 */
extern int ci_cpu_speed;

int ci_get_cpu_khz(unsigned* cpu_khz_out)
{
  if (ci_cpu_speed > 0) {
    *cpu_khz_out = (unsigned) ci_cpu_speed;
    return 0;
  }
  else {
    ci_log("error - ci_cpu_speed was read before being set");
    return -EINVAL;
  }
}

#if defined(__ci_wdm__)

#define REG_CPU0_KEY L"\\Registry\\Machine\\\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"

#define REG_CPU0_MHZ_VALUE L"~MHz"

int ci_get_cpu_khz(unsigned* cpu_khz_out)
{
  static unsigned cached_result;
  NTSTATUS status;
  PKEY_VALUE_PARTIAL_INFORMATION vpip;
  HANDLE HKey;
  OBJECT_ATTRIBUTES oa;
  ULONG size;
  ULONG vpip_size;
  UNICODE_STRING keyname, valname;

  ci_assert(cpu_khz_out);

  if( cached_result > 0 ) {
    *cpu_khz_out = cached_result;
    return 0;
  }

  RtlInitUnicodeString(&keyname, REG_CPU0_KEY);
  InitializeObjectAttributes(&oa, &keyname, OBJ_CASE_INSENSITIVE, NULL, NULL);
  
  status = ZwOpenKey(&HKey, KEY_READ, &oa);
  if (!NT_SUCCESS(status)) 
      goto fail;

  RtlInitUnicodeString(&valname, REG_CPU0_MHZ_VALUE);
  size=0;
  status = ZwQueryValueKey(HKey, &valname, KeyValuePartialInformation,
			   NULL, 0, &size);
  if (STATUS_BUFFER_TOO_SMALL != status &&
      STATUS_BUFFER_OVERFLOW != status &&
      !NT_SUCCESS(status))
    goto fail;

  vpip = (PKEY_VALUE_PARTIAL_INFORMATION)ci_alloc(size);
  if (NULL == vpip)
    goto fail;

  status = ZwQueryValueKey(HKey, &valname, KeyValuePartialInformation,
			   vpip, size, &vpip_size);
  if (!NT_SUCCESS(status))
    goto fail2;

  cached_result = (*(ci_uint32 *)(&vpip->Data)) * 1000;
  ci_free(vpip);
  *cpu_khz_out = cached_result;
  return 0;

fail2:
  ci_free(vpip);
fail:
  ci_log("Unable to read processor speed from registry - rc %X", status);
  return -EINVAL;
  /* or we could lie:
     *cpu_khz_out = 2800 * 1000;
     return 0;
  */
}
#endif



/* NOTE: there seems to be no reliable way of getting this in the kernel, but
 *       it is required to allow netif creation from within the kernel (used
 *       for iSCSI support).  So, the value to be returned by ci_get_cpu_khz()
 *       is currently set by passing a module parameter to the char driver,
 *       and the implementation of ci_get_cpu_khz() can be found in
 *       driver/linux/char_driver.c .
 */


/*! \cidoxg_end */
