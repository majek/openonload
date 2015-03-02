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
*//*! \file driver/ul/linux_bar.h Implements bar mapping in ul driver lib
** <L5_PRIVATE L5_SOURCE>
** \author  jch
**  \brief  Package - ul driver
**   \date  2006/11
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_include_ci_driver_efab */

# ifndef __LINUX_BAR_H__
#define __LINUX_BAR_H__

#include <ci/efhw/hardware_sysdep.h>

#define CI_BAR_ERR_BASE -300

/* Errs specific to this API */
#define CI_BAR_ESUCCESS			(0)
#define CI_BAR_ESYS			(CI_BAR_ERR_BASE-1) /* System error - refer to errno. */
#define CI_BAR_ENODEV			(CI_BAR_ERR_BASE-2)
#define CI_BAR_ENOFUNC			(CI_BAR_ERR_BASE-3)
#define CI_BAR_ENOPERM			(CI_BAR_ERR_BASE-4)
#define CI_BAR_EPARM			(CI_BAR_ERR_BASE-5)
#define CI_BAR_EBADVENDOR		(CI_BAR_ERR_BASE-6)
#define CI_BAR_EPCI			(CI_BAR_ERR_BASE-7)
#define CI_BAR_ENOBAR			(CI_BAR_ERR_BASE-8)
#define CI_BAR_EBARINVALID		(CI_BAR_ERR_BASE-9)
#define CI_BAR_EDISABLED		(CI_BAR_ERR_BASE-10)
#define CI_BAR_EISIOPORT		(CI_BAR_ERR_BASE-11)
#define CI_BAR_EISIOMEM			(CI_BAR_ERR_BASE-12)
#define CI_BAR_EISEXPROM		(CI_BAR_ERR_BASE-13)
#define CI_BAR_ENOSUCHBAR		(CI_BAR_ERR_BASE-14)
#define CI_BAR_ENOT_SUPPORTED		(CI_BAR_ERR_BASE-15)
#define CI_BAR_ERECONFIG_FAILED		(CI_BAR_ERR_BASE-16)
#define CI_BAR_EOFFSET_RANGE		(CI_BAR_ERR_BASE-17)
#define CI_BAR_EPORT_OFFSET_RANGE	(CI_BAR_ERR_BASE-18)
#define CI_BAR_EBLOCK_NOT_IO_ENABLED	(CI_BAR_ERR_BASE-19)
#define CI_BAR_EBADDEVICE		(CI_BAR_ERR_BASE-20)
/* Extra return codes just for debug */
#define CI_BAR_ENODEV2			(CI_BAR_ERR_BASE-21)
#define CI_BAR_ENODEV3			(CI_BAR_ERR_BASE-22)

/* The index of the 32bit expansion BAR as an offset from 64bit BARS (!!) */
#define CI_BAR_EXP_ROM 6

/* Maximum offset accessible via indirected IOPort */
#define IOPORT_MAX_OFFSET (8*2*CI_PAGE_SIZE)

/* Supported mapping types */
enum efx_bar_map_flags {
  EFX_BAR_ACCESS_IOMEM = 0x1,
  EFX_BAR_ACCESS_IOPORT = 0x2,
  EFX_BAR_ACCESS_EXPROM = 0x4,
  EFX_BAR_ALLOW_RECONFIG = 0x8,

  EFX_BAR_ACCESS_ALL = 0x7,
};

/*
 * Exported API 
 * 
 * Note: This API makes use of libpci (which must be linked into executables
 * using it) and mmap of /dev/mem (which means must be executed with root
 * privileges).
 * 
 * To build requires pci/pci.h - to ensure that this and libpci are available
 * the appropriate pciutils-devel-***** package must be installed.
 *
 * &struct efx_bar_map is informational - it stores information about
 * a mapping to be used by efx_dev_unmap().
 */
struct efx_bar_map 
{
  char *dev_name;
  int nic_i, func, bar; /* Must be assigned before call to efx_bar_map() */
  int pci_domain;       /* Info - assigned by call to efx_bar_map() */
  int pci_bus;          /* ... */
  int pci_dev;          /* ... */
  int pci_func;         /* ... */
  volatile char __iomem *bar_addr;  /* for IOMEM and EXPROM */
  int ioport;           /* for IOPORT */
  int bar_bytes, mmap_bytes;
  const char* bar_name;
};

/*!
 * Return textual error message corresponding to interface error return
 */
extern char *efx_bar_errstring(int err);

/*!
 * Return message of error known to be returned either by one of the efx_bar_*
 * fns or a negative system code
 *
 * We need the value of errno available at the time the error was created to
 * provide the correct result.
 */
extern char *efx_bar_strerror(int err, int sys_errno);

/*!
 * Return some system error code to represent the given bar error code.
 *
 * We need the value of errno available at the time the error was created to
 * provide the correct result.
 */
extern int /*+rc*/ efx_bar_errno(int err, int sys_errno);

/*
 * Check offset is valid for the mapped bar - return 0 if valid
 * For IOPort access indirected offset is checked
 */
extern int efx_bar_validate_offset(struct efx_bar_map *bar, int offset);

/**********************************************************************
****************** NEW API ********************************************
**********************************************************************/

struct efx_bar_device {
  /* PCI info. */
  int pci_domain, pci_bus, pci_dev, pci_func;
  int pci_vendor_id, pci_device_id, pci_revision;
  int nic_index;
};

/*
 * Return information about the given nic, specified as index.  Returns
 * CI_BAR_ENODEV if the given nic goes not exist.
 */
extern int /*-bar rc*/ efx_dev_find_i(struct efx_bar_device* dev_out,
                                      int nic_i);

/*
 * Return information about the given nic, specified as domain, bus, and
 * device.  Returns CI_BAR_ENODEV if the given nic goes not exist.
 */
extern int /*-bar rc*/ efx_dev_find(struct efx_bar_device* dev_out, int domain,
                                    int bus, int device, int pci_func);

/* Iterate over all devices calling the provided iterator. Stops
 * when te iterator returns a non-zero value.
 */
extern int /*-bar rc*/
efx_dev_iterate(int (*callback)(struct efx_bar_device *, void *),
                void *priv);

/*
 * Return bar address information about the given NIC, specified as a string.
 * Returns TRUE iff the prefix of the device name is the name of a NIC.
 * If successful *ref_dev_name is updated to point at the character following
 * the NIC name.
 * Return code from CI_BAR_* series always placed in \c out_bar_rc
 */
extern int /*bool*/ efx_dev_parse_str(const char **ref_dev_name,
                                      struct efx_bar_device* device_out,
                                      int *out_bar_rc);

/*
 * Return bar address information about the given NIC, specified as a string.
 * Returns CI_BAR_ENODEV if the given nic goes not exist.
 */
extern int /*-bar rc*/ efx_dev_find_str(struct efx_bar_device* dev_out,
                                        const char *dev_name);

/*
 * Return information about the given nic, specified as a PCI address.
 * Returns CI_BAR_ENODEV if the given nic goes not exist.
 */
extern int /*- bar rc*/ efx_dev_find_pci(struct efx_bar_device* device_out,
                                         int domain, int bus,
                                         int device, int func);
/*
 * Map a memory-mapped bar.
 */
extern int /*-bar rc*/ efx_dev_map(const struct efx_bar_device* bdev, int func,
                                   int bar,
                                   struct efx_bar_map* bar_out,
                                   enum efx_bar_map_flags flags);

/*
 * Find a bar by name.  Returns CI_BAR_ENOSUCHBAR on failure.
 */
extern int /*-bar rc*/ efx_dev_choose_bar(const struct efx_bar_device* device,
                                          const char* name, int* func_out,
                                          int* bar_out);

/*
 * Map the "char" bar of the given device.  [*bar_out] is overwritten and
 * need not be initialised in any way.
 *
 * Invoke efx_dev_unmap() to delete the mapping.
 */
extern int /*-bar rc*/ efx_dev_map_char(const struct efx_bar_device*,
                                        struct efx_bar_map* bar_out);

/*
 * Unmap BAR address obtained by call to efx_bar_map()
 */
int /*-bar rc*/ efx_dev_unmap(struct efx_bar_map *bar);


#endif /* __LINUX_BAR_H__ */
/*! \cidoxg_end */
