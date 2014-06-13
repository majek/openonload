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
*//*! \file reg_walker.h
** <L5_PRIVATE L5_HEADER >
** \author  aam
**  \brief  Generic registry access helper
**   \date  2006/07/11
**    \cop  (c) Solarflare Communications Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_iscsi */

#ifndef __CI_ISCSI_REG_WALKER_H__
#define __CI_ISCSI_REG_WALKER_H__

/*! The registry walker is provided to aid storage and retrieval of
 * information in the system registry. The walker can be told to move around
 * the registry structure reading and writing information as required. Key
 * values can be accessed by name, or by iterating through all values in a
 * given key.
 * When a fatal error occurs (eg failure to access registry, out of memory) an
 * error message is logged and the walker is left in an error state. In this
 * state operations can still be requested, and will fail gracefully.
 *
 * Note that the walker cannot currently move up registry tree, as this
 * behaviour has not yet been needed.
 *
 * The following code is not optimised for speed. It is assumed that if you're
 * using the registry things are going to be slow anyway.
 *
 * This was originally written for the iSCSI driver, however there is no reason
 * it could not be used for other modules.
 *
 * This module should only be used an IRQL = PASSIVE_LEVEL.
 */

/*! Registry walker. This should be considered an opaque object and none of
 * it's members should be manipulated directly
 */
typedef struct _registryWalker {
  PDEVICE_OBJECT logdev; /* Device log event messages can be sent to */
  int nIndex;            /* Index of current record for iterator */
  void *infoBuffer;      /* Buffer for read data */
  ci_uint32 bufferSize;  /* Size of buffer allocated */
  HANDLE handle;         /* Handle to current registry key */
  int error;             /* The first error encountered */
} RegWalker;

/*! Construct a registry walker. Must be called before the walker is used.
 * Once successfully constructed, the iterator must later be destructed
 * to avoid leaks.
 * \param   pWalker          walker to initialise
 */
extern void
ci_regWalkerCtor(RegWalker *pWalker, PDEVICE_OBJECT log_dev);

/*! Destruct a previously constructed registry walker.
 * \param   pWalker          walker to destruct
 */
extern void
ci_regWalkerDtor(RegWalker *pWalker);

/*! Move an open walker to the specified registry path.
 * \param   walker           walker to move
 * \param   path             path to move to
 * \return  0     => success
 *          non-0 => specified path could not be found
 */
extern int
ci_regWalkerMoveToPath(RegWalker *walker, WCHAR *path);

/*! Move an open walker to a child entry, and create such a child if one
 * doesn't exist.
 * \param   pWalker          walker to move
 * \param   name             relative name of child to open
 * \return  0 => child already existed
 *          1 => we created child
 */
extern int
ci_regWalkerMoveToChild(RegWalker *pWalker, WCHAR *name);

/*! Move an open walker to a device's hardware key entry.
 * \param   pWalker          walker to move
 * \param   pDevice          PDO of device to navigate to
 */
extern void
ci_regWalkerMoveToDevice(RegWalker *pWalker, PDEVICE_OBJECT pDevice);

/*! Move an open walker to a device's software key (driver) entry.
 * \param   pWalker          walker to move
 * \param   pDevice          PDO of device to navigate to
 */
extern void
ci_regWalkerMoveToDriver(RegWalker *pWalker, PDEVICE_OBJECT pDevice);

/*! Move an open walker to a device's service key entry.
 * \param   pWalker          walker to move
 */
extern void
ci_regWalkerMoveToService(RegWalker *pWalker);

/*! Report the first fatal error we encountered.
 * \param   pWalker          walker to query
 * \return  error code, 0 for no error
 */
extern int
ci_regWalkerGetError(RegWalker *pWalker);

/*! Methods to handle named values */

/*! Find the value with the given name in the current key
 * \param   pWalker          walker to query
 * \param   name             name of value to get
 * \return  pointer to KEY_VALUE_PARTIAL_INFORMATION object containing data, or
 *          NULL if value not found.
 */
extern KEY_VALUE_PARTIAL_INFORMATION *
ci_regWalkerGetNamedValue(RegWalker *pWalker, WCHAR *name);

/*! Find the DWORD value with the given name in the current key
 * \param   pWalker          walker to query
 * \param   name             name of value to get
 * \param   pValue           location to store retrieved value
 * \return  0 => success
 *          1 => could not find specified value
 */
extern int
ci_regWalkerGetNamedDWORD(RegWalker *pWalker, WCHAR *name, ULONG *pValue);

/*! Find the DWORD value with the given name in the current key. If such a
 * value does not exist create it, set it's to the given default value, and
 * return that.
 * \param   pWalker          walker to query
 * \param   name             name of value to get
 * \param   dflt             default value to use if value is not in key
 * \return  retrieved value
 */
extern ULONG
ci_regWalkerGetRequiredNamedDWORD(RegWalker *pWalker, WCHAR *name, ULONG dflt);

/*! Set the value with the given name in the current key
 * \param   pWalker          walker to query
 * \param   name             name of value to set
 * \param   type             type of value
 * \param   valueSize        size of value data
 * \param   value            value
 */
extern void
ci_regWalkerSetNamedValue(RegWalker *pWalker, WCHAR *name, ULONG type,
                          ULONG valueSize, void *value);

/*! Set the DWORD value with the given name in the current key
 * \param   pWalker          walker to query
 * \param   name             name of value to set
 * \param   value            value
 */
extern void
ci_regWalkerSetNamedDWORD(RegWalker *pWalker, WCHAR *name, ULONG value);

/*! Set the value data using a WMI style string in the current key
 * The data will be stored as binary data, without the size field
 * \param   pWalker          walker to query
 * \param   name             name of value to set
 * \param   string           WMI style string
 */
extern void
ci_regWalkerSetNamedWmiString(RegWalker *pWalker, WCHAR *name, WCHAR *string);

/*! Delete the value with the given name in the current key
 * \param   pWalker          walker to query
 * \param   name             name of value to delete
 */
extern void
ci_regWalkerDeleteNamedValue(RegWalker *pWalker, WCHAR *name);


/*! Methods to iterate through all values in a key */

/*! Start an iteration through the current key
 * \param   pWalker          walker to setup for iteration
 */
extern void
ci_regWalkerIterStart(RegWalker *pWalker);

/*! Get the value the iterator currently points to
 * \param   pWalker          walker iterator
 * \return  pointer to KEY_VALUE_FULL_INFORMATION object containing data, or
 *          NULL if no values remaining.
 * Note that the memory pointed to by the return value is owned by the walker
 * and should not be deleted.
 */
extern KEY_VALUE_FULL_INFORMATION *
ci_regWalkerIterGet(RegWalker *pWalker);

/*! Delete the value the iterator currently points to. This implicitly advances
 * the iterator to the next key.
 * \param   pWalker          walker iterator
 */
extern void
ci_regWalkerIterDelete(RegWalker *pWalker);

/*! Advance the given walker iterator to the next value in the key
 * \param   pWalker          walker iterator
 */
extern void
ci_regWalkerIterAdvance(RegWalker *pWalker);


/*! Methods to handle higher level structures */

/*! For persistent logins we store the following struct in the registry */
typedef struct {
  ci_iscsi_session_params session;
  ci_iscsi_connection_params connection;
  ci_iscsi_lun_map luns;
} ci_iscsi_login_info;

/*! Report the login info pointed to by the walker iterator.
 * Note this method will delete any "corrupted" entries, so it must not be
 * called on keys that have any valid values that are not login infos.
 * \param   pWalker          walker iterator
 * \return  login info pointed to by iterator, or NULL if there are no more
 * Note that the memory pointed to by the return value is owned by the walker
 * and should not be deleted.
 */
extern ci_iscsi_login_info *
ci_regWalkerIterGetLoginInfo(RegWalker *pWalker);

/*! Find the mac address value with the given name in the current key
 * \param   pWalker          walker to query
 * \param   name             name of value to get
 * \param   pValue           location to store retrieved value
 * \return  0 => success
 *          1 => could not find specified value
 */
extern int
ci_regWalkerGetNamedMac(RegWalker *pWalker, WCHAR *name, UCHAR value[6]);

/*! Set the value with the given name in the current key to the a mac address
 * \param   pWalker          walker to query
 * \param   name             name of value to set
 * \param   value            mac address
 */
extern void
ci_regWalkerSetNamedMac(RegWalker *pWalker, WCHAR *name, UCHAR value[6]);



#endif //#ifndef __CI_ISCSI_REG_WALKER_H__
