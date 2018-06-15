/*
** Copyright 2005-2018  Solarflare Communications Inc.
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

/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/module.h>
#ifndef EFX_USE_KCOMPAT
#include <linux/mtd/mtd.h>
#else
#include "linux_mtd_mtd.h"
#endif
#include <linux/slab.h>
#ifndef EFX_USE_KCOMPAT
#include <linux/rtnetlink.h>
#endif

#include "net_driver.h"
#include "efx.h"

/* Some partitions should only be written during manufacturing.  Not
 * only should they not be rewritten later, but exposing all of them
 * can easily fill up the MTD table (16 or 32 entries).
 */
bool efx_allow_nvconfig_writes;
#ifdef EFX_NOT_UPSTREAM
module_param(efx_allow_nvconfig_writes, bool, 0644);
MODULE_PARM_DESC(efx_allow_nvconfig_writes,
		 "Allow access to static config and backup firmware");
#endif /* EFX_NOT_UPSTREAM */

/* MTD interface */

static int efx_mtd_erase(struct mtd_info *mtd, struct erase_info *erase)
{
	struct efx_mtd_partition *part = mtd->priv;
	struct efx_nic *efx = part->efx;
	int rc;

	rc = efx->type->mtd_erase(mtd, erase->addr, erase->len);
#if defined(EFX_USE_KCOMPAT) && defined(MTD_ERASE_DONE)
	erase->state = rc ? MTD_ERASE_FAILED : MTD_ERASE_DONE;
	mtd_erase_callback(erase);
#endif
	return rc;
}

static void efx_mtd_sync(struct mtd_info *mtd)
{
	struct efx_mtd_partition *part = mtd->priv;
	struct efx_nic *efx = part->efx;
	int rc;

	rc = efx->type->mtd_sync(mtd);
	if (rc)
		pr_err("%s: %s sync failed (%d)\n",
		       part->name, part->dev_type_name, rc);
}

#ifdef EFX_NOT_UPSTREAM
/* Free the MTD device after all references have gone away. */
static void efx_mtd_release_partition(struct device *dev)
{
	struct mtd_info *mtd = dev_get_drvdata(dev);
	struct efx_mtd_partition *part = mtd->priv;
	struct efx_nic *efx;

	/* Call mtd_release to remove the /dev/mtdXro node */
	if (dev->type && dev->type->release)
		(dev->type->release)(dev);

	list_del(&part->node);

	/* Free memory if all MTD devices have been removed */
	efx = part->efx;
	if (list_empty(&efx->mtd_list)) {
		kfree(efx->mtd_parts);
		efx->mtd_parts = NULL;
	}
}
#endif

static void efx_mtd_remove_partition(struct efx_mtd_partition *part)
{
	int rc;

	for (;;) {
		rc = mtd_device_unregister(&part->mtd);
		if (rc != -EBUSY)
			break;
		ssleep(1);
	}
	WARN_ON(rc);
#ifndef EFX_NOT_UPSTREAM
	list_del(&part->node);
#endif
}

int efx_mtd_add(struct efx_nic *efx, struct efx_mtd_partition *parts,
		size_t n_parts)
{
	struct efx_mtd_partition *part;
	size_t i;

	efx->mtd_parts = parts;

	for (i = 0; i < n_parts; i++) {
		part = &parts[i];
		part->efx = efx;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_MTD_WRITESIZE)
		if (!part->mtd.writesize)
			part->mtd.writesize = 1;
#endif
		if (efx_allow_nvconfig_writes)
			part->mtd.flags |= MTD_WRITEABLE;

		part->mtd.owner = THIS_MODULE;
		part->mtd.priv = part;
		part->mtd.name = part->name;
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_MTD_DIRECT_ACCESS)
		part->mtd.erase = efx_mtd_erase;
		part->mtd.read = efx->type->mtd_read;
		part->mtd.write = efx->type->mtd_write;
		part->mtd.sync = efx_mtd_sync;
#else
		part->mtd._erase = efx_mtd_erase;
		part->mtd._read = efx->type->mtd_read;
		part->mtd._write = efx->type->mtd_write;
		part->mtd._sync = efx_mtd_sync;
#endif

		efx->type->mtd_rename(part);

		if (mtd_device_register(&part->mtd, NULL, 0))
			goto fail;

#ifdef EFX_NOT_UPSTREAM
		/* The core MTD functionality does not comply completely with
		 * the device API. When it does we may need to change the way
		 * our data is cleaned up.
		 */
		WARN_ON_ONCE(part->mtd.dev.release);
		part->mtd.dev.release = efx_mtd_release_partition;
#endif

		/* Add to list in order - efx_mtd_remove() depends on this */
		list_add_tail(&part->node, &efx->mtd_list);
	}

	return 0;

fail:
	while (i--)
		efx_mtd_remove_partition(&parts[i]);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_MTD_TABLE)
	/* The number of MTDs is limited (to 16 or 32 by default) and
	 * we probably reached that limit.
	 */
	return -EBUSY;
#else
	/* Failure is unlikely here, but probably means we're out of memory */
	return -ENOMEM;
#endif
}

void efx_mtd_remove(struct efx_nic *efx)
{
	struct efx_mtd_partition *part, *next;

	WARN_ON(efx_dev_registered(efx));

	if (list_empty(&efx->mtd_list))
		return;

	list_for_each_entry_safe(part, next, &efx->mtd_list, node)
		efx_mtd_remove_partition(part);
#ifndef EFX_NOT_UPSTREAM

	kfree(efx->mtd_parts);
	efx->mtd_parts = NULL;
#endif
}

void efx_mtd_rename(struct efx_nic *efx)
{
	struct efx_mtd_partition *part;

	ASSERT_RTNL();

	list_for_each_entry(part, &efx->mtd_list, node)
		efx->type->mtd_rename(part);
}
