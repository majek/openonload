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

/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains /proc/driver/sfc_resource/ implementation.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#include <ci/efrm/debug.h>
#include <ci/efrm/driver_private.h>
#include <ci/efrm/kernel_proc.h>
#include <linux/proc_fs.h>

/** Top level directory for sfc specific stats **/
static struct proc_dir_entry *efrm_proc_root = NULL;
static struct proc_dir_entry *efrm_proc_resources = NULL;

/** Subdirectories (interfaces) **/
struct efrm_procdir_s {
	char efrm_pd_name [IFNAMSIZ];
	int efrm_pd_refcount;
	struct efrm_procdir_s* efrm_pd_next;
/*	int efrm_pd_access_mode; */
	struct efrm_file_s* efrm_pd_child;
	struct proc_dir_entry* efrm_pd_dir;
};
struct efrm_file_s {
	struct efrm_procdir_s* efrm_pf_parent;
	char efrm_pf_name [IFNAMSIZ];
	struct efrm_file_s* efrm_pf_next;
	struct proc_dir_entry* efrm_pf_file;
};
struct efrm_procdir_s* efrm_pd_root = NULL;
static DEFINE_MUTEX(efrm_pd_mutex);

/****************************************************************************
 *
 * /proc/drivers/sfc/ethX/
 *
 ****************************************************************************/

void efrm_pd_set_owner( struct proc_dir_entry* dir_entry )
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
	dir_entry->owner = THIS_MODULE;
#endif
}

efrm_pd_handle efrm_proc_dir_get(char const* dirname)
{
	/* Acquire a handle to a directory; creates the directory if needed */
	struct efrm_procdir_s* rval = NULL;
	struct efrm_procdir_s* procdir;
	if( !efrm_proc_root ) {
		EFRM_ERR( "%s: Creating subdirectory %s before root.\n",
		          __func__, dirname );
		return NULL;
	}
	
	if ( !dirname )
		return 0;
	
	mutex_lock( &efrm_pd_mutex );
	procdir = efrm_pd_root;
	
	/* Does it already exist? If so, increment the refcount */
	while ( procdir ) {
		if ( procdir->efrm_pd_name
		     && !strcmp(procdir->efrm_pd_name, dirname) ) {
			procdir->efrm_pd_refcount++;
			rval = procdir;
			break;
		}
		procdir = procdir->efrm_pd_next;
	}
	
	/* Entry doesn't exist?  Create it */
	if ( !rval ) {
		rval = (struct efrm_procdir_s*) kmalloc(
				sizeof(struct efrm_procdir_s), GFP_KERNEL );
		if ( rval ) {
			/* Create the directory */
			rval->efrm_pd_dir = proc_mkdir(dirname, efrm_proc_root);
			if ( rval->efrm_pd_dir ) {
				rval->efrm_pd_refcount = 1;
				rval->efrm_pd_next = efrm_pd_root;
				rval->efrm_pd_child = NULL;
				efrm_pd_root = rval;
				strlcpy( rval->efrm_pd_name, dirname, IFNAMSIZ);
			}
			else {
				/* Failed to create actual directory,
				   don't leave the table hanging around */
				kfree( rval );
				rval = NULL;
			}
		}
	}
	
	mutex_unlock( &efrm_pd_mutex );
	return (efrm_pd_handle) rval;
}

int efrm_proc_dir_put(efrm_pd_handle pd_handle)
{
	/* Release handle to directory, removes directory if not in use. */
	struct efrm_procdir_s* handle = (struct efrm_procdir_s*) pd_handle;
	struct efrm_procdir_s* procdir;
	struct efrm_procdir_s* prev = NULL;
	int rval = -EINVAL;
	
	if ( !pd_handle ) return rval;
	
	mutex_lock( &efrm_pd_mutex );
	procdir = efrm_pd_root;
	
	/* Check provided procdir actually exists */
	while ( procdir ) {
		if ( procdir == handle ) {
			/* Decrement refcount, and remove if zero */
			procdir->efrm_pd_refcount--;
			if ( !procdir->efrm_pd_refcount ) {
				if ( prev ) {
					prev->efrm_pd_next =
							procdir->efrm_pd_next;
				}
				else {
					efrm_pd_root = procdir->efrm_pd_next;
				}
				/* Delete the directory and table entry*/
				/* TODO: Warn if it still has files in it */
				remove_proc_entry(procdir->efrm_pd_dir->name,
						procdir->efrm_pd_dir->parent);
				kfree( procdir );
			}
			rval = 0;
			break;
		} else {
			prev = procdir;
			procdir = procdir->efrm_pd_next;
		}
	}
	
	mutex_unlock( &efrm_pd_mutex );
	return rval;
}

efrm_pd_handle
efrm_proc_create_file( char const* name, mode_t mode, efrm_pd_handle parent,
                       read_proc_t* read_proc, write_proc_t* write_proc,
                       void* context )
{
	/* Tracking the files within a /proc/ directory. */
	struct proc_dir_entry* entry;
	struct efrm_procdir_s* handle = (struct efrm_procdir_s*) parent;
	struct proc_dir_entry* root;
	struct efrm_file_s* rval = NULL;
	
	mutex_lock( &efrm_pd_mutex );
	
	root = handle ? handle->efrm_pd_dir : efrm_proc_root;
	if ( !root ) {
		EFRM_WARN("%s: Creating %s before init.", __func__, name );
		goto done_create_file;
	}
	
	rval = kmalloc( sizeof(struct efrm_file_s), GFP_KERNEL );
	if ( !rval ) {
		EFRM_WARN("%s: Out of memory", __func__);
		goto done_create_file;
	}
	rval->efrm_pf_parent = handle;
	strlcpy( rval->efrm_pf_name, name, IFNAMSIZ );
	rval->efrm_pf_next = handle ? handle->efrm_pd_child : NULL;
	
	entry = create_proc_entry( name, mode, root );
	if ( !entry ) {
		EFRM_WARN("%s: Unable to create procfile %s", __func__, name);
		kfree( rval );
		rval = NULL;
	}
	else {
		entry->data = context;
		entry->read_proc = read_proc;
		entry->write_proc = write_proc;
		efrm_pd_set_owner(entry);
		rval->efrm_pf_file = entry;
		if ( handle ) {
			rval->efrm_pf_next = handle->efrm_pd_child;
			handle->efrm_pd_child = rval;
		}
	}

done_create_file:
	mutex_unlock( &efrm_pd_mutex );
	return rval;
}

void
efrm_proc_remove_file( efrm_pd_handle handle )
{
	/* Tracking the files within a /proc/ directory. */
	struct efrm_file_s* entry = (struct efrm_file_s*) handle;
	struct efrm_procdir_s* parent;

	mutex_lock( &efrm_pd_mutex );

	if ( entry && entry->efrm_pf_file ) {
		remove_proc_entry( entry->efrm_pf_name,
		                   entry->efrm_pf_file->parent );
		parent = entry->efrm_pf_parent;
		if ( parent ) {
			/* remove ourselves from the list of children */
			struct efrm_file_s* prev = parent->efrm_pd_child;
			struct efrm_file_s* after = entry->efrm_pf_next;
			if ( prev == entry ) {
				parent->efrm_pd_child = entry->efrm_pf_next;
			}
			else {
				while ( prev ) {
					if ( prev->efrm_pf_next == entry ) {
						prev->efrm_pf_next = after;
						break;
					}
					prev = prev->efrm_pf_next;
				}
			}
		}
	}
	if ( entry )
		kfree( entry );
	
	mutex_unlock( &efrm_pd_mutex );
}

static int efrm_proc_dir_check_all_removed(void)
{
	/* Check there are no directories hanging around. */
	int rval = 1;
	struct efrm_procdir_s* procdir;
	mutex_lock( &efrm_pd_mutex );
	
	procdir = efrm_pd_root;
	
	while ( procdir ) {
		/* If it's better to remove them */
		struct efrm_procdir_s* next = procdir->efrm_pd_next;
		rval = 0;
		/* Which is worse, to leak these, or to destroy them while
		   somthing is holding a handle? */
		remove_proc_entry(procdir->efrm_pd_dir->name,
		                  procdir->efrm_pd_dir->parent);
		/* Delete the table entry*/
		kfree( procdir );
		procdir = next;
	}
	
	efrm_pd_root = NULL;
	mutex_unlock( &efrm_pd_mutex );
	return rval;
}

/****************************************************************************
 *
 * /proc/drivers/sfc/resources
 *
 ****************************************************************************/


static int
efrm_resource_read_proc(char *buf, char **start, off_t offset, int count,
			int *eof, void *data);

int efrm_install_proc_entries(void)
{
	int rc = 0;
	mutex_lock( &efrm_pd_mutex );
	if ( !efrm_proc_root ) {
		/* create the top-level directory for etherfabric specific stuff */
		efrm_proc_root = proc_mkdir("driver/sfc_resource", NULL);
		if (!efrm_proc_root) {
			rc = -ENOMEM;
		}
		else {
			efrm_pd_set_owner(efrm_proc_root);
			efrm_proc_resources = create_proc_read_entry(
					"resources", 0, efrm_proc_root,
					efrm_resource_read_proc, 0);
			if ( efrm_proc_resources ) {
				efrm_pd_set_owner(efrm_proc_resources);
			}
			else {
				EFRM_WARN("%s: Unable to create /proc/drivers/"
					  "sfc_resource/resources", __func__);
			}
		}
	}
	mutex_unlock( &efrm_pd_mutex );
	return rc;
}

int efrm_uninstall_proc_entries(void)
{
	int rc = 0;
	
	if ( !efrm_proc_dir_check_all_removed() ) {
		return -EPERM;
	}

	mutex_lock( &efrm_pd_mutex );

	if ( !efrm_proc_root ) {
		rc = -EPERM;
		goto done_efrm_uninstall_proc_entries;
	}

	if ( efrm_proc_resources )
		remove_proc_entry(efrm_proc_resources->name, efrm_proc_root);
	efrm_proc_resources = NULL;
	if ( efrm_proc_root )
		remove_proc_entry(efrm_proc_root->name, efrm_proc_root->parent);
	efrm_proc_root = NULL;

done_efrm_uninstall_proc_entries:
	mutex_unlock( &efrm_pd_mutex );
	return rc;
}

/****************************************************************************
 *
 * /proc/drivers/sfc/resources
 *
 ****************************************************************************/

#define EFRM_PROC_PRINTF(buf, len, fmt, ...)				\
	do {								\
		if (count - len > 0)					\
			len += snprintf(buf+len, count-len, (fmt),	\
					__VA_ARGS__);			\
	} while (0)

static int
efrm_resource_read_proc(char *buf, char **start, off_t offset, int count,
			int *eof, void *data)
{
	int len = 0;
	int type;
	struct efrm_resource_manager *rm;

	for (type = 0; type < EFRM_RESOURCE_NUM; type++) {
		rm = efrm_rm_table[type];
		if (rm == NULL)
			continue;

		EFRM_PROC_PRINTF(buf, len, "*** %s ***\n", rm->rm_name);

		spin_lock_bh(&rm->rm_lock);
		EFRM_PROC_PRINTF(buf, len, "current = %u\n", rm->rm_resources);
		EFRM_PROC_PRINTF(buf, len, "    max = %u\n\n",
				 rm->rm_resources_hiwat);
		spin_unlock_bh(&rm->rm_lock);
	}

	return count ? strlen(buf) : 0;
}

