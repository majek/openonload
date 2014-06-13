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

/****************************************************************************
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2012 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/sysfs.h>
#include <linux/poll.h>
#include <linux/sched.h>

#include "aoe.h"

static struct aoe_parent_dev aoe_parent;
struct aoe_parent_dev *aoe_parent_p = &aoe_parent;

extern struct file_operations aoe_file_ops;

static int __init aoe_init_module(void)
{
	int retval;

	memset(&aoe_parent, 0, sizeof(aoe_parent));

	retval = register_chrdev(0, AOE_NAME, (struct file_operations*)&aoe_file_ops);
	if (!retval)
		goto out1;

	aoe_parent_p->aoe_major = retval;

	aoe_parent_p->aoe_class = class_create(THIS_MODULE, AOE_NAME);
	if (IS_ERR_OR_NULL(aoe_parent_p->aoe_class)) {
		printk(KERN_ERR "sfc_aoe: Unable to create class %s\n", AOE_NAME);
		retval = PTR_ERR(aoe_parent_p->aoe_class);
		goto out2;
	}

	aoe_parent_p->aoe_dev = aoe_root_device_register(AOE_NAME);

	if (IS_ERR_OR_NULL(aoe_parent_p->aoe_dev)) {
		printk(KERN_ERR "sfc_aoe: Unable to create device %s\n", AOE_NAME);
		retval = PTR_ERR(aoe_parent_p->aoe_dev);
		goto out3;
	}

	retval = aoe_device_setup();
	if (retval) {
		printk(KERN_ERR "sfc_aoe: No AOE Devices created\n");
		goto out4;
	}

	printk(KERN_INFO "sfc_aoe: AOE Extension Driver loaded\n");

	return 0;

out4:
	aoe_root_device_unregister(aoe_parent_p->aoe_dev);
out3:
	class_unregister(aoe_parent_p->aoe_class);
	class_destroy(aoe_parent_p->aoe_class);
out2:
	unregister_chrdev(aoe_parent_p->aoe_major, AOE_NAME);
out1:
	printk(KERN_ERR "sfc_aoe: AOE Driver load failed\n");
	return retval;
}
module_init(aoe_init_module);

static void __exit aoe_exit_module(void)
{
	aoe_root_device_unregister(aoe_parent_p->aoe_dev);

	if (aoe_parent_p->aoe_class) {
		class_unregister(aoe_parent_p->aoe_class);
		class_destroy(aoe_parent_p->aoe_class);
	}

	if (aoe_parent_p->aoe_major)
		unregister_chrdev(aoe_parent_p->aoe_major, AOE_NAME);

	/* Unregister with driverlink in linux_net */

	aoe_device_close();

	printk(KERN_INFO "sfc_aoe: AOE Driver unloaded\n");
}
module_exit(aoe_exit_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Solarflare Communications and "
              "Stuart Hodgson <support@solarflare.com>");
MODULE_VERSION(AOE_DRIVER_VERSION);
