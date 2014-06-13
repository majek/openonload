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
 * Copyright 2006-2013 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "aoe_compat.h"



#ifdef AOE_NEED_KOBJECT_SET_NAME_VARGS
int kobject_set_name_vargs(struct kobject *kobj, const char *fmt, va_list vargs)
{
	char *s;
	int need;
	int limit;
	char *name;
	const char *old_name;
	va_list cvargs;

	if (kobject_name(kobj) && !fmt)
		return 0;

	va_copy(cvargs, vargs);
	need = vsnprintf(NULL, 0, fmt, cvargs);
	va_end(cvargs);

	/* 
	 * Need more space? Allocate it and try again 
	 */
	limit = need + 1;
	name = kmalloc(limit,GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	vsnprintf(name,limit,fmt,vargs);

	/* ewww... some of these buggers have '/' in the name ... */
	while ((s = strchr(name, '/')))
		s[0] = '!';

	/* Free the old name, if necessary. */
	old_name = kobject_name(kobj);
	if (old_name && (old_name != name))
		kfree(old_name);

	/* Now, set the new name */
	kobject_set_name(kobj, name);

	return 0;
}
#endif /* AOE_NEED_KOBJECT_SET_NAME_VARGS */

#ifdef AOE_NEED_KOBJECT_INIT_AND_ADD
int aoe_kobject_init_and_add(struct kobject *kobj, struct kobj_type *ktype,
		struct kobject *parent, const char *fmt, ...)
{
	int retval;
	va_list args;

	BUG_ON(!kobj || !ktype || atomic_read(&kobj->kref.refcount));

	kref_init(&kobj->kref);
	INIT_LIST_HEAD(&kobj->entry);
	kobj->ktype = ktype;

	va_start(args, fmt);
	retval = kobject_set_name_vargs(kobj, fmt, args);
	va_end(args);

	if (retval) {
		printk(KERN_ERR "kobject: can not set name properly!\n");
		return retval;
	}
	kobj->parent = parent;
	return kobject_add(kobj);
}

#endif /* AOE_NEED_KOBJECT_INIT_AND_ADD */

#ifdef AOE_NEED_ROOT_DEVICE_REGISTER
struct root_device {
	struct device dev;
	struct module *owner;
};


inline struct root_device *to_root_device(struct device *d)
{
	return container_of(d, struct root_device, dev);
}

static void root_device_release(struct device *dev)
{
	kfree(to_root_device(dev));
}

struct device * __aoe_root_device_register(const char *name, struct module *owner)
{
	struct root_device *root;
	int err = -ENOMEM;

	root = kzalloc(sizeof(struct root_device), GFP_KERNEL);
	if (!root)
		return ERR_PTR(err);

	/* device_register() needs the bus_id set to name this device.
	 * This behaviour is changed in later kernel versions that have __root_device_register.
	 */
        snprintf(root->dev.bus_id, sizeof(root->dev.bus_id), "%s", name);

	root->dev.release = root_device_release;

	err = device_register(&root->dev);
	if (err) {
		put_device(&root->dev);
		return ERR_PTR(err);
	}

#ifdef CONFIG_MODULES   /* gotta find a "cleaner" way to do this */
	if (owner) {
#ifdef AOE_HAVE_OLD_STRUCT_MODULE_MKOBJ_PTR
		struct module_kobject *mk =  owner->mkobj;
#else
		struct module_kobject *mk = &owner->mkobj;
#endif
		err = sysfs_create_link(&root->dev.kobj, &mk->kobj, "module");
		if (err) {
			device_unregister(&root->dev);
			return ERR_PTR(err);
		}
		root->owner = owner;
	}
#endif

	return &root->dev;
}

void aoe_root_device_unregister(struct device *dev)
{
	struct root_device *root = to_root_device(dev);

	if (root->owner)
		sysfs_remove_link(&root->dev.kobj, "module");

	device_unregister(dev);
}
#endif /* AOE_NEED_ROOT_DEVICE_REGISTER */

#ifdef AOE_HAVE_PARAM_BOOL_INT

int aoe_param_set_bool(const char *val, struct kernel_param *kp)
{
	bool v;

	if (!val) {
		/* No equals means "set"... */
		v = true;
	} else {
		/* One of =[yYnN01] */
		switch (val[0]) {
		case 'y':
		case 'Y':
		case '1':
			v = true;
			break;
		case 'n':
		case 'N':
		case '0':
			v = false;
			break;
		default:
			return -EINVAL;
		}
	}

	*(bool *)kp->arg = v;
	return 0;
}
EXPORT_SYMBOL(aoe_param_set_bool);

int aoe_param_get_bool(char *buffer, struct kernel_param *kp)
{
	/* Y and N chosen as being relatively non-coder friendly */
	return sprintf(buffer, "%c", *(bool *)kp->arg ? 'Y' : 'N');
}
EXPORT_SYMBOL(aoe_param_get_bool);

#endif /* AOE_HAVE_PARAM_BOOL_INT */

#ifdef AOE_NEED_TIMESPEC_ADD
struct timespec aoe_timespec_add(struct timespec lhs,
				 struct timespec rhs)
{
	struct timespec ts_delta;
	set_normalized_timespec(&ts_delta, lhs.tv_sec + rhs.tv_sec,
				lhs.tv_nsec + rhs.tv_nsec);
	return ts_delta;
}
#endif /* AOE_NEED_TIMESPEC_ADD */

#ifdef AOE_NEED_NS_TO_TIMESPEC

#ifdef AOE_HAVE_DIV_S64_REM
#include <linux/math64.h>
#else
#undef div_s64_rem
#define div_s64_rem aoe_div_s64_rem
static inline s64 aoe_div_s64_rem(s64 dividend, s32 divisor, s32 *rem32)
{
	s64 res;
	long remainder;

	/*
	 * This implementation has the same limitations as
	 * div_long_long_rem_signed().  However these should not
	 * affect its use by ns_to_timespec().  (By 2038 this driver,
	 * the relevant kernel versions and 32-bit PCs should be long
	 * obsolete.)
	 */
	AOE_BUG_ON_PARANOID(divisor < 0);

	if (unlikely(dividend < 0)) {
		AOE_BUG_ON_PARANOID(-dividend >> 31 >= divisor);
		res = -div_long_long_rem(-dividend, divisor, &remainder);
		*rem32 = -remainder;
	} else {
		AOE_BUG_ON_PARANOID(dividend >> 31 >= divisor);
		res = div_long_long_rem(dividend, divisor, &remainder);
		*rem32 = remainder;
	}
	return res;
}
#endif

struct timespec aoe_ns_to_timespec(const s64 nsec)
{
	struct timespec ts;
	s32 rem;

	if (!nsec)
		return (struct timespec) {0, 0};

	ts.tv_sec = div_s64_rem(nsec, NSEC_PER_SEC, &rem);
	if (unlikely(rem < 0)) {
		ts.tv_sec--;
		rem += NSEC_PER_SEC;
	}
	ts.tv_nsec = rem;

	return ts;
}

#endif /* AOE_NEED_NS_TO_TIMESPEC */
