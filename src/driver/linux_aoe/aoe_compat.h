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

#ifndef AOE_COMPAT_H
#define AOE_COMPAT_H

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
#include <linux/autoconf.h>
#endif
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/i2c.h>
#include <linux/sysfs.h>
#include <linux/stringify.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/cpumask.h>
#include <linux/topology.h>
#include <linux/ethtool.h>
#include <linux/vmalloc.h>
#include <linux/time.h>

#include "autocompat.h"
#include <kernel_compat.h>


#ifdef DEBUG
#define AOE_BUG_ON_PARANOID(x) BUG_ON(x)
#define AOE_WARN_ON_PARANOID(x) WARN_ON(x)
#else
#define AOE_BUG_ON_PARANOID(x) do {} while (0)
#define AOE_WARN_ON_PARANOID(x) do {} while (0)
#endif


#ifdef AOE_NEED_KOBJECT_INIT_AND_ADD
	#undef kobject_init_and_add
	#define kobject_init_and_add aoe_kobject_init_and_add
	extern int
	aoe_kobject_init_and_add(struct kobject *kobj, struct kobj_type *ktype,
				 struct kobject *parent, const char *fmt, ...);
#endif

#ifdef AOE_NEED_KOBJECT_SET_NAME_VARGS
	#undef kobject_set_name_vargs
	#define kobject_set_name_vargs aoe_kobject_set_name_vargs
	extern int
	kobject_set_name_vargs(struct kobject *kobj, const char *fmt, va_list vargs);
#endif

#ifdef AOE_NEED_ROOT_DEVICE_REGISTER
#define aoe_root_device_register(_name) \
	__aoe_root_device_register(_name, THIS_MODULE)

extern struct device * __aoe_root_device_register(const char *name, struct module *owner);

void aoe_root_device_unregister(struct device *dev);

extern void device_destroy(struct class *class, dev_t devt);

#else
#define aoe_root_device_register(_name) \
	root_device_register(_name)
#define aoe_root_device_unregister(_dev) \
	root_device_unregister(_dev)
#define aoe_device_destroy(_dev_t) \
	device_destroy(_dev_t)

#endif /* AOE_NEED_ROOT_DEVICE_REGISTER */

#ifdef AOE_HAVE_PARAM_BOOL_INT
	#undef param_ops_bool
        #define param_ops_bool aoe_param_ops_bool
        extern int aoe_param_set_bool(const char *val, struct kernel_param *kp);
	#undef param_set_bool
        #define param_set_bool aoe_param_set_bool
        extern int aoe_param_get_bool(char *buffer, struct kernel_param *kp);
	#undef param_get_bool
        #define param_get_bool aoe_param_get_bool
        #undef param_check_bool
        #define param_check_bool(name, p) __param_check(name, p, bool)
#endif

#ifdef AOE_NEED_TIMESPEC_ADD
	#undef timespec_add
	#define timespec_add aoe_timespec_add
	extern struct timespec aoe_timespec_add(struct timespec lhs,
						struct timespec rhs);
#endif /* AOE_NEED_TIMESPEC_ADD */

#ifdef AOE_NEED_NS_TO_TIMESPEC
	#undef ns_to_timespec
	#define ns_to_timespec aoe_ns_to_timespec
	extern struct timespec ns_to_timespec(const s64 nsec);
#endif /* AOE_NEED_NS_TO_TIMESPEC */

#ifdef AOE_NEED_TIMESPEC_ADD_NS
	#undef timespec_add_ns
	#define timespec_add_ns aoe_timespec_add_ns
	static inline void aoe_timespec_add_ns(struct timespec *a, u64 ns)
	{
		ns += a->tv_nsec;
		while(unlikely(ns >= NSEC_PER_SEC)) {
			ns -= NSEC_PER_SEC;
			a->tv_sec++;
		}
		a->tv_nsec = ns;
	}
#endif /* AOE_NEED_TIMESPEC_ADD_NS */

#ifdef AOE_NEED_TIMESPEC_SUB
	#undef timespec_sub
	#define timespec_sub aoe_timespec_sub
	static inline struct timespec timespec_sub(struct timespec lhs,
						   struct timespec rhs)
	{
		struct timespec ts_delta;
		set_normalized_timespec(&ts_delta, lhs.tv_sec - rhs.tv_sec,
		lhs.tv_nsec - rhs.tv_nsec);
		return ts_delta;
	}

#endif /* AOE_NEED_TIMESPEC_SUB */

#ifdef AOE_NEED_TIMESPEC_COMPARE
	#undef timespec_compare
	#define timespec_compare aoe_timespec_compare
	static inline int aoe_timespec_compare(struct timespec *lhs,
					       struct timespec *rhs)
	{
		if (lhs->tv_sec < rhs->tv_sec)
			return -1;
		if (lhs->tv_sec > rhs->tv_sec)
			return 1;
		return lhs->tv_nsec - rhs->tv_nsec;
	}
#endif /* AOE_NEED_TIMESPEC_COMPARE */

#ifdef AOE_NEED_IS_ERR_OR_NULL
	static inline long __must_check IS_ERR_OR_NULL(const void *ptr)
	{
		return !ptr || IS_ERR_VALUE((unsigned long)ptr);
	}	
#endif /* AOE_NEED_IS_ERR_OR_NULL */

#endif /* AOE_COMPAT_H */
