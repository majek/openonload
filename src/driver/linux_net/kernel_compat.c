/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#define EFX_IN_KCOMPAT_C 1

#include "efx.h"
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/random.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/cpumask.h>
#include <asm/uaccess.h>
#ifdef EFX_HAVE_LINUX_EXPORT_H
#include <linux/export.h>
#endif
#if defined(EFX_NEED_HWMON_DEVICE_REGISTER_WITH_INFO)
#include <linux/hwmon.h>
#endif
#ifdef EFX_NEED_HASH_64
#include <asm/types.h>
#include <linux/compiler.h>
#endif

/*
 * Kernel backwards compatibility
 *
 * This file provides functionality missing from earlier kernels.
 */

#ifdef EFX_NEED_HEX_DUMP

/**************************************************************************
 *
 * print_hex_dump, taken from lib/hexdump.c.
 *
 **************************************************************************
 *
 */

#define hex_asc(x)	"0123456789abcdef"[x]
#ifndef isascii
#define isascii(c) (((unsigned char)(c)) <= 0x7f)
#endif

static void hex_dump_to_buffer(const void *buf, size_t len, int rowsize,
			       int groupsize, char *linebuf, size_t linebuflen,
			       int ascii)
{
	const u8 *ptr = buf;
	u8 ch;
	int j, lx = 0;
	int ascii_column;

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	if (!len)
		goto nil;
	if (len > rowsize)              /* limit to one line at a time */
		len = rowsize;
	if ((len % groupsize) != 0)     /* no mixed size output */
		groupsize = 1;

	switch (groupsize) {
	case 8: {
		const u64 *ptr8 = buf;
		int ngroups = len / groupsize;

		for (j = 0; j < ngroups; j++)
			lx += scnprintf(linebuf + lx, linebuflen - lx,
				"%16.16llx ", (unsigned long long)*(ptr8 + j));
		ascii_column = 17 * ngroups + 2;
		break;
	}

	case 4: {
		const u32 *ptr4 = buf;
		int ngroups = len / groupsize;

		for (j = 0; j < ngroups; j++)
			lx += scnprintf(linebuf + lx, linebuflen - lx,
				"%8.8x ", *(ptr4 + j));
		ascii_column = 9 * ngroups + 2;
		break;
	}

	case 2: {
		const u16 *ptr2 = buf;
		int ngroups = len / groupsize;

		for (j = 0; j < ngroups; j++)
			lx += scnprintf(linebuf + lx, linebuflen - lx,
				"%4.4x ", *(ptr2 + j));
		ascii_column = 5 * ngroups + 2;
		break;
	}

	default:
		for (j = 0; (j < rowsize) && (j < len) && (lx + 4) < linebuflen;
		     j++) {
			ch = ptr[j];
			linebuf[lx++] = hex_asc(ch >> 4);
			linebuf[lx++] = hex_asc(ch & 0x0f);
			linebuf[lx++] = ' ';
		}
		ascii_column = 3 * rowsize + 2;
		break;
	}
	if (!ascii)
		goto nil;

	while (lx < (linebuflen - 1) && lx < (ascii_column - 1))
		linebuf[lx++] = ' ';
	/* Removed is_print() check */
	for (j = 0; (j < rowsize) && (j < len) && (lx + 2) < linebuflen; j++)
		linebuf[lx++] = isascii(ptr[j]) ? ptr[j] : '.';
nil:
	linebuf[lx++] = '\0';
}

void print_hex_dump(const char *level, const char *prefix_str, int prefix_type,
		    int rowsize, int groupsize,
		    const void *buf, size_t len, int ascii)
{
	const u8 *ptr = buf;
	int i, linelen, remaining = len;
	char linebuf[200];

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	for (i = 0; i < len; i += rowsize) {
		linelen = min(remaining, rowsize);
		remaining -= rowsize;
		hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize,
				   linebuf, sizeof(linebuf), ascii);

		switch (prefix_type) {
		case DUMP_PREFIX_ADDRESS:
			printk("%s%s%*p: %s\n", level, prefix_str,
			       (int)(2 * sizeof(void *)), ptr + i, linebuf);
			break;
		case DUMP_PREFIX_OFFSET:
			printk("%s%s%.8x: %s\n", level, prefix_str, i, linebuf);
			break;
		default:
			printk("%s%s%s\n", level, prefix_str, linebuf);
			break;
		}
	}
}

#endif /* EFX_NEED_HEX_DUMP */

#ifdef EFX_NEED_USLEEP_RANGE

void usleep_range(unsigned long min, unsigned long max)
{
	unsigned long delay = DIV_ROUND_UP(min, 1000) ? : 1;
	msleep(delay);
}

#endif

#ifdef EFX_NEED_PCI_CLEAR_MASTER

void pci_clear_master(struct pci_dev *dev)
{
	u16 old_cmd, cmd;

	pci_read_config_word(dev, PCI_COMMAND, &old_cmd);
	cmd = old_cmd & ~PCI_COMMAND_MASTER;
	if (cmd != old_cmd) {
		dev_dbg(&dev->dev, "disabling bus mastering\n");
		pci_write_config_word(dev, PCI_COMMAND, cmd);
	}
	dev->is_busmaster = false;
}

#endif /* EFX_NEED_PCI_CLEAR_MASTER */


#ifdef EFX_NEED_PCI_WAKE_FROM_D3

#ifndef PCI_D3hot
#define PCI_D3hot 3
#endif

int pci_wake_from_d3(struct pci_dev *dev, bool enable)
{
	/* We always support waking from D3hot on boards that do WoL,
	 * so no need to check capabilities */
	return pci_enable_wake(dev, PCI_D3hot, enable);
}

#endif /* EFX_NEED_PCI_WAKE_FROM_D3 */

#if defined(EFX_NEED_UNMASK_MSIX_VECTORS) || \
    defined(EFX_NEED_SAVE_MSIX_MESSAGES)

#undef pci_save_state
#undef pci_restore_state

#include <linux/pci.h>

#define PCI_MSIX_TABLE         4
#define PCI_MSIX_PBA           8
#define  PCI_MSIX_BIR          0x7

#define PCI_MSIX_ENTRY_SIZE		16
#define  PCI_MSIX_ENTRY_LOWER_ADDR	0
#define  PCI_MSIX_ENTRY_UPPER_ADDR	4
#define  PCI_MSIX_ENTRY_DATA		8
#define  PCI_MSIX_ENTRY_VECTOR_CTRL	12

static void
efx_for_each_msix_vector(struct efx_nic *efx,
			 void (*fn)(struct efx_channel *, void __iomem *))
{
	struct pci_dev *pci_dev = efx->pci_dev;
	resource_size_t membase_phys;
	void __iomem *membase;
	int msix, offset, bar, length, i;
	u32 dword;

	if (efx->interrupt_mode != EFX_INT_MODE_MSIX)
		return;

	/* Find the location (bar, offset) of the MSI-X table */
	msix = pci_find_capability(pci_dev, PCI_CAP_ID_MSIX);
	if (!msix)
		return;
	pci_read_config_dword(pci_dev, msix + PCI_MSIX_TABLE, &dword);
	bar = dword & PCI_MSIX_BIR;
	offset = dword & ~PCI_MSIX_BIR;

	/* Map enough of the table for all our interrupts */
	membase_phys = pci_resource_start(pci_dev, bar);
	length = efx->n_channels * 0x10;
#if defined(EFX_USE_KCOMPAT)
	membase = efx_ioremap(membase_phys + offset, length);
#else
	membase = ioremap(membase_phys + offset, length);
#endif
	if (!membase) {
		dev_dbg(&pci_dev->dev, "failed to remap MSI-X table\n");
		return;
	}

	for (i = 0; i < efx->n_channels; i++)
		fn(efx_get_channel(efx, i), membase + i * PCI_MSIX_ENTRY_SIZE);

	/* Release the mapping */
	iounmap(membase);
}

static void
efx_save_msix_state(struct efx_channel *channel, void __iomem *entry)
{
#ifdef EFX_NEED_SAVE_MSIX_MESSAGES
	channel->msix_msg.address_lo = readl(entry + PCI_MSIX_ENTRY_LOWER_ADDR);
	channel->msix_msg.address_hi = readl(entry + PCI_MSIX_ENTRY_UPPER_ADDR);
	channel->msix_msg.data = readl(entry + PCI_MSIX_ENTRY_DATA);
#endif
#ifdef EFX_NEED_UNMASK_MSIX_VECTORS
	channel->msix_ctrl = readl(entry + PCI_MSIX_ENTRY_VECTOR_CTRL);
#endif
}

int efx_pci_save_state(struct pci_dev *pci_dev)
{
	efx_for_each_msix_vector(pci_get_drvdata(pci_dev), efx_save_msix_state);
	return pci_save_state(pci_dev);
}

static void
efx_restore_msix_state(struct efx_channel *channel, void __iomem *entry)
{
#ifdef EFX_NEED_SAVE_MSIX_MESSAGES
	writel(channel->msix_msg.address_lo, entry + PCI_MSIX_ENTRY_LOWER_ADDR);
	writel(channel->msix_msg.address_hi, entry + PCI_MSIX_ENTRY_UPPER_ADDR);
	writel(channel->msix_msg.data, entry + PCI_MSIX_ENTRY_DATA);
#endif
#ifdef EFX_NEED_UNMASK_MSIX_VECTORS
	writel(channel->msix_ctrl, entry + PCI_MSIX_ENTRY_VECTOR_CTRL);
#endif
}

void efx_pci_restore_state(struct pci_dev *pci_dev)
{
	pci_restore_state(pci_dev);
	efx_for_each_msix_vector(pci_get_drvdata(pci_dev),
				 efx_restore_msix_state);
}

#endif /* EFX_NEED_UNMASK_MSIX_VECTORS || EFX_NEED_SAVE_MSIX_MESSAGES */

#ifdef EFX_NEED_NS_TO_TIMESPEC
#ifndef EFX_HAVE_TIMESPEC64

#ifdef EFX_HAVE_DIV_S64_REM
#include <linux/math64.h>
#else
static inline s64 div_s64_rem(s64 dividend, s32 divisor, s32 *rem32)
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
	EFX_WARN_ON_ONCE_PARANOID(divisor < 0);

	if (unlikely(dividend < 0)) {
		EFX_WARN_ON_ONCE_PARANOID(-dividend >> 31 >= divisor);
		res = -div_long_long_rem(-dividend, divisor, &remainder);
		*rem32 = -remainder;
	} else {
		EFX_WARN_ON_ONCE_PARANOID(dividend >> 31 >= divisor);
		res = div_long_long_rem(dividend, divisor, &remainder);
		*rem32 = remainder;
	}
	return res;
}
#endif

struct timespec ns_to_timespec(const s64 nsec)
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

#endif /* EFX_HAVE_TIMESPEC64 */
#endif /* EFX_NEED_NS_TO_TIMESPEC */

#if defined(EFX_NEED_KTIME_SUB_NS) &&				\
	!(BITS_PER_LONG == 64 || defined(CONFIG_KTIME_SCALAR))
ktime_t ktime_sub_ns(const ktime_t kt, u64 nsec)
{
	ktime_t tmp;

	if (likely(nsec < NSEC_PER_SEC)) {
		tmp.tv64 = nsec;
	} else {
		unsigned long rem = do_div(nsec, NSEC_PER_SEC);

		tmp = ktime_set((long)nsec, rem);
	}

	return ktime_sub(kt, tmp);
}
#endif

#ifdef EFX_HAVE_PARAM_BOOL_INT

int efx_param_set_bool(const char *val, struct kernel_param *kp)
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
EXPORT_SYMBOL(efx_param_set_bool);

int efx_param_get_bool(char *buffer, struct kernel_param *kp)
{
	/* Y and N chosen as being relatively non-coder friendly */
	return sprintf(buffer, "%c", *(bool *)kp->arg ? 'Y' : 'N');
}
EXPORT_SYMBOL(efx_param_get_bool);

#endif /* EFX_HAVE_PARAM_BOOL_INT */

#ifdef EFX_NEED_KOBJECT_SET_NAME_VARGS
int efx_kobject_set_name_vargs(struct kobject *kobj, const char *fmt, va_list vargs)
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
	need = vsnprintf(NULL, 0, fmt, vargs);
	va_end(cvargs);

	/*
	 * Need more space? Allocate it and try again
	 */
	limit = need + 1;
	name = kmalloc(limit, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	vsnprintf(name, limit, fmt, vargs);

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
#endif /* EFX_NEED_KOBJECT_SET_NAME_VARGS */

#ifdef EFX_NEED_KOBJECT_INIT_AND_ADD
int efx_kobject_init_and_add(struct kobject *kobj, struct kobj_type *ktype,
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

#endif /* EFX_NEED_KOBJECT_INIT_AND_ADD */

#ifndef EFX_HAVE_PCI_VFS_ASSIGNED
int pci_vfs_assigned(struct pci_dev *dev)
{
#if defined(CONFIG_PCI_ATS) && defined(EFX_HAVE_PCI_DEV_FLAGS_ASSIGNED)
	struct pci_dev *vfdev;
	int pos;
	unsigned int vfs_assigned = 0;
	unsigned short dev_id;

	/* only search if we are a PF */
	if (!dev->is_physfn)
		return 0;

	pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return 0;

	/*
	 * determine the device ID for the VFs, the vendor ID will be the
	 * same as the PF so there is no need to check for that one
	 */
	pci_read_config_word(dev, pos + PCI_SRIOV_VF_DID, &dev_id);

	/* loop through all the VFs to see if we own any that are assigned */
	vfdev = pci_get_device(dev->vendor, dev_id, NULL);
	while (vfdev) {
		/*
		 * It is considered assigned if it is a virtual function with
		 * our dev as the physical function and the assigned bit is set
		 */
		if (vfdev->is_virtfn && (vfdev->physfn == dev) &&
		    (vfdev->dev_flags & PCI_DEV_FLAGS_ASSIGNED))
			vfs_assigned++;

		vfdev = pci_get_device(dev->vendor, dev_id, vfdev);
	}

	return vfs_assigned;
#else
	return 0;
#endif
}
EXPORT_SYMBOL_GPL(pci_vfs_assigned);
#endif

#ifdef EFX_NEED_PCI_ENABLE_MSIX_RANGE
/**
 * pci_enable_msix_range - configure device's MSI-X capability structure
 * @dev: pointer to the pci_dev data structure of MSI-X device function
 * @entries: pointer to an array of MSI-X entries
 * @minvec: minimum number of MSI-X irqs requested
 * @maxvec: maximum number of MSI-X irqs requested
 *
 * Setup the MSI-X capability structure of device function with a maximum
 * possible number of interrupts in the range between @minvec and @maxvec
 * upon its software driver call to request for MSI-X mode enabled on its
 * hardware device function. It returns a negative errno if an error occurs.
 * If it succeeds, it returns the actual number of interrupts allocated and
 * indicates the successful configuration of MSI-X capability structure
 * with new allocated MSI-X interrupts.
 **/
int pci_enable_msix_range(struct pci_dev *dev, struct msix_entry *entries,
			  int minvec, int maxvec)
{
	int nvec = maxvec;
	int rc;

	if (maxvec < minvec)
		return -ERANGE;

	do {
		rc = pci_enable_msix(dev, entries, nvec);
		if (rc < 0) {
			return rc;
		} else if (rc > 0) {
			if (rc < minvec)
				return -ENOSPC;
			nvec = rc;
		}
	} while (rc);

	return nvec;
}
EXPORT_SYMBOL(pci_enable_msix_range);
#endif
#ifdef EFX_HAVE_MSIX_CAP
#ifdef EFX_NEED_PCI_MSIX_VEC_COUNT
#ifndef msix_table_size
#define msix_table_size(flags)	((flags & PCI_MSIX_FLAGS_QSIZE) + 1)
#endif

/**
 * pci_msix_vec_count - return the number of device's MSI-X table entries
 * @dev: pointer to the pci_dev data structure of MSI-X device function
 * This function returns the number of device's MSI-X table entries and
 * therefore the number of MSI-X vectors device is capable of sending.
 * It returns a negative errno if the device is not capable of sending MSI-X
 * interrupts.
 **/
int pci_msix_vec_count(struct pci_dev *dev)
{
	u16 control;

	if (!dev->msix_cap)
		return -EINVAL;

	pci_read_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, &control);
	return msix_table_size(control);
}
EXPORT_SYMBOL(pci_msix_vec_count);
#endif
#endif

#if defined(EFX_NEED_CPUMASK_LOCAL_SPREAD) && (NR_CPUS != 1)
unsigned int cpumask_local_spread(unsigned int i, int node)
{
	int cpu;

	/* Wrap: we always want a cpu. */
	i %= num_online_cpus();

	if (node == -1) {
		for_each_cpu(cpu, cpu_online_mask)
			if (i-- == 0)
				return cpu;
	} else {
		/* NUMA first. */
		for_each_cpu(cpu, cpu_online_mask) {
			if (!cpumask_test_cpu(cpu, cpumask_of_node(node)))
				continue;
			if (i-- == 0)
				return cpu;
		}

		for_each_cpu(cpu, cpu_online_mask) {
			/* Skip NUMA nodes, done above. */
			if (cpumask_test_cpu(cpu, cpumask_of_node(node)))
				continue;

			if (i-- == 0)
				return cpu;
		}
	}
	BUG();
	/* silence compiler warning */
	return -EIO;
}
#endif

#ifdef EFX_NEED_D_HASH_AND_LOOKUP
struct dentry *d_hash_and_lookup(struct dentry *dir, struct qstr *name)
{
	/* The real in-kernel function checks for an FS specific hash.
	 * We only use this in debugfs handling, where there is no such
	 * hash.
	 */
	name->hash = full_name_hash(name->name, name->len);
	return d_lookup(dir, name);
}
#endif

#if defined(EFX_NEED_HWMON_DEVICE_REGISTER_WITH_INFO)
struct EFX_HWMON_DEVICE_REGISTER_TYPE *hwmon_device_register_with_info(
	struct device *dev,
	const char *name __always_unused,
	void *drvdata __always_unused,
	const struct hwmon_chip_info *info __always_unused,
	const struct attribute_group **extra_groups __always_unused)
{
	return hwmon_device_register(dev);
}
#endif

#ifdef EFX_NEED_HASH_64
/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define GOLDEN_RATIO_PRIME_32 0x9e370001UL
/*  2^63 + 2^61 - 2^57 + 2^54 - 2^51 - 2^18 + 1 */
#define GOLDEN_RATIO_PRIME_64 0x9e37fffffffc0001UL

#if BITS_PER_LONG == 32
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_PRIME_32
#define hash_long(val, bits) hash_32(val, bits)
#elif BITS_PER_LONG == 64
#define hash_long(val, bits) hash_64(val, bits)
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_PRIME_64
#else
#error Wordsize not 32 or 64
#endif

static __always_inline u64 hash_64(u64 val, unsigned int bits)
{
	u64 hash = val;

#if defined(CONFIG_ARCH_HAS_FAST_MULTIPLIER) && BITS_PER_LONG == 64
	hash = hash * GOLDEN_RATIO_PRIME_64;
#else
	/*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
	u64 n = hash;
	n <<= 18;
	hash -= n;
	n <<= 33;
	hash -= n;
	n <<= 3;
	hash += n;
	n <<= 3;
	hash -= n;
	n <<= 4;
	hash += n;
	n <<= 2;
	hash += n;
#endif

	/* High bits are more random, so use them. */
	return hash >> (64 - bits);
}
#endif
