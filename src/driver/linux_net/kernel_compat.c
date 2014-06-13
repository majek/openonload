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
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2012 Solarflare Communications Inc.
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
#include <linux/bootmem.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

/*
 * Kernel backwards compatibility
 *
 * This file provides functionality missing from earlier kernels.
 */

#ifdef EFX_NEED_COMPOUND_PAGE_FIX

void efx_compound_page_destructor(struct page *page)
{
	/* Fake up page state to keep __free_pages happy */
	set_page_count(page, 1);
	page[1].mapping = NULL;

	__free_pages(page, (unsigned long)page[1].index);
}

#endif /* NEED_COMPOUND_PAGE_FIX */

#ifdef EFX_NEED_HEX_DUMP

/**************************************************************************
 *
 * print_hex_dump, taken from lib/hexdump.c.
 *
 **************************************************************************
 *
 */

#define hex_asc(x)	"0123456789abcdef"[x]
#define isascii(c) (((unsigned char)(c)) <= 0x7f)

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

/**************************************************************************
 *
 * print_mac, from net/ethernet/eth.c in v2.6.24
 *
 **************************************************************************
 *
 */
#ifdef EFX_NEED_PRINT_MAC
char *print_mac(char *buf, const u8 *addr)
{
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return buf;
}
#endif /* EFX_NEED_PRINT_MAC */

#ifdef EFX_NEED_CSUM_TCPUDP_NOFOLD
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
__wsum
csum_tcpudp_nofold(__be32 saddr, __be32 daddr, unsigned short len,
		   unsigned short proto, __wsum sum)
#else
__wsum
csum_tcpudp_nofold(unsigned long saddr, unsigned long daddr,
		   unsigned short len, unsigned short proto, __wsum sum)
#endif
{
	unsigned long result;

	result = (__force u64)saddr + (__force u64)daddr +
		(__force u64)sum + ((len + proto) << 8);

	/* Fold down to 32-bits so we don't lose in the typedef-less network stack.  */
	/* 64 to 33 */
	result = (result & 0xffffffff) + (result >> 32);
	/* 33 to 32 */
	result = (result & 0xffffffff) + (result >> 32);
	return (__force __wsum)result;

}
#endif /* EFX_NEED_CSUM_TCPUDP_NOFOLD */

#ifdef EFX_USE_I2C_LEGACY

#ifdef CONFIG_SFC_HWMON

struct i2c_client *i2c_new_device(struct i2c_adapter *adap,
				  const struct i2c_board_info *info)
{
	return i2c_new_probed_device(adap, info, NULL);
}

struct i2c_client *i2c_new_probed_device(struct i2c_adapter *adap,
					 const struct i2c_board_info *info,
					 const unsigned short *addr_list)
{
	int (*probe)(struct i2c_client *, const struct i2c_device_id *);
	struct i2c_client *client;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return NULL;

	client->adapter = adap;
	client->dev.platform_data = info->platform_data;
	client->flags = info->flags;
	client->addr = addr_list ? addr_list[0] : info->addr; /* FIXME */
	strlcpy(client->name, info->type, sizeof client->name);

	if (!strcmp(client->name, "sfc_lm87")) {
		client->driver = &efx_lm87_driver;
		probe = efx_lm87_probe;
	} else if (!strcmp(client->name, "max6646") ||
		   !strcmp(client->name, "max6647")) {
		client->driver = &efx_lm90_driver;
		probe = efx_lm90_probe;
	} else {
		BUG();
		probe = NULL;
	}

	if (i2c_attach_client(client))
		goto fail_client;

	if (probe(client, NULL))
		goto fail_attached;

	return client;

fail_attached:
	i2c_detach_client(client);
fail_client:
	kfree(client);
	return NULL;
}

#endif /* CONFIG_SFC_HWMON */

void i2c_unregister_device(struct i2c_client *client)
{
	if (client->driver->detach_client) {
		client->driver->detach_client(client);
	} else {
		if (!i2c_detach_client(client))
			kfree(client);
	}
}

#endif /* EFX_USE_I2C_LEGACY */

#ifdef EFX_NEED_I2C_NEW_DUMMY

struct i2c_driver efx_i2c_dummy_driver = {
#ifdef EFX_USE_I2C_DRIVER_NAME
	.name = "sfc_i2c_dummy"
#else
	.driver.name = "sfc_i2c_dummy"
#endif
};

struct i2c_client *efx_i2c_new_dummy(struct i2c_adapter *adap, u16 address)
{
	struct i2c_client *client;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return NULL;

	client->adapter = adap;
	client->addr = address;
	strcpy(client->name, efx_i2c_dummy_driver.driver.name);

	client->driver = &efx_i2c_dummy_driver;

	if (i2c_attach_client(client)) {
		kfree(client);
		return NULL;
	}

	return client;
}

#endif /* EFX_NEED_I2C_NEW_DUMMY */

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

#if (defined(EFX_NEED_UNMASK_MSIX_VECTORS) || \
     defined(EFX_NEED_SAVE_MSIX_MESSAGES)) && \
	!defined(EFX_HAVE_MSIX_TABLE_RESERVED)

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
	membase = ioremap_nocache(membase_phys + offset, length);
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

#endif /* (EFX_NEED_UNMASK_MSIX_VECTORS || EFX_NEED_SAVE_MSIX_MESSAGES) &&
	  !EFX_HAVE_MSIX_TABLE_RESERVED */

#ifdef EFX_NEED_NS_TO_TIMESPEC

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
	EFX_BUG_ON_PARANOID(divisor < 0);

	if (unlikely(dividend < 0)) {
		EFX_BUG_ON_PARANOID(-dividend >> 31 >= divisor);
		res = -div_long_long_rem(-dividend, divisor, &remainder);
		*rem32 = -remainder;
	} else {
		EFX_BUG_ON_PARANOID(dividend >> 31 >= divisor);
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

#ifdef EFX_NEED_PCI_VPD_LRDT
int efx_pci_vpd_find_tag(const u8 *buf, unsigned int off, unsigned int len, u8 rdt)
{
	int i;

	for (i = off; i < len; ) {
		u8 val = buf[i];

		if (val & PCI_VPD_LRDT) {
			/* Don't return success of the tag isn't complete */
			if (i + PCI_VPD_LRDT_TAG_SIZE > len)
				break;

			if (val == rdt)
				return i;

			i += PCI_VPD_LRDT_TAG_SIZE +
			     pci_vpd_lrdt_size(&buf[i]);
		} else {
			u8 tag = val & ~PCI_VPD_SRDT_LEN_MASK;

			if (tag == rdt)
				return i;

			if (tag == PCI_VPD_SRDT_END)
				break;

			i += PCI_VPD_SRDT_TAG_SIZE +
			     pci_vpd_srdt_size(&buf[i]);
		}
	}

	return -ENOENT;
}

int efx_pci_vpd_find_info_keyword(const u8 *buf, unsigned int off,
			      unsigned int len, const char *kw)
{
	int i;

	for (i = off; i + PCI_VPD_INFO_FLD_HDR_SIZE <= off + len;) {
		if (buf[i + 0] == kw[0] &&
		    buf[i + 1] == kw[1])
			return i;

		i += PCI_VPD_INFO_FLD_HDR_SIZE +
		     pci_vpd_info_field_size(&buf[i]);
	}

	return -ENOENT;
}
#endif /* EFX_NEED_PCI_VPD_LRDT */

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

#if defined(EFX_NEED_WARN) || defined(EFX_NEED_WARN_ON)
void efx_warn_slowpath(const char *file, const int line, const char *function,
		       const char *fmt, ...)
{
	va_list args;

	printk(KERN_WARNING "------------[ cut here ]------------\n");
	printk(KERN_WARNING "WARNING: CPU: %d PID:%d at %s:%d %s()\n",
	       raw_smp_processor_id(), current->pid, file, line, function);

	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);

	/* Can't call print_modules() as it's not exported */
	dump_stack();
	/* Can't call print_oops_end_marker() as it's not exported */
	printk(KERN_WARNING "---[ end trace ]---\n");
#ifdef TAINT_WARN
	add_taint(TAINT_WARN);
#endif
}
EXPORT_SYMBOL(efx_warn_slowpath); /* Onload */
#endif

#ifdef EFX_NEED_WARN_ON
/* This trivial wrapper could be combined with the WARN_ON macro, except
 * that it depends on the -Wno-format-zero-length compiler option.
 * When Onload includes kernel_compat.h it does not set that option and
 * we can't really expect it to do so.
 */
void efx_warn_on_slowpath(const char *file, const int line,
			  const char *function)
{
	efx_warn_slowpath(file, line, function, "");
}
EXPORT_SYMBOL(efx_warn_on_slowpath); /* Onload */
#endif
