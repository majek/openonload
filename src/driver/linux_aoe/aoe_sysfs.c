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

/****************************************************************************
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2012 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "aoe.h"

const char *dimm_bank_name[MAX_BANKS_COUNT] = {
	[MC_CMD_FC_IN_DDR_BANK_B0] = "bottom0",
	[MC_CMD_FC_IN_DDR_BANK_B1] = "bottom1",
	[MC_CMD_FC_IN_DDR_BANK_T0] = "top0",
	[MC_CMD_FC_IN_DDR_BANK_T1] = "top1"
};

static ssize_t aoe_fpga_reload(struct aoe_device *dev,
			       const char *buf, size_t count);

struct aoe_device_attr {
	struct attribute attr;
	ssize_t (*show)(struct aoe_device *, char *);
	ssize_t (*store)(struct aoe_device *, const char *, size_t);
};

struct aoe_state_attr {
	struct attribute attr;
	ssize_t (*show)(struct aoe_state_info *, char *);
	ssize_t (*store)(struct aoe_state_info *, const char *, size_t);
};

struct aoe_map_attr {
	struct attribute attr;
	ssize_t (*show)(struct aoe_mmap_entry *, char *);
	ssize_t (*store)(struct aoe_mmap_entry *, const char *, size_t);
};

struct aoe_port_attr {
	struct attribute attr;
	ssize_t (*show)(struct aoe_port_info *, char *);
	ssize_t (*store)(struct aoe_port_info *, const char *, size_t);
};

struct aoe_dimm_attr {
	struct attribute attr;
	ssize_t (*show)(struct aoe_dimm_info *, char*);
	ssize_t (*store)(struct aoe_dimm_info *, const char *, size_t);
};

static void aoe_boardattr_release(struct kobject *kobj) { }

static ssize_t aoe_map_attr_show(struct kobject *kobj,
				 struct attribute *attr, char *buf)
{
	struct aoe_mmap_entry *entry = container_of(kobj,
						    struct aoe_mmap_entry,
						    map_kobj);
	struct aoe_map_attr *map_attr = container_of(attr,
						     struct aoe_map_attr, attr);

	if (map_attr->show)
		return map_attr->show(entry, buf);

	return -EPERM;
}

static ssize_t aoe_device_attr_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct aoe_device *dev = container_of(kobj,
					      struct aoe_device,
					      aoe_kobj);
	struct aoe_device_attr *aoe_attr = container_of(attr,
							struct aoe_device_attr,
							attr);

	if (aoe_attr->show)
		return aoe_attr->show(dev, buf);

	return -EPERM;
}

static ssize_t aoe_state_attr_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct aoe_state_info *info = container_of(kobj,
					      struct aoe_state_info,
					      state_kobj);
	struct aoe_state_attr *aoe_attr = container_of(attr,
							struct aoe_state_attr,
							attr);

	if (aoe_attr->show)
		return aoe_attr->show(info, buf);

	return -EPERM;
}

static ssize_t aoe_port_attr_show(struct kobject *kobj,
		 	 	  struct attribute *attr, char *buf)
{
	struct aoe_port_info *port = container_of(kobj,
						  struct aoe_port_info,
						  port_kobj);
	struct aoe_port_attr *port_attr = container_of(attr,
						       struct aoe_port_attr,
						       attr);

	if (port_attr->show)
		return port_attr->show(port, buf);

	return -EPERM;
}

static ssize_t aoe_dimm_attr_show(struct kobject *kobj,
				  struct attribute *attr, char *buf)
{
	struct aoe_dimm_info *dimm = container_of(kobj,
						  struct aoe_dimm_info,
						  dimm_kobj);
	struct aoe_dimm_attr *dimm_attr = container_of(attr,
						       struct aoe_dimm_attr, attr);

	if (dimm_attr->show)
		return dimm_attr->show(dimm, buf);

	return -EPERM;
}

static ssize_t aoe_port_attr_store(struct kobject *kobj,
				   struct attribute *attr,
				   const char *buf,
				   size_t len)
{
	struct aoe_port_info *port = container_of(kobj,
						  struct aoe_port_info,
						  port_kobj);
	struct aoe_port_attr *port_attr = container_of(attr,
						       struct aoe_port_attr,
						       attr);

	if (port_attr->store)
		return port_attr->store(port, buf, len);

	return -EPERM;
}

static ssize_t aoe_device_attr_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buf,
				     size_t len)
{
	struct aoe_device *dev = container_of(kobj,
					      struct aoe_device,
					      aoe_kobj);
	struct aoe_device_attr *aoe_attr = container_of(attr,
							struct aoe_device_attr,
							attr);

	if (aoe_attr->store)
		return aoe_attr->store(dev, buf, len);

	return -EPERM;
}

static struct sysfs_ops aoe_board_ops = {
	.show = aoe_device_attr_show,
	.store = aoe_device_attr_store,
};

static struct sysfs_ops aoe_state_ops = {
	.show = aoe_state_attr_show,
	.store = NULL,
};

static struct sysfs_ops aoe_map_ops = {
	.show = aoe_map_attr_show,
	.store = NULL,
};

static struct sysfs_ops aoe_port_ops = {
	.show = aoe_port_attr_show,
	.store = aoe_port_attr_store,
};

static struct sysfs_ops aoe_dimm_ops = {
	.show = aoe_dimm_attr_show,
	.store = NULL,
};

#define AOE_GENERIC_ATTR(_type, _name, _mode, _show, _store) \
	static struct _type _type##_##_name = \
		__ATTR(_name, _mode, _show, _store)

#define AOE_DEVICE_ATTR(_name, _mode, _show, _store) \
	AOE_GENERIC_ATTR(aoe_device_attr, _name, _mode, _show, _store)

#define AOE_MAP_ATTR_LONG(_name, _mode) \
	static ssize_t aoe_map_attr_##_name##_show (struct aoe_mmap_entry *map, char *buf) { \
                return snprintf(buf, PAGE_SIZE, "0x%llX\n", map->_name); \
        } \
	AOE_GENERIC_ATTR(aoe_map_attr, _name, _mode, aoe_map_attr_##_name##_show, NULL)

#define AOE_MAP_ATTR_INT(_name, _mode) \
	static ssize_t aoe_map_attr_##_name##_show (struct aoe_mmap_entry *map, char *buf) { \
		return snprintf(buf, PAGE_SIZE, "0x%X\n", map->_name); \
	} \
	AOE_GENERIC_ATTR(aoe_map_attr, _name, _mode, aoe_map_attr_##_name##_show, NULL)

#define AOE_MAP_ATTR_CHAR(_name, _mode) \
	static ssize_t aoe_map_attr_##_name##_show (struct aoe_mmap_entry *map, char *buf) { \
		return snprintf(buf, PAGE_SIZE, "%s\n", map->_name); \
	} \
	AOE_GENERIC_ATTR(aoe_map_attr, _name, _mode, aoe_map_attr_##_name##_show, NULL)

#define AOE_PORT_ATTR_LONG(_name, _mode) \
	static ssize_t aoe_port_attr_##_name##_show (struct aoe_port_info *port, char *buf) { \
		return snprintf(buf, PAGE_SIZE, "%u\n", port->_name); \
	} \
	static ssize_t aoe_port_attr_##_name##_store (struct aoe_port_info *port, const char *buf, size_t len) { \
		sscanf(buf, "%u", &port->_name); \
		port->update(port); \
		return len; \
	} \
	AOE_GENERIC_ATTR(aoe_port_attr, _name, _mode, \
			 aoe_port_attr_##_name##_show, \
			 aoe_port_attr_##_name##_store)

#define AOE_PORT_ATTR_IMMUTABLE_LONG(_name, _mode) \
	static ssize_t aoe_port_attr_##_name##_show (struct aoe_port_info *port, char *buf) { \
		return snprintf(buf, PAGE_SIZE, "%u\n", port->_name); \
	} \
	AOE_GENERIC_ATTR(aoe_port_attr, _name, _mode, \
			 aoe_port_attr_##_name##_show, NULL)

#define AOE_PORT_ATTR(_field, _query) \
	static ssize_t aoe_port_attr_##_field##_show(struct aoe_port_info *port, char *buf) \
	{ \
		if (port->_query) \
			return port->_query(port, buf); \
		else \
			return -ENODEV; \
	} \
	AOE_GENERIC_ATTR(aoe_port_attr, _field, 0444, aoe_port_attr_##_field##_show, NULL)

#define AOE_DIMM_ATTR(_name, _query) \
	static ssize_t aoe_dimm_attr_##_name##_show (struct aoe_dimm_info *dimm, char *buf) { \
		if (dimm->_query) \
			return dimm->_query(dimm, buf); \
		else \
			return -ENODEV; \
	} \
	AOE_GENERIC_ATTR(aoe_dimm_attr, _name, 0644, \
			 aoe_dimm_attr_##_name##_show, \
			 NULL)

#define AOE_INFO_ATTR(_field, _query) \
	static ssize_t aoe_##_field(struct aoe_state_info *info, char *buf) \
	{ \
		if (info->parent->_field) \
			return info->parent->_field(info->parent, buf); \
		else \
			return -ENODEV; \
	} \
	AOE_GENERIC_ATTR(aoe_state_attr, _field, 0444, aoe_##_field, NULL)

/* FPGA attributes */
AOE_INFO_ATTR(fpga_version, aoe_mcdi_fpga_version);
AOE_INFO_ATTR(cpld_version, aoe_mcdi_cpld_version);
AOE_INFO_ATTR(board_rev, aoe_mcdi_board_revision);
AOE_INFO_ATTR(fc_version, aoe_mcdi_fc_version);
AOE_INFO_ATTR(fpga_build_changeset, aoe_mcdi_fpga_build_changeset);
AOE_INFO_ATTR(fpga_services_version, aoe_mcdi_fpga_services_version);
AOE_INFO_ATTR(fpga_services_changeset, aoe_mcdi_fpga_services_changeset);
AOE_INFO_ATTR(fpga_bsp_version, aoe_mcdi_fpga_bsp_version);

AOE_INFO_ATTR(peg_power, aoe_mcdi_info_peg_power);
AOE_INFO_ATTR(cpld_good, aoe_mcdi_info_cpld_good);
AOE_INFO_ATTR(fpga_good, aoe_mcdi_info_fpga_good);
AOE_INFO_ATTR(fpga_power, aoe_mcdi_info_fpga_power);
AOE_INFO_ATTR(bad_sodimm, aoe_mcdi_info_bad_sodimm);
AOE_INFO_ATTR(has_byteblaster, aoe_mcdi_info_has_byte_blaster);
AOE_INFO_ATTR(fc_running, aoe_mcdi_info_fc_running);
AOE_INFO_ATTR(boot_result, aoe_mcdi_info_boot_result);

/* FPGA operations */
AOE_DEVICE_ATTR(reload, 0664, NULL, aoe_fpga_reload);

/* MAP attributes */
AOE_MAP_ATTR_LONG(base_addr, 0664);
AOE_MAP_ATTR_LONG(length, 0664);
AOE_MAP_ATTR_INT(comp_info, 0644);
AOE_MAP_ATTR_CHAR(name, 0644);

/* PER PORT attributes */
AOE_PORT_ATTR_LONG(mtu, 0644);
AOE_PORT_ATTR(vod, vod);
AOE_PORT_ATTR(preemp_1stposttap, preemp_1stposttap);
AOE_PORT_ATTR(preemp_pretap, preemp_pretap);
AOE_PORT_ATTR(preemp_2ndposttap, preemp_2ndposttap);
AOE_PORT_ATTR(dc_gain, dc_gain);
AOE_PORT_ATTR(rx_eq, rx_eq);
AOE_PORT_ATTR_IMMUTABLE_LONG(ifindex, 0444);
AOE_PORT_ATTR(mac_addr, mac_addr);

/* DIMM attrubutes */
AOE_DIMM_ATTR(size, ddr_size);
AOE_DIMM_ATTR(type, ddr_type);
AOE_DIMM_ATTR(voltage, ddr_voltage);
AOE_DIMM_ATTR(status, ddr_status);
AOE_DIMM_ATTR(partnum, ddr_partnum);
AOE_DIMM_ATTR(spd, ddr_spd);

static struct attribute *aoe_default_attrs[] = {
	&aoe_device_attr_reload.attr,
	NULL,
};

static struct attribute *aoe_state_attrs[] = {
	&aoe_state_attr_board_rev.attr,
	&aoe_state_attr_fpga_version.attr,
	&aoe_state_attr_cpld_version.attr,
	&aoe_state_attr_fc_version.attr,
	&aoe_state_attr_fpga_build_changeset.attr,
	&aoe_state_attr_fpga_services_version.attr,
	&aoe_state_attr_fpga_services_changeset.attr,
	&aoe_state_attr_fpga_bsp_version.attr,
	&aoe_state_attr_peg_power.attr,
	&aoe_state_attr_cpld_good.attr,
	&aoe_state_attr_fpga_good.attr,
	&aoe_state_attr_fpga_power.attr,
	&aoe_state_attr_bad_sodimm.attr,
	&aoe_state_attr_has_byteblaster.attr,
	&aoe_state_attr_fc_running.attr,
	&aoe_state_attr_boot_result.attr,
	NULL,
};

static struct attribute *aoe_default_map_attrs[] = {
	&aoe_map_attr_base_addr.attr,
	&aoe_map_attr_length.attr,
	&aoe_map_attr_comp_info.attr,
	&aoe_map_attr_name.attr,
	NULL,
};

static struct attribute *aoe_default_port_attrs[] = {
  &aoe_port_attr_mtu.attr,
  &aoe_port_attr_vod.attr,
  &aoe_port_attr_preemp_1stposttap.attr,
  &aoe_port_attr_preemp_pretap.attr,
  &aoe_port_attr_preemp_2ndposttap.attr,
  &aoe_port_attr_dc_gain.attr,
  &aoe_port_attr_rx_eq.attr,
  &aoe_port_attr_ifindex.attr,
  &aoe_port_attr_mac_addr.attr,
  NULL,
};

static struct attribute *aoe_default_dimm_attrs[] = {
	&aoe_dimm_attr_size.attr,
	&aoe_dimm_attr_type.attr,
	&aoe_dimm_attr_voltage.attr,
	&aoe_dimm_attr_status.attr,
	&aoe_dimm_attr_partnum.attr,
	&aoe_dimm_attr_spd.attr,
	NULL,
};

static struct kobj_type aoe_board_ktype = {
	.release = aoe_boardattr_release,
	.sysfs_ops = &aoe_board_ops,
	.default_attrs = aoe_default_attrs,
};

static struct kobj_type aoe_state_ktype = {
	.release = aoe_boardattr_release,
	.sysfs_ops = &aoe_state_ops,
	.default_attrs = aoe_state_attrs,
};

static struct kobj_type aoe_map_ktype = {
	.release = aoe_boardattr_release,
	.sysfs_ops = &aoe_map_ops,
	.default_attrs = aoe_default_map_attrs,
};

static struct kobj_type aoe_port_ktype = {
	.release = aoe_boardattr_release,
	.sysfs_ops = &aoe_port_ops,
	.default_attrs = aoe_default_port_attrs,
};

static struct kobj_type aoe_dimm_ktype = {
	.release = aoe_boardattr_release,
	.sysfs_ops = &aoe_dimm_ops,
	.default_attrs = aoe_default_dimm_attrs,
};

static ssize_t aoe_fpga_reload(struct aoe_device *dev,
			       const char *buf, size_t count)
{
	int s_part;
	int e_part;
	int status;
	unsigned int timeout;
	struct timespec start;
	struct timespec end;
	struct aoe_device *aoe_instance = dev;

	if (!count)
		return -EINVAL;

	/* We block here and wait for an evernt to unblock us, this
	 * should take a maximum of 8 seconds, so timeout if this
	 * does not occour */

	switch (*buf) {
		case '0':
			s_part = e_part = 0;
			break;
		case '1':
			s_part = e_part = 1;
			break;
		case '2':
			s_part = 0;
			e_part = 1;
			break;
		default:
			return -EINVAL;
	}

	/* Try first partition we are asked to try */

	do {
		status = aoe_mcdi_fpga_reload(aoe_instance, s_part);

		if (status)
			return -ENODEV;

		getnstimeofday(&start);
		timeout = msecs_to_jiffies(FPGA_LOAD_TIMEOUT);

		while (!aoe_fpga_up(aoe_instance)) {
			status = wait_event_interruptible_timeout(
					aoe_instance->event_queue,
					aoe_fpga_up(aoe_instance),
					timeout);
			if (!status)
				printk(KERN_ERR "sfc_aoe: FPGA Load timeout\n");

			if (-ERESTARTSYS == status) {
				getnstimeofday(&end);
				timeout = msecs_to_jiffies(FPGA_LOAD_TIMEOUT) -
					  (timespec_to_jiffies(&end) - timespec_to_jiffies(&start));
			}

			goto ok;
		}
	} while (++s_part <= e_part);

ok:
	return count;
}

/* hold map lock for these two calls */
int aoe_sysfs_add_map(struct aoe_device *aoe_instance,
		      struct aoe_mmap_entry *map)
{
	return kobject_init_and_add(&map->map_kobj, &aoe_map_ktype,
				    &aoe_instance->aoe_kobj,
				    "map-%03d", map->index);
}

void aoe_sysfs_del_map(struct aoe_device *aoe_instance,
		       struct aoe_mmap_entry *map)
{
	kobject_del(&map->map_kobj);
}

int aoe_sysfs_setup(struct device *parent, struct aoe_device *aoe_instance)
{
	unsigned int bank = 0;
	struct aoe_dimm_info *dimm;
	struct aoe_state_info *info;
	int ret = kobject_init_and_add(&aoe_instance->aoe_kobj,
				       &aoe_board_ktype,
				       &parent->kobj,
				       "fpga%d", aoe_instance->board);
	if (ret)
		return ret;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	ret = kobject_init_and_add(&info->state_kobj,
				   &aoe_state_ktype,
				   &aoe_instance->aoe_kobj,
				   "state");
	if (ret)
		return ret;

	info->parent = aoe_instance;
	aoe_instance->info = info;

	/* Discover the devices ? */
	while (bank < MAX_BANKS_COUNT) {

		dimm = kzalloc(sizeof(*dimm), GFP_KERNEL);
		if (!dimm)
			return -ENOMEM;

		ret = kobject_init_and_add(&dimm->dimm_kobj,
					   &aoe_dimm_ktype,
					   &aoe_instance->aoe_kobj,
					   "dimm_%s", dimm_bank_name[bank]);

		if (ret) {
			kfree(dimm);
			return -ENODEV;
		}

		INIT_LIST_HEAD(&dimm->list);
		list_add(&dimm->list, &aoe_instance->dimms);
		dimm->parent = aoe_instance;
		dimm->id = bank++;
		aoe_mcdi_set_ddr_funcs(dimm);
	}

	if (ret < 0)
		return ret;
	else
		return 0;
}

int aoe_port_sysfs_setup(struct aoe_device *aoe_instance,
			 struct aoe_port_info *port)
{
	int ret;

	ret = kobject_init_and_add(&port->port_kobj,
				   &aoe_port_ktype,
				   &aoe_instance->aoe_kobj,
				   "port%d",
				   AOE_PHYS_PORT(port));
	if (ret)
		goto failed;

	aoe_mcdi_set_port_funcs(port);
failed:
	return ret;
}

void aoe_sysfs_delete(struct aoe_device *aoe_instance)
{
	struct aoe_port_info *port;
	struct aoe_dimm_info *dimm;

	list_for_each_entry(port, &aoe_instance->nic_ports, list) {
		kobject_del(&port->port_kobj);
	}

	list_for_each_entry(dimm, &aoe_instance->dimms, list) {
		kobject_del(&dimm->dimm_kobj);
		kfree(dimm);
	}

	kobject_del(&aoe_instance->info->state_kobj);
	kfree(aoe_instance->info);

	kobject_del(&aoe_instance->aoe_kobj);
}
