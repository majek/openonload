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
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2011 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/bitops.h>
#include <linux/slab.h>
#ifndef EFX_USE_KCOMPAT
#include <linux/hwmon.h>
#endif
#include <linux/stat.h>

#include "net_driver.h"
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "nic.h"

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_HWMON_H)
#include <linux/hwmon.h>
#endif

enum efx_hwmon_type {
	EFX_HWMON_UNKNOWN,
	EFX_HWMON_TEMP,         /* temperature */
	EFX_HWMON_COOL,         /* cooling device, probably a heatsink */
	EFX_HWMON_IN            /* input voltage */
};

static const struct {
	const char *label;
	enum efx_hwmon_type hwmon_type;
	int port;
} efx_mcdi_sensor_type[MC_CMD_SENSOR_ENTRY_MAXNUM] = {
#define SENSOR(name, label, hwmon_type, port)			\
	[MC_CMD_SENSOR_##name] = { label, hwmon_type, port }
	SENSOR(CONTROLLER_TEMP,	   "Controller temp.",	   EFX_HWMON_TEMP, -1),
	SENSOR(PHY_COMMON_TEMP,	   "PHY temp.",		   EFX_HWMON_TEMP, -1),
	SENSOR(CONTROLLER_COOLING, "Controller cooling",   EFX_HWMON_COOL, -1),
	SENSOR(PHY0_TEMP,	   "PHY temp.",		   EFX_HWMON_TEMP, 0),
	SENSOR(PHY0_COOLING,	   "PHY cooling",	   EFX_HWMON_COOL, 0),
	SENSOR(PHY1_TEMP,	   "PHY temp.",		   EFX_HWMON_TEMP, 1),
	SENSOR(PHY1_COOLING, 	   "PHY cooling",	   EFX_HWMON_COOL, 1),
	SENSOR(IN_1V0,		   "1.0V supply",	   EFX_HWMON_IN,   -1),
	SENSOR(IN_1V2,		   "1.2V supply",	   EFX_HWMON_IN,   -1),
	SENSOR(IN_1V8,		   "1.8V supply",	   EFX_HWMON_IN,   -1),
	SENSOR(IN_2V5,		   "2.5V supply",	   EFX_HWMON_IN,   -1),
	SENSOR(IN_3V3,		   "3.3V supply",	   EFX_HWMON_IN,   -1),
	SENSOR(IN_12V0,		   "12.0V supply",	   EFX_HWMON_IN,   -1),
	SENSOR(IN_1V2A,		   "1.2V analogue supply", EFX_HWMON_IN,   -1),
	SENSOR(IN_VREF,		   "ref. voltage",	   EFX_HWMON_IN,   -1),
	SENSOR(OUT_VAOE,	   "AOE power supply",	   EFX_HWMON_IN,   -1),
	SENSOR(AOE_TEMP,	   "AOE temp.",		   EFX_HWMON_TEMP, -1),
	SENSOR(PSU_AOE_TEMP,	   "AOE PSU temp.",	   EFX_HWMON_TEMP, -1),
	SENSOR(PSU_TEMP,	   "Controller PSU temp.", EFX_HWMON_TEMP, -1),
	SENSOR(FAN_0,		   NULL,		   EFX_HWMON_COOL, -1),
	SENSOR(FAN_1,		   NULL,		   EFX_HWMON_COOL, -1),
	SENSOR(FAN_2,		   NULL,		   EFX_HWMON_COOL, -1),
	SENSOR(FAN_3,		   NULL,		   EFX_HWMON_COOL, -1),
	SENSOR(FAN_4,		   NULL,		   EFX_HWMON_COOL, -1),
#undef SENSOR
};

static const char *const sensor_status_names[] = {
	[MC_CMD_SENSOR_STATE_OK] = "OK",
	[MC_CMD_SENSOR_STATE_WARNING] = "Warning",
	[MC_CMD_SENSOR_STATE_FATAL] = "Fatal",
	[MC_CMD_SENSOR_STATE_BROKEN] = "Device failure",
};

void efx_mcdi_sensor_event(struct efx_nic *efx, efx_qword_t *ev)
{
	unsigned int type, state, value;
	const char *name = NULL, *state_txt;

	type = EFX_QWORD_FIELD(*ev, MCDI_EVENT_SENSOREVT_MONITOR);
	state = EFX_QWORD_FIELD(*ev, MCDI_EVENT_SENSOREVT_STATE);
	value = EFX_QWORD_FIELD(*ev, MCDI_EVENT_SENSOREVT_VALUE);

	/* Deal gracefully with the board having more drivers than we
	 * know about, but do not expect new sensor states. */
	if (type < ARRAY_SIZE(efx_mcdi_sensor_type))
		name = efx_mcdi_sensor_type[type].label;
	if (!name)
		name = "No sensor name available";
	EFX_BUG_ON_PARANOID(state >= ARRAY_SIZE(sensor_status_names));
	state_txt = sensor_status_names[state];

	netif_err(efx, hw, efx->net_dev,
		  "Sensor %d (%s) reports condition '%s' for raw value %d\n",
		  type, name, state_txt, value);
}

#ifdef CONFIG_SFC_MCDI_MON

struct efx_mcdi_mon_attribute {
	struct device_attribute dev_attr;
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_OLD_DEVICE_ATTRIBUTE)
	ssize_t (*reader)(struct device *, struct device_attribute *, char *);
#endif
	unsigned int index;
	unsigned int type;
	unsigned int limit_value;
	char name[12];
};

static int efx_mcdi_mon_update(struct efx_nic *efx)
{
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	u8 inbuf[MC_CMD_READ_SENSORS_IN_LEN];
	int rc;

	MCDI_SET_DWORD(inbuf, READ_SENSORS_IN_DMA_ADDR_LO,
		       hwmon->dma_buf.dma_addr & 0xffffffff);
	MCDI_SET_DWORD(inbuf, READ_SENSORS_IN_DMA_ADDR_HI,
		       (u64)hwmon->dma_buf.dma_addr >> 32);

	rc = efx_mcdi_rpc(efx, MC_CMD_READ_SENSORS,
			  inbuf, sizeof(inbuf), NULL, 0, NULL);
	if (rc == 0)
		hwmon->last_update = jiffies;
	return rc;
}

static ssize_t efx_mcdi_mon_show_name(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	return sprintf(buf, "%s\n", KBUILD_MODNAME);
}

static int efx_mcdi_mon_get_entry(struct device *dev, unsigned int index,
				  efx_dword_t *entry)
{
	struct efx_nic *efx = dev_get_drvdata(dev);
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	int rc;

	BUILD_BUG_ON(MC_CMD_READ_SENSORS_OUT_LEN != 0);

	mutex_lock(&hwmon->update_lock);

	/* Use cached value if last update was < 1 s ago */
	if (time_before(jiffies, hwmon->last_update + HZ))
		rc = 0;
	else
		rc = efx_mcdi_mon_update(efx);

	/* Copy out the requested entry */
	*entry = ((efx_dword_t *)hwmon->dma_buf.addr)[index];

	mutex_unlock(&hwmon->update_lock);

	return rc;
}

static ssize_t efx_mcdi_mon_show_value(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	struct efx_mcdi_mon_attribute *mon_attr =
		container_of(attr, struct efx_mcdi_mon_attribute, dev_attr);
	efx_dword_t entry;
	unsigned int value;
	int rc;

	rc = efx_mcdi_mon_get_entry(dev, mon_attr->index, &entry);
	if (rc)
		return rc;

	value = EFX_DWORD_FIELD(entry, MC_CMD_SENSOR_VALUE_ENTRY_TYPEDEF_VALUE);

	/* Convert temperature from degrees to milli-degrees Celsius */
	if (efx_mcdi_sensor_type[mon_attr->type].hwmon_type == EFX_HWMON_TEMP)
		value *= 1000;

	return sprintf(buf, "%u\n", value);
}

static ssize_t efx_mcdi_mon_show_limit(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	struct efx_mcdi_mon_attribute *mon_attr =
		container_of(attr, struct efx_mcdi_mon_attribute, dev_attr);
	unsigned int value;

	value = mon_attr->limit_value;

	/* Convert temperature from degrees to milli-degrees Celsius */
	if (efx_mcdi_sensor_type[mon_attr->type].hwmon_type == EFX_HWMON_TEMP)
		value *= 1000;

	return sprintf(buf, "%u\n", value);
}

static ssize_t efx_mcdi_mon_show_alarm(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	struct efx_mcdi_mon_attribute *mon_attr =
		container_of(attr, struct efx_mcdi_mon_attribute, dev_attr);
	efx_dword_t entry;
	int state;
	int rc;

	rc = efx_mcdi_mon_get_entry(dev, mon_attr->index, &entry);
	if (rc)
		return rc;

	state = EFX_DWORD_FIELD(entry, MC_CMD_SENSOR_VALUE_ENTRY_TYPEDEF_STATE);
	return sprintf(buf, "%d\n", state != MC_CMD_SENSOR_STATE_OK);
}

static ssize_t efx_mcdi_mon_show_label(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	struct efx_mcdi_mon_attribute *mon_attr =
		container_of(attr, struct efx_mcdi_mon_attribute, dev_attr);
	return sprintf(buf, "%s\n",
		       efx_mcdi_sensor_type[mon_attr->type].label);
}

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_OLD_DEVICE_ATTRIBUTE)

/* Every attribute needs its own distinct function! */
#define DEFINE_SHOW(index) DEFINE_SHOW_2(index)
#define DEFINE_SHOW_2(index)						\
	static ssize_t efx_mcdi_mon_show_attr_ ## index(struct device *dev, \
							char *buf)	\
	{								\
		struct efx_nic *efx = dev_get_drvdata(dev);		\
		struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);		\
		struct efx_mcdi_mon_attribute *attr = &hwmon->attrs[index]; \
		return attr->reader(dev, &attr->dev_attr, buf);		\
	}
#define SHOW(index) SHOW_2(index)
#define SHOW_2(index) efx_mcdi_mon_show_attr_ ## index

/* Allow for name + up to 23 sensors, 5 unlabelled
 * => 1 + 23 * 6 - 5 = 134 attributes
 */
DEFINE_SHOW(0) DEFINE_SHOW(1) DEFINE_SHOW(2) DEFINE_SHOW(3) DEFINE_SHOW(4)
DEFINE_SHOW(5) DEFINE_SHOW(6) DEFINE_SHOW(7) DEFINE_SHOW(8) DEFINE_SHOW(9)
DEFINE_SHOW(10) DEFINE_SHOW(11) DEFINE_SHOW(12) DEFINE_SHOW(13) DEFINE_SHOW(14)
DEFINE_SHOW(15) DEFINE_SHOW(16) DEFINE_SHOW(17) DEFINE_SHOW(18) DEFINE_SHOW(19)
DEFINE_SHOW(20) DEFINE_SHOW(21) DEFINE_SHOW(22) DEFINE_SHOW(23) DEFINE_SHOW(24)
DEFINE_SHOW(25) DEFINE_SHOW(26) DEFINE_SHOW(27) DEFINE_SHOW(28) DEFINE_SHOW(29)
DEFINE_SHOW(30) DEFINE_SHOW(31) DEFINE_SHOW(32) DEFINE_SHOW(33) DEFINE_SHOW(34)
DEFINE_SHOW(35) DEFINE_SHOW(36) DEFINE_SHOW(37) DEFINE_SHOW(38) DEFINE_SHOW(39)
DEFINE_SHOW(40) DEFINE_SHOW(41) DEFINE_SHOW(42) DEFINE_SHOW(43) DEFINE_SHOW(44)
DEFINE_SHOW(45) DEFINE_SHOW(46) DEFINE_SHOW(47) DEFINE_SHOW(48) DEFINE_SHOW(49)
DEFINE_SHOW(50) DEFINE_SHOW(51) DEFINE_SHOW(52) DEFINE_SHOW(53) DEFINE_SHOW(54)
DEFINE_SHOW(55) DEFINE_SHOW(56) DEFINE_SHOW(57) DEFINE_SHOW(58) DEFINE_SHOW(59)
DEFINE_SHOW(60) DEFINE_SHOW(61) DEFINE_SHOW(62) DEFINE_SHOW(63) DEFINE_SHOW(64)
DEFINE_SHOW(65) DEFINE_SHOW(66) DEFINE_SHOW(67) DEFINE_SHOW(68) DEFINE_SHOW(69)
DEFINE_SHOW(70) DEFINE_SHOW(71) DEFINE_SHOW(72) DEFINE_SHOW(73) DEFINE_SHOW(74)
DEFINE_SHOW(75) DEFINE_SHOW(76) DEFINE_SHOW(77) DEFINE_SHOW(78) DEFINE_SHOW(79)
DEFINE_SHOW(80) DEFINE_SHOW(81) DEFINE_SHOW(82) DEFINE_SHOW(83) DEFINE_SHOW(84)
DEFINE_SHOW(85) DEFINE_SHOW(86) DEFINE_SHOW(87) DEFINE_SHOW(88) DEFINE_SHOW(89)
DEFINE_SHOW(90) DEFINE_SHOW(91) DEFINE_SHOW(92) DEFINE_SHOW(93) DEFINE_SHOW(94)
DEFINE_SHOW(95) DEFINE_SHOW(96) DEFINE_SHOW(97) DEFINE_SHOW(98) DEFINE_SHOW(99)
DEFINE_SHOW(100) DEFINE_SHOW(101) DEFINE_SHOW(102) DEFINE_SHOW(103)
DEFINE_SHOW(104) DEFINE_SHOW(105) DEFINE_SHOW(106) DEFINE_SHOW(107)
DEFINE_SHOW(108) DEFINE_SHOW(109) DEFINE_SHOW(110) DEFINE_SHOW(111)
DEFINE_SHOW(112) DEFINE_SHOW(113) DEFINE_SHOW(114) DEFINE_SHOW(115)
DEFINE_SHOW(116) DEFINE_SHOW(117) DEFINE_SHOW(118) DEFINE_SHOW(119)
DEFINE_SHOW(120) DEFINE_SHOW(121) DEFINE_SHOW(122) DEFINE_SHOW(123)
DEFINE_SHOW(124) DEFINE_SHOW(125) DEFINE_SHOW(126) DEFINE_SHOW(127)
DEFINE_SHOW(128) DEFINE_SHOW(129) DEFINE_SHOW(130) DEFINE_SHOW(131)
DEFINE_SHOW(132) DEFINE_SHOW(133)
static ssize_t
(*const efx_mcdi_mon_show_attr_by_index[])(struct device *, char *) = {
	SHOW(0), SHOW(1), SHOW(2), SHOW(3), SHOW(4), SHOW(5), SHOW(6),
	SHOW(7), SHOW(8), SHOW(9), SHOW(10), SHOW(11), SHOW(12), SHOW(13),
	SHOW(14), SHOW(15), SHOW(16), SHOW(17), SHOW(18), SHOW(19), SHOW(20),
	SHOW(21), SHOW(22), SHOW(23), SHOW(24), SHOW(25), SHOW(26), SHOW(27),
	SHOW(28), SHOW(29), SHOW(30), SHOW(31), SHOW(32), SHOW(33), SHOW(34),
	SHOW(35), SHOW(36), SHOW(37), SHOW(38), SHOW(39), SHOW(40), SHOW(41),
	SHOW(42), SHOW(43), SHOW(44), SHOW(45), SHOW(46), SHOW(47), SHOW(48),
	SHOW(49), SHOW(50), SHOW(51), SHOW(52), SHOW(53), SHOW(54), SHOW(55),
	SHOW(56), SHOW(57), SHOW(58), SHOW(59), SHOW(60), SHOW(61), SHOW(62),
	SHOW(63), SHOW(64), SHOW(65), SHOW(66), SHOW(67), SHOW(68), SHOW(69),
	SHOW(70), SHOW(71), SHOW(72), SHOW(73), SHOW(74), SHOW(75), SHOW(76),
	SHOW(77), SHOW(78), SHOW(79), SHOW(80), SHOW(81), SHOW(82), SHOW(83),
	SHOW(84), SHOW(85), SHOW(86), SHOW(87), SHOW(88), SHOW(89), SHOW(90),
	SHOW(91), SHOW(92), SHOW(93), SHOW(94), SHOW(95), SHOW(96), SHOW(97),
	SHOW(98), SHOW(99), SHOW(100), SHOW(101), SHOW(102), SHOW(103),
	SHOW(104), SHOW(105), SHOW(106), SHOW(107), SHOW(108), SHOW(109),
	SHOW(110), SHOW(111), SHOW(112), SHOW(113), SHOW(114), SHOW(115),
	SHOW(116), SHOW(117), SHOW(118), SHOW(119), SHOW(120), SHOW(121),
	SHOW(122), SHOW(123), SHOW(124), SHOW(125), SHOW(126), SHOW(127),
	SHOW(128), SHOW(129), SHOW(130), SHOW(131), SHOW(132), SHOW(133),
};

#undef DEFINE_SHOW
#undef DEFINE_SHOW_2
#undef SHOW
#undef SHOW_2

#endif /* EFX_USE_KCOMPAT && EFX_HAVE_OLD_DEVICE_ATTRIBUTE */

static int
efx_mcdi_mon_add_attr(struct efx_nic *efx, const char *name,
		      ssize_t (*reader)(struct device *,
					struct device_attribute *, char *),
		      unsigned int index, unsigned int type,
		      unsigned int limit_value)
{
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	struct efx_mcdi_mon_attribute *attr = &hwmon->attrs[hwmon->n_attrs];
	int rc;

	strlcpy(attr->name, name, sizeof(attr->name));
	attr->index = index;
	attr->type = type;
	attr->limit_value = limit_value;
	sysfs_attr_init(&attr->dev_attr.attr);
	attr->dev_attr.attr.name = attr->name;
	attr->dev_attr.attr.mode = S_IRUGO;
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_OLD_DEVICE_ATTRIBUTE)
	if (WARN_ON(hwmon->n_attrs >=
		    ARRAY_SIZE(efx_mcdi_mon_show_attr_by_index)))
		return -ENOMEM;
	attr->dev_attr.show = efx_mcdi_mon_show_attr_by_index[hwmon->n_attrs];
	attr->reader = reader;
#else
	attr->dev_attr.show = reader;
#endif
	rc = device_create_file(&efx->pci_dev->dev, &attr->dev_attr);
	if (rc == 0)
		++hwmon->n_attrs;
	return rc;
}

int efx_mcdi_mon_probe(struct efx_nic *efx)
{
	struct efx_mcdi_mon *hwmon = efx_mcdi_mon(efx);
	unsigned int n_attrs, n_temp = 0, n_cool = 0, n_in = 0;
	u8 outbuf[MC_CMD_SENSOR_INFO_OUT_LENMAX];
	size_t outlen;
	char name[12];
	u32 mask;
	int rc, i, type;

	BUILD_BUG_ON(MC_CMD_SENSOR_INFO_IN_LEN != 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_SENSOR_INFO, NULL, 0,
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < MC_CMD_SENSOR_INFO_OUT_LENMIN)
		return -EIO;

	/* Find out which sensors are present.  Don't create a device
	 * if there are none.
	 */
	mask = MCDI_DWORD(outbuf, SENSOR_INFO_OUT_MASK);
	if (mask == 0)
		return 0;

	/* Check again for short response */
	if (outlen < MC_CMD_SENSOR_INFO_OUT_LEN(hweight32(mask)))
		return -EIO;

	rc = efx_nic_alloc_buffer(efx, &hwmon->dma_buf,
				  4 * MC_CMD_SENSOR_ENTRY_MAXNUM);
	if (rc)
		return rc;

	mutex_init(&hwmon->update_lock);
	efx_mcdi_mon_update(efx);

	/* Allocate space for the maximum possible number of
	 * attributes for this set of sensors: name of the driver plus
	 * value, min, max, crit, alarm and label for each sensor.
	 */
	n_attrs = 1 + 6 * hweight32(mask);
	hwmon->attrs = kcalloc(n_attrs, sizeof(*hwmon->attrs), GFP_KERNEL);
	if (!hwmon->attrs) {
		rc = -ENOMEM;
		goto fail;
	}

	hwmon->device = hwmon_device_register(&efx->pci_dev->dev);
	if (IS_ERR(hwmon->device)) {
		rc = PTR_ERR(hwmon->device);
		goto fail;
	}

	rc = efx_mcdi_mon_add_attr(efx, "name", efx_mcdi_mon_show_name, 0, 0, 0);
	if (rc)
		goto fail;

	for (i = 0, type = -1; ; i++) {
		const char *hwmon_prefix;
		unsigned hwmon_index;
		u16 min1, max1, min2, max2;

		/* Find next sensor type or exit if there is none */
		type++;
		while (!(mask & (1 << type))) {
			type++;
			if (type == 32)
				return 0;
		}

		/* Skip sensors specific to a different port */
		if (efx_mcdi_sensor_type[type].hwmon_type != EFX_HWMON_UNKNOWN &&
		    efx_mcdi_sensor_type[type].port >= 0 &&
		    efx_mcdi_sensor_type[type].port != efx_port_num(efx))
			continue;

		switch (efx_mcdi_sensor_type[type].hwmon_type) {
		case EFX_HWMON_TEMP:
			hwmon_prefix = "temp";
			hwmon_index = ++n_temp; /* 1-based */
			break;
		case EFX_HWMON_COOL:
			/* This is likely to be a heatsink, but there
			 * is no convention for representing cooling
			 * devices other than fans.
			 */
			hwmon_prefix = "fan";
			hwmon_index = ++n_cool; /* 1-based */
			break;
		default:
			hwmon_prefix = "in";
			hwmon_index = n_in++; /* 0-based */
			break;
		}

		min1 = MCDI_ARRAY_FIELD(outbuf, SENSOR_ENTRY,
					SENSOR_INFO_ENTRY, i, MIN1);
		max1 = MCDI_ARRAY_FIELD(outbuf, SENSOR_ENTRY,
					SENSOR_INFO_ENTRY, i, MAX1);
		min2 = MCDI_ARRAY_FIELD(outbuf, SENSOR_ENTRY,
					SENSOR_INFO_ENTRY, i, MIN2);
		max2 = MCDI_ARRAY_FIELD(outbuf, SENSOR_ENTRY,
					SENSOR_INFO_ENTRY, i, MAX2);

		if (min1 != max1) {
			snprintf(name, sizeof(name), "%s%u_input",
				 hwmon_prefix, hwmon_index);
			rc = efx_mcdi_mon_add_attr(
				efx, name, efx_mcdi_mon_show_value, i, type, 0);
			if (rc)
				goto fail;

			snprintf(name, sizeof(name), "%s%u_min",
				 hwmon_prefix, hwmon_index);
			rc = efx_mcdi_mon_add_attr(
				efx, name, efx_mcdi_mon_show_limit,
				i, type, min1);
			if (rc)
				goto fail;

			snprintf(name, sizeof(name), "%s%u_max",
				 hwmon_prefix, hwmon_index);
			rc = efx_mcdi_mon_add_attr(
				efx, name, efx_mcdi_mon_show_limit,
				i, type, max1);
			if (rc)
				goto fail;

			if (min2 != max2) {
				/* Assume max2 is critical value.
				 * But we have no good way to expose min2.
				 */
				snprintf(name, sizeof(name), "%s%u_crit",
					 hwmon_prefix, hwmon_index);
				rc = efx_mcdi_mon_add_attr(
					efx, name, efx_mcdi_mon_show_limit,
					i, type, max2);
				if (rc)
					goto fail;
			}
		}

		snprintf(name, sizeof(name), "%s%u_alarm",
			 hwmon_prefix, hwmon_index);
		rc = efx_mcdi_mon_add_attr(
			efx, name, efx_mcdi_mon_show_alarm, i, type, 0);
		if (rc)
			goto fail;

		if (efx_mcdi_sensor_type[type].label) {
			snprintf(name, sizeof(name), "%s%u_label",
				 hwmon_prefix, hwmon_index);
			rc = efx_mcdi_mon_add_attr(
				efx, name, efx_mcdi_mon_show_label, i, type, 0);
			if (rc)
				goto fail;
		}
	}

fail:
	efx_mcdi_mon_remove(efx);
	return rc;
}

void efx_mcdi_mon_remove(struct efx_nic *efx)
{
	struct siena_nic_data *nic_data = efx->nic_data;
	struct efx_mcdi_mon *hwmon = &nic_data->hwmon;
	unsigned int i;

	for (i = 0; i < hwmon->n_attrs; i++)
		device_remove_file(&efx->pci_dev->dev,
				   &hwmon->attrs[i].dev_attr);
	kfree(hwmon->attrs);
	if (hwmon->device)
		hwmon_device_unregister(hwmon->device);
	efx_nic_free_buffer(efx, &hwmon->dma_buf);
}

#endif /* CONFIG_SFC_MCDI_MON */
