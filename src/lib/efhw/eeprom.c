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

  /**************************************************************************\
*//*! \file eeprom.c i2c eeprom interface
   ** <L5_PRIVATE L5_SOURCE>
   ** \author  djr/slp
   **  \brief  Package - driver/efab EtherFabric NIC driver
   **     $Id$
   **   \date  2003
   **    \cop  (c) Level 5 Networks Limited.
   ** </L5_PRIVATE>
   *//*
     \************************************************************************* */

/*! \cidoxg_driver_efab */

/*--------------------------------------------------------------------
 *
 * CI headers
 *
 *--------------------------------------------------------------------*/

#include <ci/driver/efab/hardware.h>


/*--------------------------------------------------------------------
 *
 * i2c bit banging
 *
 *--------------------------------------------------------------------*/

// Make sure that the I2C bus is sane
// ----------------------------------
// It is possible to leave the I2C bus in a broken state where
// the slave device is pulling SDA low.  This is probably
// because it thinks it is still doing a burst read.
// The fix is to waggle the clock line 8 times so that the
// slave will let go of SDA.  If the bus isn't stuck then
// this activity has no effect.  -djc-
static void
eeprom_prepare(ci_iohandle_t handle, volatile char __iomem *efhw_kva)
{
	uint dev;
	int i;

	ci_udelay(EFAB_EEPROM_DELAY);
	dev = ci_get32(handle, efhw_kva + EFAB_EEPROM);

	// ensure that SDA and SCL really are released...
	// (follow the order for a STOP)
	ci_put32(handle, efhw_kva + EFAB_EEPROM, dev | EFAB_EEPROM_SCL);	// SCL -> high
	ci_mb();
	ci_udelay(EFAB_EEPROM_DELAY);

	dev = dev | (EFAB_EEPROM_SDA | EFAB_EEPROM_SCL);	// SCL and SDA -> high

	ci_put32(handle, efhw_kva + EFAB_EEPROM, dev);
	ci_mb();
	ci_udelay(EFAB_EEPROM_DELAY);

	// Blip the clock line about 8 times.
	for (i = 0; i < 9; i++) {
		ci_put32(handle, efhw_kva + EFAB_EEPROM, dev & ~EFAB_EEPROM_SCL);	// SCL -> low
		ci_mb();
		ci_udelay(EFAB_EEPROM_DELAY);

		ci_put32(handle, efhw_kva + EFAB_EEPROM, dev);	// SCL -> high
		ci_mb();
		ci_udelay(EFAB_EEPROM_DELAY);
	}
}

static void
eeprom_release(ci_iohandle_t handle, volatile char __iomem *efhw_kva)
{
	uint dev;
	int i;

	ci_udelay(EFAB_EEPROM_DELAY);
	dev = ci_get32(handle, efhw_kva + EFAB_EEPROM);

	/* Release eeprom lines.  In older boards they were shared
	   with the PHY interrupts but in the newer boards they are
	   not.  To make sure that this works we also need to waggle
	   the clock line (see eeprom_prepare above) */

	dev = dev | (EFAB_EEPROM_SDA | EFAB_EEPROM_SCL);	// SCL and SDA -> high
	ci_put32(handle, efhw_kva + EFAB_EEPROM, dev);
	ci_mb();

	// Blip the clock line about 8 times.
	for (i = 0; i < 9; i++) {
		ci_put32(handle, efhw_kva + EFAB_EEPROM, dev & ~EFAB_EEPROM_SCL);	// SCL -> low
		ci_mb();
		ci_udelay(EFAB_EEPROM_DELAY);

		ci_put32(handle, efhw_kva + EFAB_EEPROM, dev);	// SCL -> high
		ci_mb();
		ci_udelay(EFAB_EEPROM_DELAY);
	}

}

static void
eeprom_start(ci_iohandle_t handle, volatile char __iomem *efhw_kva)
{
	uint dev;

	ci_udelay(EFAB_EEPROM_DELAY);
	dev = ci_get32(handle, efhw_kva + EFAB_EEPROM);

	if ((dev & (EFAB_EEPROM_SDA | EFAB_EEPROM_SCL)) !=
	    (EFAB_EEPROM_SDA | EFAB_EEPROM_SCL)) {
		ci_udelay(EFAB_EEPROM_DELAY);
		ci_put32(handle, efhw_kva + EFAB_EEPROM,
			 dev | (EFAB_EEPROM_SDA | EFAB_EEPROM_SCL));
		ci_mb();
	}
	dev &= ~(EFAB_EEPROM_SDA | EFAB_EEPROM_SCL);

	ci_udelay(EFAB_EEPROM_DELAY);
	ci_put32(handle, efhw_kva + EFAB_EEPROM, dev | EFAB_EEPROM_SCL);
	ci_mb();

	ci_udelay(EFAB_EEPROM_DELAY);
	ci_put32(handle, efhw_kva + EFAB_EEPROM, dev);
	ci_mb();
}

static void
eeprom_stop(ci_iohandle_t handle, volatile char __iomem *efhw_kva)
{
	uint dev;

	ci_udelay(EFAB_EEPROM_DELAY);
	dev = ci_get32(handle, efhw_kva + EFAB_EEPROM);
	ci_check(!(dev & EFAB_EEPROM_SCL));

	if (dev & (EFAB_EEPROM_SDA | EFAB_EEPROM_SCL)) {
		dev &= ~(EFAB_EEPROM_SDA | EFAB_EEPROM_SCL);
		ci_udelay(EFAB_EEPROM_DELAY);
		ci_put32(handle, efhw_kva + EFAB_EEPROM, dev);
		ci_mb();
	}

	ci_udelay(EFAB_EEPROM_DELAY);
	dev |= EFAB_EEPROM_SCL;
	ci_put32(handle, efhw_kva + EFAB_EEPROM, dev);
	ci_mb();

	ci_udelay(EFAB_EEPROM_DELAY);
	dev |= EFAB_EEPROM_SDA;
	ci_put32(handle, efhw_kva + EFAB_EEPROM, dev);
	ci_mb();
}

static void
eeprom_write(ci_iohandle_t handle, volatile char __iomem *efhw_kva,
	     uint8_t data)
{
	int i;
	uint dev;

	ci_udelay(EFAB_EEPROM_DELAY);
	dev = ci_get32(handle, efhw_kva + EFAB_EEPROM);
	ci_mb();
	ci_check(!(dev & EFAB_EEPROM_SCL));

	for (i = 0; i < 8; i++, data <<= 1) {
		if (data & 0x80)
			dev |= EFAB_EEPROM_SDA;
		else
			dev &= ~EFAB_EEPROM_SDA;

		ci_udelay(EFAB_EEPROM_DELAY);
		ci_put32(handle, efhw_kva + EFAB_EEPROM, dev);
		ci_mb();

		ci_udelay(EFAB_EEPROM_DELAY);
		ci_put32(handle, efhw_kva + EFAB_EEPROM, dev | EFAB_EEPROM_SCL);
		ci_mb();

		ci_udelay(EFAB_EEPROM_DELAY);
		ci_put32(handle, efhw_kva + EFAB_EEPROM, dev);
		ci_mb();
	}

	/* Release SDA. */
	if (!(dev & EFAB_EEPROM_SDA)) {
		ci_udelay(EFAB_EEPROM_DELAY);
		ci_put32(handle, efhw_kva + EFAB_EEPROM, dev | EFAB_EEPROM_SDA);
		ci_mb();
	}
}

static uint8_t
eeprom_read(ci_iohandle_t handle, volatile char __iomem *efhw_kva)
{
	uint i, dev, rd;
	uint8_t val = 0;

	ci_udelay(EFAB_EEPROM_DELAY);
	dev = ci_get32(handle, efhw_kva + EFAB_EEPROM);
	ci_mb();
	ci_check(!(dev & EFAB_EEPROM_SCL));

	/* Need to release SDA (ie. not hold it low). */
	if (!(dev & EFAB_EEPROM_SDA)) {
		dev |= EFAB_EEPROM_SDA;
		ci_udelay(EFAB_EEPROM_DELAY);
		ci_put32(handle, efhw_kva + EFAB_EEPROM, dev);
		ci_mb();
	}

	for (i = 0; i < 8; ++i) {
		ci_udelay(EFAB_EEPROM_DELAY);
		ci_put32(handle, efhw_kva + EFAB_EEPROM, dev | EFAB_EEPROM_SCL);
		ci_mb();

		ci_udelay(EFAB_EEPROM_DELAY);
		rd = ci_get32(handle, efhw_kva + EFAB_EEPROM);
		ci_mb();
		val = (val << 1) | ((rd & EFAB_EEPROM_SDA) != 0);

		ci_udelay(EFAB_EEPROM_DELAY);
		ci_put32(handle, efhw_kva + EFAB_EEPROM, dev);
		ci_mb();
	}

	return val;
}

static int
eeprom_check_ack(ci_iohandle_t handle, volatile char __iomem *efhw_kva)
{
	int ack;
	uint dev;

	ci_udelay(EFAB_EEPROM_DELAY);
	dev = ci_get32(handle, efhw_kva + EFAB_EEPROM);
	ci_check(!(dev & EFAB_EEPROM_SCL));

	ci_put32(handle, efhw_kva + EFAB_EEPROM, dev | EFAB_EEPROM_SCL);
	ci_mb();

	ci_udelay(EFAB_EEPROM_DELAY);
	ack = ci_get32(handle, efhw_kva + EFAB_EEPROM) & EFAB_EEPROM_SDA;

	ci_udelay(EFAB_EEPROM_DELAY);
	ci_put32(handle, efhw_kva + EFAB_EEPROM, ack & ~EFAB_EEPROM_SCL);
	ci_mb();

	return ack != 0;
}

static void
eeprom_send_ack(ci_iohandle_t handle, volatile char __iomem *efhw_kva)
{
	uint dev;

	ci_udelay(EFAB_EEPROM_DELAY);
	dev = ci_get32(handle, efhw_kva + EFAB_EEPROM);
	ci_check(!(dev & EFAB_EEPROM_SCL));

	ci_udelay(EFAB_EEPROM_DELAY);
	dev &= ~EFAB_EEPROM_SDA;	/* Drive SDA low */
	ci_put32(handle, efhw_kva + EFAB_EEPROM, dev);
	ci_mb();

	ci_udelay(EFAB_EEPROM_DELAY);
	dev |= EFAB_EEPROM_SCL;	/* Drive SCL high */
	ci_put32(handle, efhw_kva + EFAB_EEPROM, dev);
	ci_mb();

	ci_udelay(EFAB_EEPROM_DELAY);
	dev &= ~EFAB_EEPROM_SCL;	/* Drive SCL low */
	ci_put32(handle, efhw_kva + EFAB_EEPROM, dev);
	ci_mb();

	ci_udelay(EFAB_EEPROM_DELAY);
	dev |= EFAB_EEPROM_SDA;	/* Release SDA -> high */
	ci_put32(handle, efhw_kva + EFAB_EEPROM, dev & ~EFAB_EEPROM_SCL);
	ci_mb();

	return;
}

int
efab_eeprom_read_offset(ci_iohandle_t handle,
			volatile char __iomem *efhw_kva,
			uint8_t offset)
{
	int result;

	eeprom_prepare(handle, efhw_kva);	// makes sure that the bus is in a sane state
	eeprom_start(handle, efhw_kva);

	eeprom_write(handle, efhw_kva, EFAB_EEPROM_WRITE_SELECT);
	if (eeprom_check_ack(handle, efhw_kva)) {
		ci_log
		    ("eeprom_read_offset_n: failed writing first control byte");
		return -EIO;
	}

	eeprom_write(handle, efhw_kva, offset);
	if (eeprom_check_ack(handle, efhw_kva)) {
		eeprom_release(handle, efhw_kva);	// djc
		ci_log("eeprom_read_offset_n: failed writing offset byte");
		return -EIO;
	}

	eeprom_stop(handle, efhw_kva);
	eeprom_start(handle, efhw_kva);

	eeprom_write(handle, efhw_kva, EFAB_EEPROM_READ_SELECT);
	if (eeprom_check_ack(handle, efhw_kva)) {
		eeprom_release(handle, efhw_kva);	// djc
		ci_log
		    ("eeprom_read_offset_n: failed writing second control byte");
		return -EIO;
	}

	result = eeprom_read(handle, efhw_kva);

	eeprom_stop(handle, efhw_kva);
	eeprom_release(handle, efhw_kva);

	return result;
}

int
efab_eeprom_read_offset_n(ci_iohandle_t handle,
			  volatile char __iomem *efhw_kva,
			  uint8_t offset, int n, uint8_t * data)
{
	int i;

	eeprom_prepare(handle, efhw_kva);	// makes sure that the bus is in a sane state
	eeprom_start(handle, efhw_kva);

	eeprom_write(handle, efhw_kva, EFAB_EEPROM_WRITE_SELECT);
	if (eeprom_check_ack(handle, efhw_kva)) {
		eeprom_release(handle, efhw_kva);	// djc
		ci_log
		    ("eeprom_read_offset_n: failed writing first control byte");
		return -EIO;
	}

	eeprom_write(handle, efhw_kva, offset);
	if (eeprom_check_ack(handle, efhw_kva)) {
		eeprom_release(handle, efhw_kva);	// djc
		ci_log("eeprom_read_offset_n: failed writing offset byte");
		return -EIO;
	}

	eeprom_stop(handle, efhw_kva);
	eeprom_start(handle, efhw_kva);

	eeprom_write(handle, efhw_kva, EFAB_EEPROM_READ_SELECT);
	if (eeprom_check_ack(handle, efhw_kva)) {
		eeprom_release(handle, efhw_kva);	// djc
		ci_log
		    ("eeprom_read_offset_n: failed writing second control byte");
		return -EIO;
	}
	// do all but the last one in a loop
	for (i = 0; i < n - 1; i++) {
		data[i] = eeprom_read(handle, efhw_kva);
		eeprom_send_ack(handle, efhw_kva);
	}
	// last one does not need an ACK
	data[i] = eeprom_read(handle, efhw_kva);

	eeprom_stop(handle, efhw_kva);
	eeprom_release(handle, efhw_kva);

	return 0;
}

extern int
efab_eeprom_write_offset(ci_iohandle_t handle,
			 volatile char __iomem *efhw_kva,
			 uint8_t offset, uint8_t data)
{

// This is the magic number which controls how many times
// we poll to see whether the byte-write operation has completed
#define EFAB_EEPROM_ACK_POLL_LOOPS   16

// Note:
// -----
// It is possible to put the polling loop at the beginning of the
// byte-write code, but if the next thing you do isn't a byte write
// it will fail because the EEPROM will be busy.
// So we'll put the poll at the end like it says in the data sheet
// and waste perhaps one byte-time per write, which is insignificant.

	int i;

	eeprom_prepare(handle, efhw_kva);	// makes sure that the bus is in a sane state
	eeprom_start(handle, efhw_kva);

	// First we have to write the control code, offset and data byte....
	eeprom_write(handle, efhw_kva, EFAB_EEPROM_WRITE_SELECT);
	if (eeprom_check_ack(handle, efhw_kva)) {
		eeprom_release(handle, efhw_kva);	// djc
		ci_log("efab_eeprom_write_offset: failed writing control byte");
		return -EIO;
	}

	eeprom_write(handle, efhw_kva, offset);
	if (eeprom_check_ack(handle, efhw_kva)) {
		eeprom_release(handle, efhw_kva);	// djc
		ci_log("efab_eeprom_write_offset: failed writing offset byte");
		return -EIO;
	}
	// This data byte should be acknowledged by the EEPROM
	eeprom_write(handle, efhw_kva, data);
	if (eeprom_check_ack(handle, efhw_kva)) {
		eeprom_release(handle, efhw_kva);	// djc
		ci_log("efab_eeprom_write_offset: failed writing data byte");
		return -EIO;
	}

	eeprom_stop(handle, efhw_kva);

	// Now the EEPROM is supposed to go off and commit the byte to
	// memory.  This takes a while; we have to poll to see when it
	// has finished......
	for (i = 0; i < EFAB_EEPROM_ACK_POLL_LOOPS; i++) {
		eeprom_start(handle, efhw_kva);
		eeprom_write(handle, efhw_kva, EFAB_EEPROM_WRITE_SELECT);
		if (eeprom_check_ack(handle, efhw_kva)) {
			if (i == EFAB_EEPROM_ACK_POLL_LOOPS) {
				// see if that was the last pass....
				ci_log
				    ("efab_eeprom_write_offset: failed while polling for ack after write");
				eeprom_release(handle, efhw_kva);	// djc
				return -EIO;
			}
			eeprom_stop(handle, efhw_kva);
			ci_udelay(EFAB_EEPROM_DELAY_WR);	// essential!
		} else {
			i = EFAB_EEPROM_ACK_POLL_LOOPS;
			eeprom_stop(handle, efhw_kva);	// give up
		}
	}

	eeprom_release(handle, efhw_kva);	// djc
	return 0;
}

/*! \cidoxg_end */
