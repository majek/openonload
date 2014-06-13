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

  /**************************************************************************\
*//*! \file falcon_spi.c EtherFabric EFXXXX NIC  SPI interface
   ** <L5_PRIVATE L5_SOURCE>
   ** \author  slp
   **  \brief  Package - driver/efab     EtherFabric NIC driver
   **     $Id$
   **   \date  2004/08
   **    \cop  (c) Level 5 Networks Limited.
   ** </L5_PRIVATE>
   *//*
     \************************************************************************* */

/*! \cidoxg_driver_efab */

#include <ci/efhw/debug.h>
#include <ci/efhw/falcon.h>
#include <ci/driver/efab/hardware.h>
#include <ci/driver/efab/hardware/falcon_spi.h>

#define CHECK_DEVICE(device)                                  \
  EFHW_ASSERT( (device == FALCON_SPI_DEV_EEPROM_AT25040)   || \
               (device == FALCON_SPI_DEV_EEPROM_MC25XX640) || \
               (device == FALCON_SPI_DEV_FLASH_AT25F1024));

#define SELECT_DEVICE(device)                   \
{						\
 switch(device) {				\
  case  FALCON_SPI_DEV_EEPROM_AT25040:		\
    adbcnt = 1;					\
    munge  = 1;					\
    break;					\
  case FALCON_SPI_DEV_EEPROM_MC25XX640:		\
    adbcnt = 2;					\
    munge  = 0;					\
    break;					\
  case FALCON_SPI_DEV_FLASH_AT25F1024:		\
    adbcnt = 3;					\
    munge  = 0;					\
    break;					\
  default:					\
    adbcnt = 0;					\
    munge  = 0;					\
    EFHW_ASSERT(0);				\
  }						\
}

/* Some devices with 9-bit addresses (e.g. AT25040A EEPROM)
 * use bit 3 of the command byte as address bit A8, rather
 * than having a two-byte address.
 */
#define MUNGE(addr, cmd) if (munge && (addr & 0x100)) cmd |= 0x8

/*----------------------------------------------------------------------------
 *
 * SPI low level interface
 *
 *---------------------------------------------------------------------------*/

static int spi_busy(struct efhw_nic * nic)
{
	int busy = 0;
	uint val;

	FALCON_LOCK_DECL;

	FALCON_LOCK_LOCK(nic);
	EFHW_ASSERT(nic->resetting == 0);
	val = readl(EFHW_KVA(nic) + FR_AB_EE_SPI_HCMD_REG_OFST);
	FALCON_LOCK_UNLOCK(nic);

	busy |= (val & (1 << FRF_AB_EE_SPI_HCMD_CMD_EN_LBN));
	busy |= (val & (1 << FRF_AB_EE_WR_TIMER_ACTIVE_LBN));

	EFHW_TRACE("spi_busy: %08x -> %x", val, busy);

	return (busy != 0);
}

static int spi_wait(struct efhw_nic * nic)
{
	int i;

	for (i = 0; i < 1000; i++) {
		if (!spi_busy(nic)) {
			EFHW_TRACE("spi command DONE%s", "");
			return 0;
		}
		ci_udelay(100);
	}
	EFHW_WARN("%s: spi seems to be stuck", __FUNCTION__);
	return -1;
}

static int
falcon_spi_command(struct efhw_nic * nic, falcon_spi_devices device,
		   uint dabcnt, uint rd, uint dummy, uint adbcnt, uint cmd)
{
	/* returns -1 on failure */

	volatile char __iomem *efhw_kva = EFHW_KVA(nic);
	uint val = 0;

	int is_flash = (device == FALCON_SPI_DEV_FLASH_AT25F1024);

	FALCON_LOCK_DECL;

	CHECK_DEVICE(device);

	if (spi_busy(nic)) {
		EFHW_WARN("spi device %d seems to be active", device);
		return -1;
	}

	/* device = 1 for flash 0 for small eeprom                       */
	/* dabcnt = data byte count (obviously)                          */
	/* rd     = 1 for commands that read 0 for commands that write   */
	/* dummy  = dummy bytes count for some commands                  */
	/* adbcnt = number of address bytes associated with this command */
	/* cmd    = the chip specific command                            */

	val = ((1 << FRF_AB_EE_SPI_HCMD_CMD_EN_LBN) |
	       (is_flash << FRF_AB_EE_SPI_HCMD_SF_SEL_LBN) |
	       (dabcnt << FRF_AB_EE_SPI_HCMD_DABCNT_LBN) |
	       (rd << FRF_AB_EE_SPI_HCMD_READ_LBN) |
	       (dummy << FRF_AB_EE_SPI_HCMD_DUBCNT_LBN) |
	       (adbcnt << FRF_AB_EE_SPI_HCMD_ADBCNT_LBN) |
	       (cmd << FRF_AB_EE_SPI_HCMD_ENC_LBN));

	FALCON_LOCK_LOCK(nic);
	EFHW_ASSERT(nic->resetting == 0);
	writeq(val, efhw_kva + FR_AB_EE_SPI_HCMD_REG_OFST);
	writeq(0, efhw_kva + FR_AB_EE_SPI_HCMD_REG_OFST + 8);
	mmiowb();
	FALCON_LOCK_UNLOCK(nic);

	/* wait for spi command to complete */
	return spi_wait(nic);
}

/*--------------------------------------------------------------------
 *
 * Low level interface
 *
 *--------------------------------------------------------------------*/

extern int
falcon_spi_read_device_id(struct efhw_nic * nic, falcon_spi_devices device)
{
	int val, rc;

	FALCON_LOCK_DECL;

	EFHW_ASSERT(device == FALCON_SPI_DEV_FLASH_AT25F1024);

	if ((rc = falcon_spi_command(nic,
				     /* device */ device,
				     /* dabcnt */ 3,
				     /* rd */ 1,
				     /* dummy */ 0,
				     /* adbcnt */ 0,
				     /* cmd    */ SPI_FL_RDID)))
		return rc;

	FALCON_LOCK_LOCK(nic);
	EFHW_ASSERT(nic->resetting == 0);
	val = readl(EFHW_KVA(nic) + FR_AB_EE_SPI_HDATA_REG_OFST);
	FALCON_LOCK_UNLOCK(nic);

	return val & 0xffffff;
}

extern int
falcon_spi_set_write_enable(struct efhw_nic * nic, falcon_spi_devices device)
{
	int rc = falcon_spi_command(nic,
				    /* device */ device,
				    /* dabcnt */ 0,
				    /* rd */ 0,
				    /* dummy */ 0,
				    /* adbcnt */ 0,
				    /* cmd    */ SPI_WREN);
	return rc;
}

extern int
falcon_spi_reset_write_enable(struct efhw_nic * nic, falcon_spi_devices device)
{
	int rc = falcon_spi_command(nic,
				    /* device */ device,
				    /* dabcnt */ 0,
				    /* rd */ 0,
				    /* dummy */ 0,
				    /* adbcnt */ 0,
				    /* cmd    */ SPI_WRDI);

	return rc;
}

extern int
falcon_spi_enable_write_status_register(struct efhw_nic * nic,
					falcon_spi_devices device)
{
	int rc = falcon_spi_command(nic,
				    /* device */ device,
				    /* dabcnt */ 0,
				    /* rd */ 0,
				    /* dummy */ 0,
				    /* adbcnt */ 0,
				    /* cmd    */ SPI_SST_EWSR);
	return rc;
}

extern int
falcon_spi_read_status_register(struct efhw_nic * nic, falcon_spi_devices device)
{
	int rc, val;

	FALCON_LOCK_DECL;

	if ((rc = falcon_spi_command(nic,
				     /* device */ device,
				     /* dabcnt */ 1,
				     /* rd */ 1,
				     /* dummy */ 0,
				     /* adbcnt */ 0,
				     /* cmd    */ SPI_RDSR)))
		return rc;

/*   ci_udelay(10); ?? */


	FALCON_LOCK_LOCK(nic);
	EFHW_ASSERT(nic->resetting == 0);
	val = readl(EFHW_KVA(nic) + FR_AB_EE_SPI_HDATA_REG_OFST);
	FALCON_LOCK_UNLOCK(nic);

	return val & 0xff;
}

extern int
falcon_spi_write_status_register(struct efhw_nic * nic, falcon_spi_devices device,
				 uint data)
{
	int rc;

	FALCON_LOCK_DECL;


	FALCON_LOCK_LOCK(nic);
	EFHW_ASSERT(nic->resetting == 0);
	writeq(data, EFHW_KVA(nic) + FR_AB_EE_SPI_HDATA_REG_OFST);
	writeq(0, EFHW_KVA(nic) + FR_AB_EE_SPI_HDATA_REG_OFST + 8);
	mmiowb();
	FALCON_LOCK_UNLOCK(nic);

	if ((rc = falcon_spi_command(nic,
				     /* device */ device,
				     /* dabcnt */ 1,
				     /* rd */ 0,
				     /* dummy */ 0,
				     /* adbcnt */ 0,
				     /* cmd    */ SPI_WRSR)))
		return rc;

	return 0;
}

extern int
falcon_spi_read(struct efhw_nic * nic, falcon_spi_devices device, uint addr)
{
	int rc, val, cmd = SPI_READ, adbcnt, munge;

	FALCON_LOCK_DECL;

	SELECT_DEVICE(device);

	MUNGE(addr, cmd);


	FALCON_LOCK_LOCK(nic);
	EFHW_ASSERT(nic->resetting == 0);
	writeq(addr, EFHW_KVA(nic) + FR_AB_EE_SPI_HADR_REG_OFST);
	writeq(0, EFHW_KVA(nic) + FR_AB_EE_SPI_HADR_REG_OFST + 8);
	mmiowb();
	FALCON_LOCK_UNLOCK(nic);

	if ((rc = falcon_spi_command(nic,
				     /* device */ device,
				     /* dabcnt */ 4,
				     /* rd */ 1,
				     /* dummy */ 0,
				     /* adbcnt */ adbcnt,
				     /* cmd    */ cmd)))
		return rc;


	FALCON_LOCK_LOCK(nic);
	EFHW_ASSERT(nic->resetting == 0);
	val = readl(EFHW_KVA(nic) + FR_AB_EE_SPI_HDATA_REG_OFST);
	FALCON_LOCK_UNLOCK(nic);

	return val;
}

extern int64_t
falcon_spi_readq(struct efhw_nic * nic, falcon_spi_devices device, uint addr)
{
	int rc, cmd = SPI_READ, adbcnt, munge;
	int64_t val;

	FALCON_LOCK_DECL;

	SELECT_DEVICE(device);

	MUNGE(addr, cmd);


	FALCON_LOCK_LOCK(nic);
	EFHW_ASSERT(nic->resetting == 0);
	writeq(addr, EFHW_KVA(nic) + FR_AB_EE_SPI_HADR_REG_OFST);
	writeq(0, EFHW_KVA(nic) + FR_AB_EE_SPI_HADR_REG_OFST + 8);
	mmiowb();
	FALCON_LOCK_UNLOCK(nic);

	if ((rc = falcon_spi_command(nic,
				     /* device */ device,
				     /* dabcnt */ 0x10,
				     /* rd */ 1,
				     /* dummy */ 0,
				     /* adbcnt */ adbcnt,
				     /* cmd    */ cmd)))
		return rc;


	FALCON_LOCK_LOCK(nic);
	EFHW_ASSERT(nic->resetting == 0);
	val = readq(EFHW_KVA(nic) + FR_AB_EE_SPI_HDATA_REG_OFST);
	FALCON_LOCK_UNLOCK(nic);

	return val;
}


extern int
falcon_sector_erase(struct efhw_nic * nic, falcon_spi_devices device, int sector)
{
	int rc;

	FALCON_LOCK_DECL;

	EFHW_ASSERT(device == FALCON_SPI_DEV_FLASH_AT25F1024);

	FALCON_LOCK_LOCK(nic);

	EFHW_ASSERT(nic->resetting == 0);
	writeq(sector, EFHW_KVA(nic) + FR_AB_EE_SPI_HADR_REG_OFST);
	writeq(0, EFHW_KVA(nic) + FR_AB_EE_SPI_HADR_REG_OFST + 8);
	mmiowb();

	FALCON_LOCK_UNLOCK(nic);

	rc = falcon_spi_command(nic,
				/* device */ FALCON_SPI_DEV_FLASH_AT25F1024,
				/* dabcnt */ 0,
				/* rd */ 0,
				/* dummy */ 0,
				/* adbcnt */ 3,
				/* cmd    */ SPI_FL_SECE);
	return rc;
}

extern int falcon_chip_erase(struct efhw_nic * nic, falcon_spi_devices device)
{
	int rc;
	EFHW_ASSERT(device == FALCON_SPI_DEV_FLASH_AT25F1024);

	rc = falcon_spi_command(nic,
				/* device */ FALCON_SPI_DEV_FLASH_AT25F1024,
				/* dabcnt */ 0,
				/* rd */ 0,
				/* dummy */ 0,
				/* adbcnt */ 0,
				/* cmd    */ SPI_FL_CHIE);

	return rc;
}

extern int falcon_device_wait(struct efhw_nic * nic, falcon_spi_devices device)
{
	int i;
	for (i = 0; i < 10000; i++) {

		/* check the busy bit */
		if (!(falcon_spi_read_status_register(nic, device) & 0x1)) {
			EFHW_TRACE("command DONE for device %d", device);
			return 0;
		}
		ci_udelay(1000);
	}
	EFHW_NOTICE("device %d seems to be stuck ", device);
	return -1;
}

extern int
falcon_spi_read_mac(struct efhw_nic * nic, falcon_spi_devices device, uint offset,
		    uint8_t * data)
{
	uint r0, r1;
	int rc;

	if ((rc = falcon_device_wait(nic, device)))
		return rc;

	r0 = falcon_spi_read(nic, device, offset);

	if ((rc = falcon_device_wait(nic, device)))
		return rc;

	r1 = falcon_spi_read(nic, device, offset + 4);

	/* This does not match Falcon documentation for SF 310/314 but is more sane */
	data[0] = (r0 & 0x000000ff) >> 0;
	data[1] = (r0 & 0x0000ff00) >> 8;
	data[2] = (r0 & 0x00ff0000) >> 16;
	data[3] = (r0 & 0xff000000) >> 24;
	data[4] = (r1 & 0x000000ff) >> 0;
	data[5] = (r1 & 0x0000ff00) >> 8;

	return 0;
}
