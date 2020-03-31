/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
  /**************************************************************************\
*//*! \file
   ** <L5_PRIVATE L5_HEADER >
   ** \author  slp
   **  \brief  EtherFabric NIC - EFXXXX (aka Falcon) SPI interface
   **     $Id$
   **   \date  2004/08
   **    \cop  (c) Level 5 Networks Limited.
   ** </L5_PRIVATE>
      *//*
        \************************************************************************* */

/*! \cidoxg_include_ci_driver_efab_hardware  */

#ifndef __CI_DRIVER_EFAB_HARDWARE_FALCON_SPI_H__
#define __CI_DRIVER_EFAB_HARDWARE_FALCON_SPI_H__

#ifdef __KERNEL__
#error "UL-only file"
#endif

/*----------------------------------------------------------------------------
 *
 * expected SPI device enumeration on a falcon NIC 
 *
 *---------------------------------------------------------------------------*/

typedef enum {

	FALCON_SPI_DEV_EEPROM_AT25040,
	FALCON_SPI_DEV_EEPROM_MC25XX640,
	FALCON_SPI_DEV_FLASH_AT25F1024,

} falcon_spi_devices;

/* expected device map for a falcon */
#define EE_MAC_0_OFST    0x310
#define EE_MAC_1_OFST    0x318
#define EE_EXPBAR_OFST   0x8000

/* spi commands */
#define SPI_WREN    0x06	// set write enable latch
#define SPI_WRDI    0x04	// reset write enable latch
#define SPI_RDSR    0x05	// read status register
#define SPI_WRSR    0x01	// write status register
#define SPI_READ    0x03	// read data from memory array
#define SPI_WRIT    0x02	// write data into memory array

/* flash specific commands */
#define SPI_FL_SECE    0x52	// erase one sector
#define SPI_FL_CHIE    0x62	// erase all sector
#define SPI_FL_RDID    0x15	// read manufacturer and product ID

/* vendor specific commands */
#define SPI_SST_EWSR    0x50	// SST: enable write to status register

/* 60601F Atmel Flash */
#define DEV_25F1840_DEVID  0x60601F
#define DEV_25F1840_BYTES  EFHW_128K

/* supported eeprom sizes */
#define DEV_AT25040_BYTES   512
#define DEV_MC25XX640_BYTES 8192

/*----------------------------------------------------------------------------
 *
 * SPI low level interface  -- for serial flash and eeprom
 *
 *---------------------------------------------------------------------------*/

extern int
falcon_spi_read_device_id(struct efhw_nic * nic, falcon_spi_devices device);

extern int
falcon_spi_set_write_enable(struct efhw_nic * nic, falcon_spi_devices device);

extern int
falcon_spi_reset_write_enable(struct efhw_nic * nic, falcon_spi_devices device);

extern int
falcon_spi_enable_write_status_register(struct efhw_nic * nic,
					falcon_spi_devices device);

extern int
falcon_spi_read_status_register(struct efhw_nic * nic,
				falcon_spi_devices device);

extern int
falcon_spi_write_status_register(struct efhw_nic * nic,
				 falcon_spi_devices device, uint data);

extern int
falcon_spi_read(struct efhw_nic * nic, falcon_spi_devices device, uint addr);

extern ci_int64
falcon_spi_readq(struct efhw_nic * nic, falcon_spi_devices device, uint addr);

extern int
falcon_sector_erase(struct efhw_nic * nic, falcon_spi_devices device,
		    int sector);

extern int
falcon_chip_erase(struct efhw_nic * nic, falcon_spi_devices device);

extern int
falcon_device_wait(struct efhw_nic * nic, falcon_spi_devices device);

extern int
falcon_spi_read_mac(struct efhw_nic * nic, falcon_spi_devices device,
		    uint offset, ci_uint8 * data);
#endif
