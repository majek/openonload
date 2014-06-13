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
*//*! \file nic_unused.c unused code from nic.c
   ** <L5_PRIVATE L5_SOURCE>
   ** \author  sasha
   **  \brief  Package - driver/efab    EtherFabric NIC driver
   **     $Id$
   **   \date  2007/10
   **    \cop  (c) Level 5 Networks Limited.
   ** </L5_PRIVATE>
   *//*
     \************************************************************************* */

/*--------------------------------------------------------------------
 *
 * Interrupt management and test code 
 *
 *--------------------------------------------------------------------*/

/*--------------------------------------------------------------------
 *
 * ci_interrupt_t - control interface for NIC interrupts
 *
 *       int ci_interrupt_ctrl( ci_fd_t, ci_interrupt_t * )
 *
 *--------------------------------------------------------------------*/

/*! Comment? */
typedef struct ci_interrupt_s {
	uint32_t op;
#define			CI_INTERRUPT_OP_ENABLE	0x1
#define			CI_INTERRUPT_OP_DISABLE	0x2
	/* in/out - interrupt mask information */
	uint32_t mask;
} ci_interrupt_t;

extern int _efhw_nic_interrupt_ctrl(efhw_nic_t * nic, ci_interrupt_t * io)
{
	int rc = 0;

	if (io->op & CI_INTERRUPT_OP_ENABLE) {
		if (!efhw_nic_have_hw(nic))
			return -ENODEV;
		/* enable interrupts and copy out new kernel interrupt mask */
		efhw_nic_interrupt_enable(nic);
		io->mask = nic->irq_mask[0];
	}

	if (io->op & CI_INTERRUPT_OP_DISABLE) {
		if (!efhw_nic_have_hw(nic))
			return -ENODEV;
		/* disable interrupts and copy out new kernel interrupt mask */
		efhw_nic_interrupt_disable(nic);
		io->mask = nic->irq_mask[0];
	}

	return rc;
}

/*! Set the NICs current MAC address for a given port (i.e not permanent) */
extern int efhw_nic_set_mac_addr(efhw_nic_t * nic, int port, uint8_t * mac)
{
	ci_assert(nic);
	ci_assert_equal(nic->magic, CI_EFAB_NIC_MAGIC);

	return efab_gmac_set_mac_addr(nic, port, mac);
}

/*--------------------------------------------------------------------
 *
 * Query Link-Status
 *
 *--------------------------------------------------------------------*/

/*! Test whether Ethernet Link is up or Down */
extern int efhw_nic_link_up(efhw_nic_t * nic, int port)
{
	ci_assert(nic);
	ci_assert_equal(nic->magic, CI_EFAB_NIC_MAGIC);

	return efab_gmac_link_up(nic, port, 0, 0);
}

/*--------------------------------------------------------------------
 *
 * Start LED Blinking
 *
 *--------------------------------------------------------------------*/

/*! Start the Link-state LEDs on a given port blinking */
extern void efhw_nic_set_led_blink_state(efhw_nic_t * nic, int port, int on)
{
	ci_assert(nic);
	ci_assert_equal(nic->magic, CI_EFAB_NIC_MAGIC);

	efab_gmac_set_led_blink_state(nic, port, on);
}

/*--------------------------------------------------------------------
 *
 * Set PHY loopback mode
 *
 *--------------------------------------------------------------------*/

/*! Set the PHY in loopback mode */
extern int efhw_nic_set_phy_loopback(efhw_nic_t * nic, int port, int loopback)
{
	ci_assert(nic);
	ci_assert_equal(nic->magic, CI_EFAB_NIC_MAGIC);

	return efab_gmac_set_phy_loopback(nic, port, loopback);
}

/*--------------------------------------------------------------------
 *
 * MTU Configuration
 *
 *--------------------------------------------------------------------*/

extern int efhw_nic_set_mtu(efhw_nic_t * nic, int port, unsigned int mtu)
{
	ci_assert(nic);
	ci_assert_equal(nic->magic, CI_EFAB_NIC_MAGIC);
	ci_assert_ge(port, 0);
	ci_assert_lt(port, EFAB_PORT_MAX);

	DEBUGNIC(ci_log("efhw_nic_set_mtu: port=%d old=%d new=%d",
			port, nic->mtu[port], mtu));
	nic->mtu[port] = mtu;

	return efab_gmac_set_pkt_max_size(nic, port, mtu);
}
