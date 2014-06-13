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
*//*! \file alaska.c  Marvell Alaska 80801111
   ** <L5_PRIVATE L5_SOURCE>
   ** \author  slp
   **  \brief  Package - driver/efab    EtherFabric NIC driver
   **     $Id$
   **   \date  7/2004
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

#include <ci/driver/efab/hardware/common.h>
#include <ci/driver/efab/hardware/alaska8080111.h>
#include "efhw_internal.h"

/*--------------------------------------------------------------------
 *
 * Debug
 *
 *--------------------------------------------------------------------*/

#define ALASKA_ASSERT_VALID()                                                \
                          ci_assert(mac);		                     \
                          ci_assert(EFHW_KVA(mac->nic));	             \
                          ci_assert((mac->phy_type == EFHW_PHY_TYPE_ALASKA));

/*--------------------------------------------------------------------
 *
 * Alaska specific GMII Access
 *
 *--------------------------------------------------------------------*/

extern int efab_alaska_irq_status(efhw_mac_t * mac, int port, int *mask)
{
	uint val;
	int rc;

	ALASKA_ASSERT_VALID();

	/* This should also clear the Alaska interrupts */
	if ((rc = mac->gmii_rw(mac, port, ALASKA_INT_STATUS, 0, 0, &val)))
		return rc;

	/* TODO need to make sure that this log line stays less than
	   CI_LOG_LINE_MAX in the case that the register read is scrambled
	   and all bits are set */
	DEBUGLOAD(ci_log
		  ("alaska[%d] INT_STATUS: %s%s%s%s%s%s%s%s%s%s%s%s%s%s", port,
		   (val & 0x0001) ? "jabber " : "",
		   (val & 0x0002) ? "polarity-changed " : "",
		   (val & 0x0010) ? "energy-changed " : "",
		   (val & 0x0020) ? "downshift " : "",
		   (val & 0x0040) ? "MDI-changed " : "",
		   (val & 0x0080) ? "FIFO-error " : "",
		   (val & 0x0100) ? "false-carrier " : "",
		   (val & 0x0200) ? "symbol-error " : "",
		   (val & 0x0400) ? "link-status-changed " : "",
		   (val & 0x0800) ? "auto-neg-complete " : "",
		   (val & 0x1000) ? "page-received " : "",
		   (val & 0x2000) ? "duplex-changed " : "",
		   (val & 0x4000) ? "speed-changed " : "",
		   (val & 0x8000) ? "auto-neg-error " : ""));

	if (mask)
		*mask = val;
	return 0;
}

extern int efab_alaska_irq_init(efhw_mac_t * mac, int port, int enable)
{
	uint val;
	int rc;

	ALASKA_ASSERT_VALID();

	if ((rc = mac->gmii_rw(mac, port, ALASKA_INT_ENABLE, 0, 0, &val)))
		return rc;

	/*! \TODO take more alaska interrupts */
	if (enable) {
		val |= ALASKA_IRQ_LINK_STATUS;
	} else {
		val &= ~ALASKA_IRQ_LINK_STATUS;
	}

	if ((rc = mac->gmii_rw(mac, port, ALASKA_INT_ENABLE, val, 1, 0)))
		return rc;

	DEBUGMAC(ci_log("alaska[%d] %sable interrupts (%x)", port,
			val & ALASKA_IRQ_LINK_STATUS ? "en" : "dis", val));
	return 0;
}

extern int
efab_alaska_technology_ability(const char *msg, int port,
			       int pre_shifted_bit_field,
			       char *buf, int how_much)
{
	/* caller should pre-shift any register read so that 
	   val[0] = technology_ability[0] */

	int len = 0, req = 256;

	uint reg = pre_shifted_bit_field;

	int doit = buf != NULL;

	DEBUGMAC(doit++);
	doit++;

	if (!doit || how_much)
		return req;

	efab_dump("%s[%d] (%x) %s%s%s%s%s%s%s%s%s%s%s%s", msg, port, reg,
		  /* These are as specified for 802 technology ability */
		  reg & EFHW_MAC_10_HD ? "[10BaseT] " : "",
		  reg & EFHW_MAC_10_FD ? "[10BaseT Full Duplex] " : "",
		  reg & EFHW_MAC_100_HD ? "[100BaseT] " : "",
		  reg & EFHW_MAC_100_FD ? "[100BaseT Full Duplex] " : "",
		  reg & EFHW_MAC_100_T4 ? "[100BaseT4] " : "",
		  reg & EFHW_MAC_PAUSE ? "[Pause] " : "",
		  reg & EFHW_MAC_ASYM_PAUSE ? "[Asymmetric Pause] " : "",
		  reg & EFHW_MAC_RESERVED ? "[Reserved] " : "",
		  /* These values have been chosen to be easy to extract from the
		     1000BaseT Status and Control registers */
		  reg & EFHW_MAC_1000_HD ? "[1000BaseT Half Duplex] " : "",
		  reg & EFHW_MAC_1000_FD ? "[1000BaseT Full Duplex] " : "",
		  /* These values have been chosen to not conflict */
		  reg & EFHW_MAC_10000 ? "[10000Gbps Not Supported] " : "",
		  reg & EFHW_MAC_LOOPBACK ? "[PHY Loopback Enabled] " : "");

	return len;
}

extern int
efab_alaska_register_dump(efhw_mac_t * mac, int port, char *buf, int how_much)
{
	/* Alaska PHY chips are GMII capable - lets go take a look */
	uint i, reg[ALASKA_REG_NUM];

	int len = 0, line_size = 28, req = line_size * ALASKA_REG_NUM;

	if (how_much)
		return req;

	ALASKA_ASSERT_VALID();

	/* assuming we're using the Alaska 80801111 */
	for (i = 0; i < ALASKA_REG_NUM; i++) {
		if (mac->gmii_rw(mac, port, i, 0, 0, &reg[i])) {
			ci_log("alaska[%d] reg[%d] **** FAILED ***", port, i);
			return len;
		}
		efab_dump("alaska_%d[%02x] %08x", port, i, reg[i]);
	}
	return len;
}

extern void efab_alaska_status(efhw_mac_t * mac, int port, int verbose)
{
	/* Alaska PHY chips are GMII capable - lets go take a look */
	uint i, reg[ALASKA_REG_NUM];

	ALASKA_ASSERT_VALID();

	/* assuming we're using the Alaska 80801111 */
	for (i = 0; i < ALASKA_REG_NUM; i++) {
		if (mac->gmii_rw(mac, port, i, 0, 0, &reg[i])) {
			ci_log("alaska[%d] reg[%d] **** FAILED ***", port, i);
			return;
		}
		if (verbose)
			ci_log("alaska[%d] reg[%d]=%x", port, i, reg[i]);
	}

	/* save the advertised technology ability of our and link partner's device */
	mac->my_ability = (((reg[ALASKA_AN_ADV] >> 5) & 0x07F) |
			   ((reg[ALASKA_1000T_CONTROL] & 0x300)));

	mac->partner_ability = (((reg[ALASKA_AN_PRT_ABL] >> 5) & 0x07F) |
				((reg[ALASKA_1000T_STATUS] & 0xc00) >> 2));

	/* Status which indicates potential errors should be reported
	   whether or not verbose is selected */
	if (reg[ALASKA_RX_ERR_COUNT]) {
		ci_log("alaska[%d] RX_ERR_COUNT: %d", port,
		       reg[ALASKA_RX_ERR_COUNT]);
	}

	if (!verbose)
		return;		/* XXX quite enough of that */

	efab_alaska_technology_ability("alaska - My autoneg advertisement",
				       port, mac->my_ability, 0, 0);

	efab_alaska_technology_ability("alaska - Partner autoneg advertisement",
				       port, mac->partner_ability, 0, 0);

	/* what a lot of status from such a small chip */
	ci_log("alaska[%d] CONTROL: %s%s%s%s%s%s%s%s%s%s", port,
	       (reg[ALASKA_CONTROL] & 0x8000) ? "RESET " : "",
	       (reg[ALASKA_CONTROL] & 0x4000) ? "LOOPBACK " : "",
	       (reg[ALASKA_CONTROL] & 0x2000) ? "100Mbps " : "",
	       (reg[ALASKA_CONTROL] & 0x1000) ? "Auto-neg-EN " : "",
	       (reg[ALASKA_CONTROL] & 0x0800) ? "power-down " : "",
	       (reg[ALASKA_CONTROL] & 0x0400) ? "isolate " : "",
	       (reg[ALASKA_CONTROL] & 0x0200) ? "restart-auto-neg " : "",
	       (reg[ALASKA_CONTROL] & 0x0100) ? "full-duplex " : "half-duplex ",
	       (reg[ALASKA_CONTROL] & 0x0080) ? "collision-test " : "",
	       (reg[ALASKA_CONTROL] & 0x0040) ? "1000Mbps " : "");

	ci_log("alaska[%d] STATUS: %s%s%s%s", port,
	       (reg[ALASKA_STATUS] & 0x2) ? "jabber " : "",
	       (reg[ALASKA_STATUS] & 0x4) ? "link-up " : "link-down ",
	       (reg[ALASKA_STATUS] & 0x10) ? "remote-fault " : "",
	       (reg[ALASKA_STATUS] & 0x20) ? "auto-neg-complete " : "");

	if ((reg[ALASKA_PHY_ID1] & 0xff0) != 0xcc0)
		ci_log("alaska[%d]: Your PHY probably needs a power cycle",
		       port);

	if (!(verbose & 1))
		return;		/* XXX quite enough of that too */

	ci_log("alaska[%d] PHY_ID:  %x %x", port,
	       reg[ALASKA_PHY_ID0], reg[ALASKA_PHY_ID1]);

	ci_log("alaska[%d] AN_ADV: (%x) %s%s%s%s", port,
	       reg[ALASKA_AN_ADV],
	       (reg[ALASKA_AN_ADV] & 0x8000) ? "adv-next-page " : "",
	       (reg[ALASKA_AN_ADV] & 0x2000) ? "set-remote-fault " : "",
	       (reg[ALASKA_AN_ADV] & 0x0800) ? "asymmetric-pause " : "",
	       (reg[ALASKA_AN_ADV] & 0x0400) ? "mac-pause " : "");

	ci_log("alaska[%d] AN_PRT_ABL: (%x) %s%s%s", port,
	       reg[ALASKA_AN_PRT_ABL],
	       (reg[ALASKA_AN_PRT_ABL] & 0x8000) ? "next-page " : "",
	       (reg[ALASKA_AN_PRT_ABL] & 0x4000) ? "ack " : "",
	       (reg[ALASKA_AN_PRT_ABL] & 0x2000) ? "remote-fault " : "");

	ci_log("alaska[%d] AN_EXP: (%x) %s%s%s%s%s", port,
	       reg[ALASKA_AN_EXP],
	       (reg[ALASKA_AN_EXP] & 0x0001) ? "partner-is-an-able " : "",
	       (reg[ALASKA_AN_EXP] & 0x0002) ? "new-page-received " : "",
	       (reg[ALASKA_AN_EXP] & 0x0004) ? "local-is-an-able " : "",
	       (reg[ALASKA_AN_EXP] & 0x0008) ? "partner-is-np-able " : "",
	       (reg[ALASKA_AN_EXP] & 0x0010) ? "parallel-fault-detected " : "");

	ci_log("alaska[%d] 1000T_STATUS: %s%s%s%s", port,
	       (reg[ALASKA_1000T_STATUS] & 0x1000) ? "remote-RX OK " : "",
	       (reg[ALASKA_1000T_STATUS] & 0x2000) ? "RX OK " : "",
	       (reg[ALASKA_1000T_STATUS] & 0x4000) ? "MASTER " : "SLAVE ",
	       (reg[ALASKA_1000T_STATUS] & 0x8000) ? "FAULT " : "");

	ci_log("alaska[%d] EXT_STATUS: %s%s", port,
	       (reg[ALASKA_EXT_STATUS] & 0x1000) ? "half-duplex-capable " : "",
	       (reg[ALASKA_EXT_STATUS] & 0x2000) ? "full-duplex-capable " : "");

	ci_log("alaska[%d] PHY_STATUS: %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	       port,
	       (reg[ALASKA_PHY_STATUS] & 0x0001) ? "jabber " : "",
	       (reg[ALASKA_PHY_STATUS] & 0x0002) ? "reverse-polarity " : "",
	       (reg[ALASKA_PHY_STATUS] & 0x0004) ? "rx-pause " : "",
	       (reg[ALASKA_PHY_STATUS] & 0x0008) ? "tx-pause " : "",
	       (reg[ALASKA_PHY_STATUS] & 0x0010) ? "sleep " : "",
	       (reg[ALASKA_PHY_STATUS] & 0x0020) ? "downshift " : "",
	       (reg[ALASKA_PHY_STATUS] & 0x0040) ? "MDIX " : "MDI ",
	       ((reg[ALASKA_PHY_STATUS] & 0x0380) == 0x0000) ? "<50m " : "",
	       ((reg[ALASKA_PHY_STATUS] & 0x0380) == 0x0010) ? "50-80m " : "",
	       ((reg[ALASKA_PHY_STATUS] & 0x0380) == 0x0100) ? "80-110m " : "",
	       ((reg[ALASKA_PHY_STATUS] & 0x0380) == 0x0110) ? "110-140m " : "",
	       ((reg[ALASKA_PHY_STATUS] & 0x0380) == 0x0200) ? ">140m " : "",
	       (reg[ALASKA_PHY_STATUS] & 0x0400) ? "link-up " : "link-down ",
	       (reg[ALASKA_PHY_STATUS] & 0x0800) ? "speed&duplex-resolved " :
	       "", (reg[ALASKA_PHY_STATUS] & 0x1000) ? "page-received " : "",
	       (reg[ALASKA_PHY_STATUS] & 0x2000) ? "full-duplex " :
	       "half-duplex ",
	       ((reg[ALASKA_PHY_STATUS] & 0xc000) == 0x0000) ? "10Mbps" : "",
	       ((reg[ALASKA_PHY_STATUS] & 0xc000) == 0x4000) ? "100Mbps" : "",
	       ((reg[ALASKA_PHY_STATUS] & 0xc000) == 0x8000) ? "1000Mbps" : "");

	ci_log("alaska[%d] INT_ENABLE: %x", port, reg[ALASKA_INT_ENABLE]);

	ci_log("alaska[%d] INT_STATUS: %s%s%s%s%s%s%s%s%s%s%s%s%s%s", port,
	       (reg[ALASKA_INT_STATUS] & 0x0001) ? "jabber " : "",
	       (reg[ALASKA_INT_STATUS] & 0x0002) ? "polarity-changed " : "",
	       (reg[ALASKA_INT_STATUS] & 0x0010) ? "energy-changed " : "",
	       (reg[ALASKA_INT_STATUS] & 0x0020) ? "downshift " : "",
	       (reg[ALASKA_INT_STATUS] & 0x0040) ? "MDI-changed " : "",
	       (reg[ALASKA_INT_STATUS] & 0x0080) ? "FIFO-error " : "",
	       (reg[ALASKA_INT_STATUS] & 0x0100) ? "false-carrier " : "",
	       (reg[ALASKA_INT_STATUS] & 0x0200) ? "symbol-error " : "",
	       (reg[ALASKA_INT_STATUS] & 0x0400) ? "link-status-changed " : "",
	       (reg[ALASKA_INT_STATUS] & 0x0800) ? "auto-neg-complete " : "",
	       (reg[ALASKA_INT_STATUS] & 0x1000) ? "page-received " : "",
	       (reg[ALASKA_INT_STATUS] & 0x2000) ? "duplex-changed " : "",
	       (reg[ALASKA_INT_STATUS] & 0x4000) ? "speed-changed " : "",
	       (reg[ALASKA_INT_STATUS] & 0x8000) ? "auto-neg-error " : "");

	ci_log("alaska[%d] EXT_PHY_STATUS: %s%s%s", port,
	       (reg[ALASKA_EXT_PHY_STATUS] & 0x8000) ?
	       "disable-fibre-auto-neg " : "",
	       (reg[ALASKA_EXT_PHY_STATUS] & 0x4000) ?
	       "fibre-auto-neg " : "copper-auto-neg ",
	       (reg[ALASKA_EXT_PHY_STATUS] & 0x2000) ?
	       "fibre-link " : "copper-link ");

	ci_log("alaska[%d] EXT_RX_ERR_COUNT: %d", port,
	       reg[ALASKA_RX_ERR_COUNT]);

}

extern int
efab_alaska_link_up(efhw_mac_t * mac, int port, int dbg, char *buf, int *how)
{
	uint val1, val2;

	int link_up = 0;

	int len = 0, req = 40;

	if (how && *how) {
		*how = req;
		return 0;
	}

	ALASKA_ASSERT_VALID();

	/* ?? seems to require alaska_status to be called before alaska_link_up
	   will correctly report the status of the link - not sure yet whether this
	   is just a timing issue */
	efab_alaska_status(mac, port, 0);

	if (mac->gmii_rw(mac, port, ALASKA_PHY_STATUS, 0, 0, &val1)) {
		ci_log("link_up: alaska[%d] reg[%d] **** FAILED ***",
		       port, ALASKA_PHY_STATUS);
	}

	if (mac->gmii_rw(mac, port, ALASKA_STATUS, 0, 0, &val2)) {
		ci_log("link_up: alaska[%d] reg[%d] **** FAILED ***", port,
		       ALASKA_STATUS);
	}

	link_up = (val1 & 0x0400) && (val2 & 0x0004);

	if (dbg || buf) {
		efab_dump("Etherfabric port[%d] LINK-%s",
			  port, link_up ? "UP" : "DOWN");
	}

	if (how)
		*how = len;
	return link_up;
}

extern void efab_alaska_link_init(efhw_mac_t * mac, int port)
{
	ALASKA_ASSERT_VALID();

	/* This function is called at start of day to bring up the PHYs
	   given the particular manner in which they have been attached to
	   our MAC. Generally it is a good think to do as little as possible
	   here because the PHYs are pretty good at bringing themselves up */

	if (mac->mac_type == EFHW_MAC_TYPE_IXF1002) {
		/* SLP: We can't touch the NXTPG bits on the 8E1111 because being
		   gigabit only we have to to perform autonegotiation manually
		   through reg[0].12 If we mess with the advertisement when doing
		   so, then no link is established. This is an alaska bug, we
		   should watch out for data-sheet updates.
		 */

		DEBUGVERB(ci_log("PHY: (alaska) port[%d] reset", port));

		if (mac->gmii_rw(mac, port, ALASKA_CONTROL, 0x9140, 1, 0)) {
			ci_log("alaska[%d] reg[%d] **** WR FAILED ***", port,
			       ALASKA_CONTROL);
			return;
		}
	}
	return;
}

extern void efab_alaska_reset(efhw_mac_t * mac, int port)
{
	uint val;

	ALASKA_ASSERT_VALID();

	/* Perform a soft-reset on the PHY. Make sure we read the register
	   first because it is possible that we have non factory default
	   settings in it ... see above */

	if (mac->gmii_rw(mac, port, ALASKA_CONTROL, 0, 0, &val)) {
		ci_log("alaska[%d] reg[%d] **** RD FAILED ***", port,
		       ALASKA_CONTROL);
		return;
	}

	val |= 0x8000;

	if (mac->gmii_rw(mac, port, ALASKA_CONTROL, val, 1, 0)) {
		ci_log("alaska[%d] reg[%d] **** WR FAILED ***", port,
		       ALASKA_CONTROL);
		return;
	}

	ci_log("PHY: (alaska) port[%d] reset", port);

	/* Reset bit is self-clearing */
	return;
}

extern void efab_alaska_set_leds(efhw_mac_t * mac, int port)
{
	uint val;

	ALASKA_ASSERT_VALID();

	if (mac->gmii_rw(mac, port, ALASKA_LED_CONTROL, 0, 0, &val)) {
		ci_log("alaska[%d] reg[%d] **** FAILED ***", port,
		       ALASKA_LED_CONTROL);
		return;
	}

	/* If we've managed to autoneg gigabit speed, then LINK LED should only light
	   if we are running at gigabit. Otherwise we link up for any speed.

	   The PHY/PCB default is to link up only for Gigabit */

	val &= ~0x49;

	if (!((mac->options & mac->partner_ability) & EFHW_MAC_GIGABIT_SPEED))
		val |= 0x08;

	val |= 0x41;		/*  TX and RX LED should be driven as a combo  */

	if (mac->gmii_rw(mac, port, ALASKA_LED_CONTROL, val, 1, 0)) {
		ci_log("alaska[%d] reg[%d] **** WR FAILED ***", port,
		       ALASKA_LED_CONTROL);
		return;
	}
}

extern void efab_alaska_set_led_blink_state(efhw_mac_t * mac, int port, int on)
{
	uint val;

	ALASKA_ASSERT_VALID();

	if (mac->gmii_rw(mac, port, ALASKA_LED_OVERRIDE, 0, 0, &val)) {
		ci_log("alaska[%d] reg[%d] **** RD FAILED ***", port,
		       ALASKA_LED_OVERRIDE);
		return;
	}

	val &= 0xFFCF;		/* LED_LINK1000:Normal */

	if (on)
		val |= 0x0010;	/* LED_LINK1000:Blink */

	if (mac->gmii_rw(mac, port, ALASKA_LED_OVERRIDE, val, 1, 0)) {
		ci_log("alaska[%d] reg[%d] **** WR FAILED ***", port,
		       ALASKA_LED_OVERRIDE);
	}
}

extern int
efab_alaska_set_phy_loopback(efhw_mac_t * mac, int port, int loopback)
{
	uint val;

	ALASKA_ASSERT_VALID();

	if (mac->gmii_rw(mac, port, ALASKA_CONTROL, 0, 0, &val)) {
		ci_log("alaska[%d] reg[%d] **** RD FAILED ***", port,
		       ALASKA_CONTROL);
		return -ENODEV;
	}

	val &= ~0x4000;
	if (loopback)
		val |= 0x4000;

	if (mac->gmii_rw(mac, port, ALASKA_CONTROL, val, 1, 0)) {
		ci_log("alaska[%d] reg[%d] **** WR FAILED ***", port,
		       ALASKA_CONTROL);
		return -ENODEV;
	}

	DEBUGVERB(ci_log("PHY: (alaska) port[%d] loopback %s",
			 port, loopback ? "on" : "off"));

	return 0;
}

extern void efab_alaska_set_class_a(efhw_mac_t * mac, int port, int enable)
{
	/* Set up the PHYs for class A emissions compliance. This is also a
	   higher-power consumption mode than class B. */
	uint page, ctrl;

	ALASKA_ASSERT_VALID();

	/* Set up page register for the classA control bits */
	if (mac->gmii_rw(mac, port, ALASKA_EXT_ADDRESS, 0, 0, &page)) {
		ci_log("alaska[%d] reg[%d] **** RD FAILED ***", port,
		       ALASKA_EXT_ADDRESS);
		return;
	}
	if (mac->gmii_rw(mac, port, ALASKA_EXT_ADDRESS, 0x00b, 1, 0)) {
		ci_log("alaska[%d] reg[%d] **** WR FAILED ***", port,
		       ALASKA_EXT_ADDRESS);
	}

	/* Set up the classA control bits */
	if (mac->gmii_rw(mac, port, ALASKA_MISC_CTRL, 0, 0, &ctrl)) {
		ci_log("alaska[%d] reg[%d] **** RD FAILED ***", port,
		       ALASKA_MISC_CTRL);
		return;
	}
	if (enable) {
		ci_log("PHY: (alaska) port[%d] enable class-A compliance",
		       port);
		ctrl |= 0x8000;

	} else {
		ci_log("PHY: (alaska) port[%d] enable class-B compliance",
		       port);
		ctrl &= ~0x8000;
	}

	/* Write out the classA control bits and put the page register back */
	if (mac->gmii_rw(mac, port, ALASKA_MISC_CTRL, ctrl, 1, 0)) {
		ci_log("alaska[%d] reg[%d] **** WR FAILED ***", port,
		       ALASKA_MISC_CTRL);
	}
	if (mac->gmii_rw(mac, port, ALASKA_EXT_ADDRESS, page, 1, 0)) {
		ci_log("alaska[%d] reg[%d] **** WR FAILED ***", port,
		       ALASKA_EXT_ADDRESS);
	}
}

/*! \cidoxg_end */
