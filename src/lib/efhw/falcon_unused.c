/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
*//*! \file falcon_unused.c Unused code deleted from falcon.c
   ** <L5_PRIVATE L5_SOURCE>
   ** \author  sasha
   **  \brief  Package - driver/efab     EtherFabric NIC driver
   **   \date  2007/10
   **    \cop  (c) Level 5 Networks Limited.
   ** </L5_PRIVATE>
   *//*
     \************************************************************************* */

#define BROKEN_FALCON_PHY_ADDR (0)	/* BROKEN REV0 PCB */
#define FALCON_PHY_ADDR_FIXED (1)	/* MOD Board with PHY address fixed */

#define FALCON_ATOMIC_DRIVER_REG       (0xdeadbeef00000011ULL)
#define FALCON_ATOMIC_MAC_STAT_REG     (0xdeadbeef00000013ULL)

/*--------------------------------------------------------------------
 *
 * Mailbox registers - low level interface 
 *
 * carved out to match EF1 which is 4x8bit and 6x32bit registers but
 * watch out because the register access is not interlocked between
 * drivers for the shared registers
 *
 *--------------------------------------------------------------------*/
static void _falcon_nic_mbox_w(efhw_nic_t * nic, uint idx, uint val)
{
	FALCON_LOCK_DECL;
	ci_iohandle_t handle = EFAB_IOHANDLE(nic);
	efhw_ioaddr_t efhw_kva = EFHW_KVA(nic);
	uint rmw = 0, shft = 0;

	CI_BUILD_ASSERT(DRIVER_REG0_KER_OFST == DRIVER_REG0_OFST);
	CI_BUILD_ASSERT(DRIVER_REG1_KER_OFST == DRIVER_REG1_OFST);
	CI_BUILD_ASSERT(DRIVER_REG2_KER_OFST == DRIVER_REG2_OFST);
	CI_BUILD_ASSERT(DRIVER_REG3_KER_OFST == DRIVER_REG3_OFST);
	CI_BUILD_ASSERT(DRIVER_REG4_KER_OFST == DRIVER_REG4_OFST);
	CI_BUILD_ASSERT(DRIVER_REG5_KER_OFST == DRIVER_REG5_OFST);
	CI_BUILD_ASSERT(DRIVER_REG6_KER_OFST == DRIVER_REG6_OFST);
	CI_BUILD_ASSERT(DRIVER_REG7_KER_OFST == DRIVER_REG7_OFST);

	switch (idx) {
	case 0:
		efhw_kva += DRIVER_REG0_OFST;
		rmw = 1;
		shft = 0;
		break;
	case 1:
		efhw_kva += DRIVER_REG0_OFST;
		rmw = 1;
		shft = 8;
		break;
	case 2:
		efhw_kva += DRIVER_REG1_OFST;
		rmw = 1;
		shft = 0;
		break;
	case 3:
		efhw_kva += DRIVER_REG1_OFST;
		rmw = 1;
		shft = 8;
		break;
	case 4:
		efhw_kva += DRIVER_REG2_OFST;
		break;
	case 5:
		efhw_kva += DRIVER_REG3_OFST;
		break;
	case 6:
		efhw_kva += DRIVER_REG4_OFST;
		break;
	case 7:
		efhw_kva += DRIVER_REG5_OFST;
		break;
	case 8:
		efhw_kva += DRIVER_REG6_OFST;
		break;
	case 9:
		efhw_kva += DRIVER_REG7_OFST;
		break;
	default:
		ci_assert(0);
	}

	/* Falcon requires 128 bit atomic access for this register */
	FALCON_LOCK_LOCK(nic);

	if (rmw) {

		ci_assert_lt(val, 0x100);

		val =
		    (ci_get32(handle, efhw_kva) & ~(0xff << shft)) | (val <<
								      shft);
	}

	falcon_write_qq(handle, efhw_kva, val, FALCON_ATOMIC_DRIVER_REG);
	ci_wiob();
	FALCON_LOCK_UNLOCK(nic);
	return;
}

static uint _falcon_nic_mbox_r(efhw_nic_t * nic, uint idx)
{
	FALCON_LOCK_DECL;
	ci_iohandle_t handle = EFAB_IOHANDLE(nic);
	efhw_ioaddr_t efhw_kva = EFHW_KVA(nic);
	uint val, rmw = 0, shft = 0;

	CI_BUILD_ASSERT(DRIVER_REG0_KER_OFST == DRIVER_REG0_OFST);
	CI_BUILD_ASSERT(DRIVER_REG1_KER_OFST == DRIVER_REG1_OFST);
	CI_BUILD_ASSERT(DRIVER_REG2_KER_OFST == DRIVER_REG2_OFST);
	CI_BUILD_ASSERT(DRIVER_REG3_KER_OFST == DRIVER_REG3_OFST);
	CI_BUILD_ASSERT(DRIVER_REG4_KER_OFST == DRIVER_REG4_OFST);
	CI_BUILD_ASSERT(DRIVER_REG5_KER_OFST == DRIVER_REG5_OFST);
	CI_BUILD_ASSERT(DRIVER_REG6_KER_OFST == DRIVER_REG6_OFST);
	CI_BUILD_ASSERT(DRIVER_REG7_KER_OFST == DRIVER_REG7_OFST);

	switch (idx) {
	case 0:
		efhw_kva += DRIVER_REG0_OFST;
		rmw = 1;
		shft = 0;
		break;
	case 1:
		efhw_kva += DRIVER_REG0_OFST;
		rmw = 1;
		shft = 8;
		break;
	case 2:
		efhw_kva += DRIVER_REG1_OFST;
		rmw = 1;
		shft = 0;
		break;
	case 3:
		efhw_kva += DRIVER_REG1_OFST;
		rmw = 1;
		shft = 8;
		break;
	case 4:
		efhw_kva += DRIVER_REG2_OFST;
		break;
	case 5:
		efhw_kva += DRIVER_REG3_OFST;
		break;
	case 6:
		efhw_kva += DRIVER_REG4_OFST;
		break;
	case 7:
		efhw_kva += DRIVER_REG5_OFST;
		break;
	case 8:
		efhw_kva += DRIVER_REG6_OFST;
		break;
	case 9:
		efhw_kva += DRIVER_REG7_OFST;
		break;
	default:
		ci_assert(0);
	}

	/* Falcon requires 128 bit atomic access for this register */
	FALCON_LOCK_LOCK(nic);

	val = ci_get32(handle, efhw_kva);

	if (rmw) {

		val = (val >> shft) & 0xff;

	}
	FALCON_LOCK_UNLOCK(nic);
	return val;
}

static void _host_ipfilter_cache_dump(int nic)
{
	unsigned i;

	ci_log("==== Start of software shadow of falcon filter table");

	for (i = 0; i < FALCON_FILTER_TBL_NUM; i++) {
		falcon_cached_ipfilter *f = host_ipfilter_cache[nic] + i;

		if (f->addr_valid) {
#if FALCON_FULL_FILTER_CACHE
			uint32_t saddr_be32 = CI_BSWAP_BE32(f->saddr_le32);
			uint32_t daddr_be32 = CI_BSWAP_BE32(f->daddr_le32);

			ci_log("nic[%u] filter[%u] tcp=%u full=%du "
			       "src=" CI_IP_PRINTF_FORMAT ":%d "
			       "dest=" CI_IP_PRINTF_FORMAT ":%d",
			       nic, i, f->tcp, f->full,
			       CI_IP_PRINTF_ARGS(&saddr_be32), f->sport_le16,
			       CI_IP_PRINTF_ARGS(&daddr_be32), f->dport_le16);
#else
			ci_log("nic[%u] filter[%u]", nic, i);
#endif
		}
	}

	ci_log("==== End of software shadow of falcon filter table");
}

extern void host_ipfilter_cache_dump(efhw_nic_t * nic)
{
	FALCON_LOCK_DECL;
	FALCON_LOCK_LOCK(nic);
	_host_ipfilter_cache_dump(nic->index);
	FALCON_LOCK_UNLOCK(nic);
}

extern void falcon_nic_ipfilter_sanity(efhw_nic_t * nic)
{
	ci_iohandle_t handle = nic->bar.handle;
	efhw_ioaddr_t efhw_kva = nic->bar.ioaddr;

	FALCON_LOCK_DECL;
	FALCON_LOCK_LOCK(nic);
	_falcon_nic_ipfilter_sanity(handle, efhw_kva);
	FALCON_LOCK_UNLOCK(nic);
}

static inline void _falcon_nic_interrupt_char(efhw_nic_t * nic)
{
	FALCON_LOCK_DECL;
	uint val;
	efhw_ioaddr_t offset;
	ci_iohandle_t handle = EFAB_IOHANDLE(nic);
	efhw_ioaddr_t efhw_kva = EFHW_KVA(nic);

	/* send an interrupt to the char driver */

	/* Lets simplify things a little */
	CI_BUILD_ASSERT(CHAR_INT_CHAR_LBN == KER_INT_CHAR_LBN);
	CI_BUILD_ASSERT(CHAR_INT_CHAR_WIDTH == 1);
	CI_BUILD_ASSERT(KER_INT_CHAR_WIDTH == 1);
	CI_BUILD_ASSERT(CHAR_INT_CHAR_LBN < 32);

	offset = (efhw_kva + INT_EN_REG_CHAR_OFST);

	/* Falcon requires 128 bit atomic access for this register */
	FALCON_LOCK_LOCK(nic);

	val = ci_get32(handle, offset);	/* TODO use nic mask */
	val |= (1 << CHAR_INT_CHAR_LBN);

	ci_log("falcon_nic_interrupt_char: %x -> %x", (int)(offset - efhw_kva),
	       val);

	falcon_write_qq(handle, offset, val, FALCON_ATOMIC_INT_EN_REG);
	ci_wiob();
	FALCON_LOCK_UNLOCK(nic);
}

static inline void _falcon_nic_interrupt_net(efhw_nic_t * nic)
{
	FALCON_LOCK_DECL;
	uint val;
	efhw_ioaddr_t offset;
	ci_iohandle_t handle = EFAB_IOHANDLE(nic);
	efhw_ioaddr_t efhw_kva = EFHW_KVA(nic);

	/* send an interrupt to the net (ker) driver */
	CI_BUILD_ASSERT(CHAR_INT_KER_LBN == KER_INT_KER_LBN);
	CI_BUILD_ASSERT(CHAR_INT_KER_WIDTH == 1);
	CI_BUILD_ASSERT(KER_INT_KER_WIDTH == 1);
	CI_BUILD_ASSERT(CHAR_INT_KER_LBN < 32);

	offset = (efhw_kva + INT_EN_REG_CHAR_OFST);

	/* Falcon requires 128 bit atomic access for this register */
	FALCON_LOCK_LOCK(nic);

	val = ci_get32(handle, offset);	/* TODO use nic mask */
	val |= (1 << CHAR_INT_KER_LBN);

	ci_log("falcon_nic_interrupt_net: %x -> %x", (int)(offset - efhw_kva),
	       val);

	falcon_write_qq(handle, offset, val, FALCON_ATOMIC_INT_EN_REG);
	ci_wiob();
	FALCON_LOCK_UNLOCK(nic);
}

static void falcon_nic_driver_irq(efhw_nic_t * nic, int which)
{
	if (which == 0)
		_falcon_nic_interrupt_net(nic);

	if (which == 1)
		_falcon_nic_interrupt_char(nic);

	/* ?? both - now that would be daring */
}

/*! Perform (G)MII register operations. Missing PHY releated
  information for the 10G mode */
extern int
falcon_mac_wrapper_gmii_rw(int mac_1G, ci_iohandle_t handle,
			   efhw_ioaddr_t efhw_kva, int phy_addr,
			   int reg_addr, uint dat, int wr, uint * dat_out)
{
	uint acc, reg, cs = 0;
	int i;

	if (mac_1G) {
		/* TODO - we need to select the MDIO for 1G or 10G. By default
		   it is set 1G - slee */
		cs = 1 << MD_GC_LBN;
	}

	/* TODO - Falcon FPGA board shorted the phy addr, so a temp fix
	   was done at Sunnyvale, and the secondary phy address (3)
	   is being configure to "0x1A". - slee 8/8/2005.
	   -- this fix was wrong... it did not work -slee
	   -- new mod is made and got it working. --slee 8/24/05
	 */
#if BROKEN_FALCON_PHY_ADDR
	if (phy_addr == 1)
		phy_addr = 0x1A;
	else
#endif
		phy_addr += FALCON_PHY_FIXUP;
	phy_addr &= 0x1f;

	/* hmmm ... seems to leave 0x2 floating high after operation has
	   completed */
	acc = ci_get32(handle, efhw_kva + MD_STAT_REG_OFST);

	if (acc) {
		ci_log("%s: **** GMII in progress **** (%x)", __FUNCTION__,
		       acc);
		return -EINPROGRESS;
	}

	if (mac_1G)
		ci_put32(handle, efhw_kva + MD_PHY_ADR_REG_OFST, 0);
	else
		ci_put32(handle, efhw_kva + MD_PHY_ADR_REG_OFST, phy_addr);

	FALCON_MAC_WRAPPER_PAD(handle, efhw_kva + MD_PHY_ADR_REG_OFST);
	ci_wiob();

#if FALCON_PHY_ADDR_FIXED
	/* TODO - board with latest modification (8/24/05) */
	reg =
	    (reg_addr & 0x1f) << MD_DEV_ADR_LBN | (phy_addr << MD_PRT_ADR_LBN);
#else
	/* TODO - original board with no modifications */
	reg =
	    (reg_addr & 0x1f) << MD_DEV_ADR_LBN | (2 /* ?? */  <<
						   MD_PRT_ADR_LBN);
#endif

	ci_put32(handle, efhw_kva + MD_ID_REG_OFST, reg);
	FALCON_MAC_WRAPPER_PAD(handle, efhw_kva + MD_ID_REG_OFST);
	ci_wiob();

	if (wr) {
		ci_put32(handle, efhw_kva + MD_TXD_REG_OFST, dat);
		FALCON_MAC_WRAPPER_PAD(handle, efhw_kva + MD_TXD_REG_OFST);
		ci_wiob();

		cs |= (1 << MD_WRC_LBN);

		ci_put32(handle, efhw_kva + MD_CS_REG_OFST, cs);
		FALCON_MAC_WRAPPER_PAD(handle, efhw_kva + MD_CS_REG_OFST);
		ci_wiob();
	} else {
		if (mac_1G)
			cs |= (1 << MD_RIC_LBN);
		else
			cs |= (1 << MD_RDC_LBN);

		ci_put32(handle, efhw_kva + MD_CS_REG_OFST, cs);
		FALCON_MAC_WRAPPER_PAD(handle, efhw_kva + MD_CS_REG_OFST);
		ci_wiob();
	}
	for (i = 0; i < 1000; i++) {

		acc = ci_get32(handle, efhw_kva + MD_STAT_REG_OFST);

		if (acc == 0)
			break;

		ci_udelay(1);
	}
	if (i == 1000) {
		ci_log("%s: *** GMII Not complete **** (%x)", __FUNCTION__,
		       acc);

		/* TODO - Need to turn read/write bit off again */
		if (mac_1G)
			cs |= (0 << MD_RIC_LBN | 0 << MD_WRC_LBN);	/* XXXX FIXME */
		else
			cs |= (0 << MD_RDC_LBN | 0 << MD_WRC_LBN);	/* XXXX FIXME */

		ci_put32(handle, efhw_kva + MD_CS_REG_OFST, cs);
		FALCON_MAC_WRAPPER_PAD(handle, efhw_kva + MD_CS_REG_OFST);
		ci_wiob();
		return -ENODATA;
	}

	if (!wr) {

		dat = ci_get32(handle, efhw_kva + MD_RXD_REG_OFST);

		/*\TODO fixme */
		if ((dat & 0xffff) == 0xffff) {
			ci_log("%s: read data %x ** BAD DATA ** ", __FUNCTION__,
			       dat);
			return -ENODATA;
		}

		if (dat_out)
			*dat_out = dat;
	}
	return 0;
}

/*!< request RMON stats from the mac wrapper */
extern int
falcon_mac_wrapper_stats(int mac_1G, ci_iohandle_t handle,
			 efhw_ioaddr_t efhw_kva, int port, uint64_t pa, char *va)
{
	uint64_t cmd;
	int offset;
	if (mac_1G) {
		offset = GDmaDone_offset;
		ci_log("%s: 1G MODE", __FUNCTION__);
	} else {
		offset = XgDmaDone_offset;
		ci_log("%s: 10G MODE", __FUNCTION__);
	}

#if defined(__ci_ul_driver__)
	/* TODO Need to allocate a page of physical memory from the real driver */
	ci_log("%s: not implemented for ul driver", __FUNCTION__);
	return 0;
#endif

	ci_assert_equal(MAC0_STAT_DMA_CMD_LBN, MAC1_STAT_DMA_CMD_LBN);
	ci_assert_equal(MAC0_STAT_DMA_ADR_LBN, MAC0_STAT_DMA_ADR_LBN);

	/* Setup DMA of statistics */
	efhw_kva +=
	    (port ? MAC1_STAT_DMA_REG_KER_OFST : MAC0_STAT_DMA_REG_KER_OFST);

	cmd =
	    ((uint64_t) 1 << MAC0_STAT_DMA_CMD_LBN) | (pa <<
						       MAC0_STAT_DMA_ADR_LBN);

	/* Make sure completion code offset is cleared */
	*((uint32_t *) (va + offset)) = 0;

	/* Request DMA of statistics */
	ci_put64(handle, efhw_kva, cmd);
	ci_put64(handle, efhw_kva + 8, FALCON_ATOMIC_MAC_STAT_REG);
	ci_wiob();
	return 0;
}

/*!< wait for a RMON stats request to complete  */
extern int falcon_mac_wrapper_stats_wait(int mac_1G, char *va)
{
	int i;
	int offset;
	if (mac_1G) {
		offset = GDmaDone_offset;
		ci_log("%s: 1G MODE", __FUNCTION__);
	} else {
		offset = XgDmaDone_offset;
		ci_log("%s: 10G MODE", __FUNCTION__);
	}

	/* Spin until hardware DMA done */
	for (i = 0; i < 100; i++) {

		ci_udelay(20);

		if (*((uint32_t *) (va + offset)) ==
		    0xFFFFFFFF /* completion code */ )
			break;
	}
	if (i == 100) {
		ci_log("%s: DMA failed", __FUNCTION__);
		return -EWOULDBLOCK;
	}

	/* Cleanup */
	*((uint32_t *) (va + offset)) = 0;
	return 0;
}
