/*
** Copyright 2005-2016  Solarflare Communications Inc.
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
 * Copyright 2006-2015 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/random.h>
#include "net_driver.h"
#include "bitfield.h"
#include "efx.h"
#include "nic.h"
#include "farch_regs.h"
#include "io.h"
#include "workarounds.h"
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "selftest.h"
#include "sriov.h"
#include "siena_sriov.h"

/* Hardware control for SFC9000 family including SFL9021 (aka Siena). */

#ifdef EFX_NOT_UPSTREAM
static bool rx_hash_insert = true;
module_param(rx_hash_insert, bool, 0444);
MODULE_PARM_DESC(rx_hash_insert,
		 "[SFC9000-family] Enable insertion of flow hash in RX buffers");
#endif

static void siena_init_wol(struct efx_nic *efx);

static inline bool maranello_enabled(struct siena_nic_data *nic)
{
	return (nic->caps & (1 << MC_CMD_CAPABILITIES_TURBO_ACTIVE_LBN));
}

static inline bool maranello_possible(struct siena_nic_data *nic)
{
	return (nic->caps & (1 << MC_CMD_CAPABILITIES_TURBO_LBN));
}

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_AOE)
static inline bool aoe_enabled(struct siena_nic_data *nic)
{
	return (nic->caps & (1 << MC_CMD_CAPABILITIES_AOE_LBN));
}

static inline bool aoe_active(struct siena_nic_data *nic)
{
	return (nic->caps & (1 << MC_CMD_CAPABILITIES_AOE_ACTIVE_LBN));
}
#endif

static void siena_push_irq_moderation(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;
	efx_dword_t timer_cmd;

	if (channel->irq_moderation_us) {
		unsigned int ticks;

		ticks = efx_usecs_to_ticks(efx, channel->irq_moderation_us);
		EFX_POPULATE_DWORD_2(timer_cmd,
				     FRF_CZ_TC_TIMER_MODE,
				     FFE_CZ_TIMER_MODE_INT_HLDOFF,
				     FRF_CZ_TC_TIMER_VAL,
				     ticks - 1);
	} else {
		EFX_POPULATE_DWORD_2(timer_cmd,
				     FRF_CZ_TC_TIMER_MODE,
				     FFE_CZ_TIMER_MODE_DIS,
				     FRF_CZ_TC_TIMER_VAL, 0);
	}
	efx_writed_page_locked(channel->efx, &timer_cmd, FR_BZ_TIMER_COMMAND_P0,
			       channel->channel);
}

void siena_prepare_flush(struct efx_nic *efx)
{
	if (efx->fc_disable++ == 0)
		efx_mcdi_set_mac(efx);
}

void siena_finish_flush(struct efx_nic *efx)
{
	if (--efx->fc_disable == 0)
		efx_mcdi_set_mac(efx);
}

static int siena_test_sram(struct efx_nic *efx,
			void (*pattern)(unsigned int, efx_qword_t *, int, int),
			int a, int b)
{
	void __iomem *membase = efx->membase + FR_BZ_BUF_FULL_TBL;
	int finish = efx->sram_lim_qw;
	efx_qword_t buf1, buf2;
	efx_oword_t reg;
	int wptr = 0, rptr = 0;

	/* Move descriptor caches out into space so we can treat all
	 * SRAM as buffer table.  These registers will be restored by
	 * a following reset. */
	EFX_POPULATE_OWORD_1(reg, FRF_AZ_SRM_RX_DC_BASE_ADR, finish);
	efx_writeo(efx, &reg, FR_AZ_SRM_RX_DC_CFG);
	EFX_POPULATE_OWORD_1(reg, FRF_AZ_SRM_TX_DC_BASE_ADR, finish + 64);
	efx_writeo(efx, &reg, FR_AZ_SRM_TX_DC_CFG);

	while (wptr < finish) {
		pattern(wptr, &buf1, a, b);
		efx_sram_writeq(efx, membase, &buf1, wptr);
		wptr++;

		/* Buffer table writes are not performed synchronously
		 * but go through a 128-entry FIFO, so we must switch
		 * from writing to reading after at most 128 writes.
		 * We choose 125 to make the following calculation
		 * result in a round number. */
		if ((wptr - rptr) < 125 && wptr < finish)
			continue;

		/* The SRAM arbiter will allow 2 writes per 8 cycles
		 * with a cycle time of 8 ns.  Each MMIO access takes
		 * at least one cycle.  So in order to avoid reads
		 * overtaking writes we must wait for at least
		 * 125 * (8 / 2 - 2) * 8 ns = 2 us */
		udelay(2);

		for (; rptr < wptr; ++rptr) {
			pattern(rptr, &buf1, a, b);
			efx_sram_readq(efx, membase, &buf2, rptr);

			if (!memcmp(&buf1, &buf2, sizeof(buf1)))
				continue;

			netif_err(efx, hw, efx->net_dev,
				  "sram test failed at index 0x%x. wrote "
				  EFX_QWORD_FMT" read "EFX_QWORD_FMT"\n",
				  rptr, EFX_QWORD_VAL(buf1),
				  EFX_QWORD_VAL(buf2));
			return -EIO;
		}
	}

	return 0;
}

static const struct efx_farch_register_test siena_register_tests[] = {
	{ FR_AZ_ADR_REGION,
	  EFX_OWORD32(0x0003FFFF, 0x0003FFFF, 0x0003FFFF, 0x0003FFFF) },
	{ FR_CZ_USR_EV_CFG,
	  EFX_OWORD32(0x000103FF, 0x00000000, 0x00000000, 0x00000000) },
	{ FR_AZ_RX_CFG,
	  EFX_OWORD32(0xFFFFFFFE, 0xFFFFFFFF, 0x0003FFFF, 0x00000000) },
	{ FR_AZ_TX_CFG,
	  EFX_OWORD32(0x7FFF0037, 0xFFFF8000, 0xFFFFFFFF, 0x03FFFFFF) },
	{ FR_AZ_TX_RESERVED,
	  EFX_OWORD32(0xFFFEFE80, 0x1FFFFFFF, 0x020000FE, 0x007FFFFF) },
	{ FR_AZ_SRM_TX_DC_CFG,
	  EFX_OWORD32(0x001FFFFF, 0x00000000, 0x00000000, 0x00000000) },
	{ FR_AZ_RX_DC_CFG,
	  EFX_OWORD32(0x00000003, 0x00000000, 0x00000000, 0x00000000) },
	{ FR_AZ_RX_DC_PF_WM,
	  EFX_OWORD32(0x000003FF, 0x00000000, 0x00000000, 0x00000000) },
	{ FR_BZ_DP_CTRL,
	  EFX_OWORD32(0x00000FFF, 0x00000000, 0x00000000, 0x00000000) },
	{ FR_BZ_RX_RSS_TKEY,
	  EFX_OWORD32(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF) },
	{ FR_CZ_RX_RSS_IPV6_REG1,
	  EFX_OWORD32(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF) },
	{ FR_CZ_RX_RSS_IPV6_REG2,
	  EFX_OWORD32(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF) },
	{ FR_CZ_RX_RSS_IPV6_REG3,
	  EFX_OWORD32(0xFFFFFFFF, 0xFFFFFFFF, 0x00000007, 0x00000000) },
};

static const struct efx_farch_table_test siena_table_tests[] = {
	{ FR_BZ_RX_FILTER_TBL0,
	  FR_BZ_RX_FILTER_TBL0_STEP, FR_BZ_RX_FILTER_TBL0_ROWS,
	  EFX_OWORD32(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x000003FF) },
	{ FR_CZ_RX_MAC_FILTER_TBL0,
	  FR_CZ_RX_MAC_FILTER_TBL0_STEP, FR_CZ_RX_MAC_FILTER_TBL0_ROWS,
	  EFX_OWORD32(0xFFFF0FFF, 0xFFFFFFFF, 0x00000E7F, 0x00000000) },
	{ FR_BZ_RX_DESC_PTR_TBL,
	  FR_BZ_RX_DESC_PTR_TBL_STEP, FR_CZ_RX_DESC_PTR_TBL_ROWS,
	  EFX_OWORD32(0xFFFFFFFE, 0x0FFFFFFF, 0x01800000, 0x00000000) },
	{ FR_BZ_TX_DESC_PTR_TBL,
	  FR_BZ_TX_DESC_PTR_TBL_STEP, FR_CZ_TX_DESC_PTR_TBL_ROWS,
	  EFX_OWORD32(0xFFFFFFFE, 0x0FFFFFFF, 0x0C000000, 0x00000000) },
	{ FR_BZ_TIMER_TBL,
	  FR_BZ_TIMER_TBL_STEP, FR_CZ_TIMER_TBL_ROWS,
	  EFX_OWORD32(0x3FFFFFFF, 0x00000000, 0x00000000, 0x00000000) },
	{ FR_CZ_TX_FILTER_TBL0,
	  FR_CZ_TX_FILTER_TBL0_STEP, FR_CZ_TX_FILTER_TBL0_ROWS,
	  EFX_OWORD32(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x000013FF) },
	{ FR_CZ_TX_MAC_FILTER_TBL0,
	  FR_CZ_TX_MAC_FILTER_TBL0_STEP, FR_CZ_TX_MAC_FILTER_TBL0_ROWS,
	  EFX_OWORD32(0xFFFF07FF, 0xFFFFFFFF, 0x0000007F, 0x00000000) },
};

static int siena_test_chip(struct efx_nic *efx, struct efx_self_tests *tests)
{
	enum reset_type reset_method = RESET_TYPE_ALL;
	int rc, rc2;

	efx_reset_down(efx, reset_method);

	/* Reset the chip immediately so that it is completely
	 * quiescent regardless of what any VF driver does.
	 */
	rc = efx_mcdi_reset(efx, reset_method);
	if (rc)
		goto out;

	tests->memory = efx_test_memory(efx) ? -1 : 1;
	tests->registers =
		efx_farch_test_registers(efx, siena_register_tests,
					 ARRAY_SIZE(siena_register_tests))
		? -1 : 1;

	rc = efx_mcdi_reset(efx, reset_method);
out:
	rc2 = efx_reset_up(efx, reset_method, rc == 0);
	return rc ? rc : rc2;
}

static int
siena_test_tables(struct efx_nic *efx,
		  void (*pattern)(unsigned int, efx_qword_t *, int, int),
		  int a, int b)
{
	int rc, i;

	rc = siena_test_sram(efx, pattern, a, b);
	if (rc)
		return rc;

	for (i = 0; i < ARRAY_SIZE(siena_table_tests); i++) {
		rc = efx_farch_test_table(efx, &siena_table_tests[i],
					  pattern, a, b);
		if (rc)
			return rc;
	}

	return 0;
}

/**************************************************************************
 *
 * PTP
 *
 **************************************************************************
 */

#ifdef CONFIG_SFC_PTP

static void siena_ptp_write_host_time(struct efx_nic *efx, u32 host_time)
{
	_efx_writed(efx, cpu_to_le32(host_time),
		    FR_CZ_MC_TREG_SMEM + MC_SMEM_P0_PTP_TIME_OFST);
}

static int siena_ptp_set_ts_config(struct efx_nic *efx,
				   struct hwtstamp_config *init)
{
	int rc;

	switch (init->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		/* if TX timestamping is still requested then leave PTP on */
		return efx_ptp_change_mode(efx,
					   init->tx_type != HWTSTAMP_TX_OFF,
					   efx_ptp_get_mode(efx));
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
		init->rx_filter = HWTSTAMP_FILTER_PTP_V1_L4_EVENT;
		return efx_ptp_change_mode(efx, true, MC_CMD_PTP_MODE_V1);
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
		init->rx_filter = HWTSTAMP_FILTER_PTP_V2_L4_EVENT;
		rc = efx_ptp_change_mode(efx, true,
					 MC_CMD_PTP_MODE_V2_ENHANCED);
		/* bug 33070 - old versions of the firmware do not support the
		 * improved UUID filtering option. Similarly old versions of the
		 * application do not expect it to be enabled. If the firmware
		 * does not accept the enhanced mode, fall back to the standard
		 * PTP v2 UUID filtering. */
		if (rc != 0)
			rc = efx_ptp_change_mode(efx, true, MC_CMD_PTP_MODE_V2);
		return rc;
	default:
		return -ERANGE;
	}
}

#endif /* CONFIG_SFC_PTP */

/**************************************************************************
 *
 * Device reset
 *
 **************************************************************************
 */

static enum reset_type siena_map_reset_reason(enum reset_type reason)
{
	return RESET_TYPE_RECOVER_OR_ALL;
}

static int siena_map_reset_flags(u32 *flags)
{
	enum {
		SIENA_RESET_PORT = (ETH_RESET_DMA | ETH_RESET_FILTER |
				    ETH_RESET_OFFLOAD | ETH_RESET_MAC |
				    ETH_RESET_PHY),
		SIENA_RESET_MC = (SIENA_RESET_PORT |
				  ETH_RESET_MGMT << ETH_RESET_SHARED_SHIFT),
	};

	if ((*flags & SIENA_RESET_MC) == SIENA_RESET_MC) {
		*flags &= ~SIENA_RESET_MC;
		return RESET_TYPE_WORLD;
	}

	if ((*flags & SIENA_RESET_PORT) == SIENA_RESET_PORT) {
		*flags &= ~SIENA_RESET_PORT;
		return RESET_TYPE_ALL;
	}

	/* no invisible reset implemented */

	return -EINVAL;
}

#ifdef CONFIG_EEH
/* When a PCI device is isolated from the bus, a subsequent MMIO read is
 * required for the kernel EEH mechanisms to notice. As the Solarflare driver
 * was written to minimise MMIO read (for latency) then a periodic call to check
 * the EEH status of the device is required so that device recovery can happen
 * in a timely fashion.
 */
static void siena_monitor(struct efx_nic *efx)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_EEH_DEV_CHECK_FAILURE)
	struct eeh_dev *eehdev =
		of_node_to_eeh_dev(pci_device_to_OF_node(efx->pci_dev));

	eeh_dev_check_failure(eehdev);
#else
	struct pci_dev *pcidev = efx->pci_dev;
	struct device_node *dn = pci_device_to_OF_node(pcidev);

	eeh_dn_check_failure(dn, pcidev);
#endif
}
#endif

static ssize_t siena_show_turbo(struct device *dev,
				struct device_attribute *attr,
				char *buff)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));

	return sprintf(buff, "%u\n", maranello_enabled(efx->nic_data));
}

static DEVICE_ATTR(turbo_mode, S_IRUGO, siena_show_turbo, NULL);

static int siena_probe_nvconfig(struct efx_nic *efx)
{
	struct siena_nic_data *nic_data = efx->nic_data;
	int rc;

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_PERM_ADDR)
	rc = efx_mcdi_get_board_cfg(efx,
				    efx->net_dev->perm_addr,
				    NULL, &nic_data->caps);
#else
	rc = efx_mcdi_get_board_cfg(efx, efx->perm_addr,
				    NULL, &nic_data->caps);
#endif

	efx->timer_quantum_ns = (maranello_enabled(efx->nic_data) ?
				 3072 : 6144); /* 768 cycles */
	efx->timer_max_ns = efx->type->timer_period_max * efx->timer_quantum_ns;

	return rc;
}

static int siena_dimension_resources(struct efx_nic *efx)
{
	/* Each port has a small block of internal SRAM dedicated to
	 * the buffer table and descriptor caches.  In theory we can
	 * map both blocks to one port, but we don't.
	 */
#ifdef CONFIG_SFC_SRIOV
	struct siena_nic_data *nic_data = efx->nic_data;
#endif
	unsigned int sram_lim_qw = FR_CZ_BUF_FULL_TBL_ROWS / 2;
	struct efx_dl_falcon_resources *res = &efx->farch_resources;
	struct efx_dl_device_info *end_res;
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_RESOURCE_LIMITS_OUT_LEN);
	size_t outlen;
	int rc;

	BUILD_BUG_ON(MC_CMD_GET_RESOURCE_LIMITS_IN_LEN != 0);

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_GET_RESOURCE_LIMITS, NULL, 0,
				outbuf, sizeof(outbuf), &outlen);
	if (rc == -ENOSYS) {
		res->buffer_table_lim = sram_lim_qw;
	} else if (rc) {
		efx_mcdi_display_error(efx, MC_CMD_GET_RESOURCE_LIMITS, 0,
				       outbuf, outlen, rc);
		return rc;
	} else {
		res->buffer_table_lim =
			MCDI_DWORD(outbuf, GET_RESOURCE_LIMITS_OUT_BUFTBL);
		res->rxq_lim = MCDI_DWORD(outbuf, GET_RESOURCE_LIMITS_OUT_RXQ);
		res->txq_lim = MCDI_DWORD(outbuf, GET_RESOURCE_LIMITS_OUT_TXQ);
		res->evq_timer_lim =
			MCDI_DWORD(outbuf, GET_RESOURCE_LIMITS_OUT_EVQ);
		if (res->buffer_table_lim < sram_lim_qw) {
			res->flags |= EFX_DL_FALCON_ONLOAD_UNSUPPORTED;
		}
	}

	res->flags |= EFX_DL_FALCON_HAVE_TIMER_QUANTUM_NS;
	res->timer_quantum_ns = efx->timer_quantum_ns; /* same as IRQ timers */

	rc = efx_farch_dimension_resources(efx, sram_lim_qw);
	if (rc)
		return rc;

	end_res = &efx->farch_resources.hdr;

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_AOE)
	/* If the board is AOE enabled */
	if (efx->nic_data && (aoe_enabled(efx->nic_data))) {
		/* Number of MACs is hardcoded for now */
		efx->aoe_resources.internal_macs = 2;
		efx->aoe_resources.external_macs = 2;
		efx->aoe_resources.hdr.type = EFX_DL_AOE_RESOURCES;
		efx->aoe_resources.hdr.next = end_res->next;
		end_res->next = &efx->aoe_resources.hdr;
		end_res = &efx->aoe_resources.hdr;
	}
#endif

#ifdef CONFIG_SFC_SRIOV
	if (efx_siena_sriov_wanted(efx)) {
		/* Advertise SR-IOV through driverlink */
		nic_data->sriov_resources.hdr.type = EFX_DL_SIENA_SRIOV;
		nic_data->sriov_resources.vi_base = EFX_VI_BASE;
		nic_data->sriov_resources.vi_scale = efx->vi_scale;
		nic_data->sriov_resources.vf_count = efx->vf_count;
		nic_data->sriov_resources.hdr.next = end_res->next;
		end_res->next = &nic_data->sriov_resources.hdr;
	}
#endif

	return 0;
}

static unsigned int siena_mem_map_size(struct efx_nic *efx)
{
	return FR_CZ_MC_TREG_SMEM +
		FR_CZ_MC_TREG_SMEM_STEP * FR_CZ_MC_TREG_SMEM_ROWS;
}

static int siena_probe_nic(struct efx_nic *efx)
{
	struct siena_nic_data *nic_data;
	efx_oword_t reg;
	int rc;

	/* Allocate storage for hardware specific data */
	nic_data = kzalloc(sizeof(struct siena_nic_data), GFP_KERNEL);
	if (!nic_data)
		return -ENOMEM;
	nic_data->efx = efx;
	efx->nic_data = nic_data;

	if (efx_farch_fpga_ver(efx) != 0) {
		netif_err(efx, probe, efx->net_dev,
			  "Siena FPGA not supported\n");
		rc = -ENODEV;
		goto fail1;
	}

	efx->max_channels = efx->max_tx_channels = EFX_MAX_CHANNELS;
	EFX_BUG_ON_PARANOID(EFX_TXQ_TYPE_CSUM_OFFLOAD >= 2);
	EFX_BUG_ON_PARANOID(EFX_TXQ_TYPE_NO_OFFLOAD >= 2);
	EFX_BUG_ON_PARANOID(EFX_TXQ_TYPE_CSUM_OFFLOAD == EFX_TXQ_TYPE_NO_OFFLOAD);
	efx->tx_queues_per_channel = 2;
	efx->select_tx_queue = efx_farch_select_tx_queue;

	efx_reado(efx, &reg, FR_AZ_CS_DEBUG);
	efx->port_num = EFX_OWORD_FIELD(reg, FRF_CZ_CS_PORT_NUM) - 1;

#ifdef EFX_NOT_UPSTREAM
	if (!rx_hash_insert) {
		efx->rx_prefix_size = 0;
		efx->net_dev->features &= ~NETIF_F_RXHASH;
#if defined(EFX_HAVE_NDO_SET_FEATURES)
		efx->net_dev->hw_features &= ~NETIF_F_RXHASH;
#elif defined(EFX_HAVE_EXT_NDO_SET_FEATURES)
		netdev_extended(efx->net_dev)->hw_features &= ~NETIF_F_RXHASH;
#endif

		/* Unlink Driverlink hash insertion information */
		efx->farch_resources.hdr.next = NULL;
	}
#endif

	rc = efx_mcdi_init(efx);
	if (rc)
		goto fail1;

	/* Now we can reset the NIC */
	rc = efx_mcdi_reset(efx, RESET_TYPE_ALL);
	if (rc) {
		netif_err(efx, probe, efx->net_dev, "failed to reset NIC\n");
		goto fail3;
	}

	siena_init_wol(efx);

	/* Allocate memory for INT_KER */
	rc = efx_nic_alloc_buffer(efx, &efx->irq_status, sizeof(efx_oword_t),
				  GFP_KERNEL);
	if (rc)
		goto fail4;
	BUG_ON(efx->irq_status.dma_addr & 0x0f);

	netif_dbg(efx, probe, efx->net_dev,
		  "INT_KER at %llx (virt %p phys %llx)\n",
		  (unsigned long long)efx->irq_status.dma_addr,
		  efx->irq_status.addr,
		  (unsigned long long)virt_to_phys(efx->irq_status.addr));

	/* Read in the non-volatile configuration */
	rc = siena_probe_nvconfig(efx);
	if (rc == -EINVAL) {
		netif_err(efx, probe, efx->net_dev,
			  "NVRAM is invalid therefore using defaults\n");
		efx->phy_type = PHY_TYPE_NONE;
		efx->mdio.prtad = MDIO_PRTAD_NONE;
	} else if (rc) {
		goto fail5;
	}

	rc = efx_mcdi_mon_probe(efx);
	if (rc)
		goto fail5;

	if (maranello_possible(efx->nic_data)) {
		rc = device_create_file(&efx->pci_dev->dev,
					&dev_attr_turbo_mode);
		if (rc)
			goto fail6;
	}

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_AOE)
	if (aoe_enabled(efx->nic_data)) {
		rc = efx_aoe_attach(efx);
		if (rc)
			goto fail7;
	}
#endif

#ifdef CONFIG_SFC_SRIOV
	efx_sriov_init_max_vfs(efx, efx->port_num);
#endif

	efx_siena_sriov_probe(efx);
	efx_ptp_defer_probe_with_channel(efx);

	return 0;

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_AOE)
fail7:
	if (maranello_possible(efx->nic_data))
		device_remove_file(&efx->pci_dev->dev,
				   &dev_attr_turbo_mode);
#endif
fail6:
	efx_mcdi_mon_remove(efx);
fail5:
	efx_nic_free_buffer(efx, &efx->irq_status);
fail4:
fail3:
	efx_mcdi_detach(efx);
	efx_mcdi_fini(efx);
fail1:
	kfree(efx->nic_data);
	efx->nic_data = NULL;
	return rc;
}

static int siena_rx_pull_rss_config(struct efx_nic *efx)
{
	efx_oword_t temp;

	/* Read from IPv6 RSS key as that's longer (the IPv4 key is just the
	 * first 128 bits of the same key, assuming it's been set by
	 * siena_rx_push_rss_config, below)
	 */
	efx_reado(efx, &temp, FR_CZ_RX_RSS_IPV6_REG1);
	memcpy(efx->rx_hash_key, &temp, sizeof(temp));
	efx_reado(efx, &temp, FR_CZ_RX_RSS_IPV6_REG2);
	memcpy(efx->rx_hash_key + sizeof(temp), &temp, sizeof(temp));
	efx_reado(efx, &temp, FR_CZ_RX_RSS_IPV6_REG3);
	memcpy(efx->rx_hash_key + 2 * sizeof(temp), &temp,
	       FRF_CZ_RX_RSS_IPV6_TKEY_HI_WIDTH / 8);
	efx_farch_rx_pull_indir_table(efx);
	return 0;
}

static int siena_rx_push_rss_config(struct efx_nic *efx, bool user,
				    const u32 *rx_indir_table, const u8 *key)
{
	efx_oword_t temp;

	/* Set hash key for IPv4 */
	if (key)
		memcpy(efx->rx_hash_key, key, sizeof(temp));
	memcpy(&temp, efx->rx_hash_key, sizeof(temp));
	efx_writeo(efx, &temp, FR_BZ_RX_RSS_TKEY);

	/* Enable IPv6 RSS */
	BUILD_BUG_ON(sizeof(efx->rx_hash_key) <
		     2 * sizeof(temp) + FRF_CZ_RX_RSS_IPV6_TKEY_HI_WIDTH / 8 ||
		     FRF_CZ_RX_RSS_IPV6_TKEY_HI_LBN != 0);
	memcpy(&temp, efx->rx_hash_key, sizeof(temp));
	efx_writeo(efx, &temp, FR_CZ_RX_RSS_IPV6_REG1);
	memcpy(&temp, efx->rx_hash_key + sizeof(temp), sizeof(temp));
	efx_writeo(efx, &temp, FR_CZ_RX_RSS_IPV6_REG2);
	EFX_POPULATE_OWORD_2(temp, FRF_CZ_RX_RSS_IPV6_THASH_ENABLE, 1,
			     FRF_CZ_RX_RSS_IPV6_IP_THASH_ENABLE, 1);
	memcpy(&temp, efx->rx_hash_key + 2 * sizeof(temp),
	       FRF_CZ_RX_RSS_IPV6_TKEY_HI_WIDTH / 8);
	efx_writeo(efx, &temp, FR_CZ_RX_RSS_IPV6_REG3);

	memcpy(efx->rx_indir_table, rx_indir_table,
		sizeof(efx->rx_indir_table));
	efx_farch_rx_push_indir_table(efx);
	return 0;
}

/* This call performs hardware-specific global initialisation, such as
 * defining the descriptor cache sizes and number of RSS channels.
 * It does not set up any buffers, descriptor rings or event queues.
 */
static int siena_init_nic(struct efx_nic *efx)
{
	efx_oword_t temp;
	int rc;

	/* Recover from a failed assertion post-reset */
	rc = efx_mcdi_handle_assertion(efx);
	if (rc)
		return rc;

#ifdef EFX_NOT_UPSTREAM
	efx_nic_check_pcie_link(efx, EFX_BW_PCIE_GEN2_X8, NULL, NULL);
#endif

	/* Do not enable TX_NO_EOP_DISC_EN, since it limits packets to 16
	 * descriptors (which is bad).
	 */
	efx_reado(efx, &temp, FR_AZ_TX_CFG);
	EFX_SET_OWORD_FIELD(temp, FRF_AZ_TX_NO_EOP_DISC_EN, 0);
	EFX_SET_OWORD_FIELD(temp, FRF_CZ_TX_FILTER_EN_BIT, 1);
	efx_writeo(efx, &temp, FR_AZ_TX_CFG);

	efx_reado(efx, &temp, FR_AZ_RX_CFG);
	EFX_SET_OWORD_FIELD(temp, FRF_BZ_RX_DESC_PUSH_EN, 0);
	EFX_SET_OWORD_FIELD(temp, FRF_BZ_RX_INGR_EN, 1);
	/* Enable hash insertion. This is broken for the 'Falcon' hash
	 * if IPv6 hashing is also enabled, so also select Toeplitz
	 * TCP/IPv4 and IPv4 hashes. */
#ifdef EFX_NOT_UPSTREAM
	EFX_SET_OWORD_FIELD(temp, FRF_BZ_RX_HASH_INSRT_HDR, rx_hash_insert);
#else
	EFX_SET_OWORD_FIELD(temp, FRF_BZ_RX_HASH_INSRT_HDR, 1);
#endif
	EFX_SET_OWORD_FIELD(temp, FRF_BZ_RX_HASH_ALG, 1);
	EFX_SET_OWORD_FIELD(temp, FRF_BZ_RX_IP_HASH, 1);
	EFX_SET_OWORD_FIELD(temp, FRF_BZ_RX_USR_BUF_SIZE,
			    EFX_RX_USR_BUF_SIZE >> 5);
	efx_writeo(efx, &temp, FR_AZ_RX_CFG);

	siena_rx_push_rss_config(efx, false, efx->rx_indir_table, NULL);

	/* Enable event logging */
	rc = efx_mcdi_log_ctrl(efx, true, false, 0);
	if (rc)
		return rc;

	/* Set destination of both TX and RX Flush events */
	EFX_POPULATE_OWORD_1(temp, FRF_BZ_FLS_EVQ_ID, 0);
	efx_writeo(efx, &temp, FR_BZ_DP_CTRL);

	EFX_POPULATE_OWORD_1(temp, FRF_CZ_USREV_DIS, 1);
	efx_writeo(efx, &temp, FR_CZ_USR_EV_CFG);

	efx_farch_init_common(efx);
	return 0;
}

static void siena_remove_nic(struct efx_nic *efx)
{
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_AOE)
	efx_aoe_detach(efx);
#endif
	efx_mcdi_mon_remove(efx);

	efx_nic_free_buffer(efx, &efx->irq_status);

	efx_mcdi_reset(efx, RESET_TYPE_ALL);

	if (maranello_possible(efx->nic_data))
		device_remove_file(&efx->pci_dev->dev,
				   &dev_attr_turbo_mode);

	efx_mcdi_detach(efx);
	efx_mcdi_fini(efx);

	/* Tear down the private nic state, and the driverlink nic params */
	kfree(efx->nic_data);
	efx->nic_data = NULL;
}

#define SIENA_DMA_STAT(ext_name, mcdi_name)			\
	[SIENA_STAT_ ## ext_name] =				\
	{ #ext_name, 64, 8 * MC_CMD_MAC_ ## mcdi_name }
#define SIENA_DMA_PACKED_STAT(ext_name1, ext_name2, mcdi_name)	\
	[SIENA_STAT_ ## ext_name1] =				\
	{ #ext_name1, 32, 8 * MC_CMD_MAC_ ## mcdi_name },	\
	[SIENA_STAT_ ## ext_name2] =				\
	{ #ext_name2, 32, 8 * MC_CMD_MAC_ ## mcdi_name + 4 }
#define SIENA_OTHER_STAT(ext_name)				\
	[SIENA_STAT_ ## ext_name] = { #ext_name, 0, 0 }
#define GENERIC_SW_STAT(ext_name)				\
	[GENERIC_STAT_ ## ext_name] = { #ext_name, 0, 0 }

static const struct efx_hw_stat_desc siena_stat_desc[SIENA_STAT_COUNT] = {
	SIENA_DMA_STAT(tx_bytes, TX_BYTES),
	SIENA_OTHER_STAT(tx_good_bytes),
	SIENA_DMA_STAT(tx_bad_bytes, TX_BAD_BYTES),
	SIENA_DMA_STAT(tx_packets, TX_PKTS),
	SIENA_DMA_STAT(tx_bad, TX_BAD_FCS_PKTS),
	SIENA_DMA_STAT(tx_pause, TX_PAUSE_PKTS),
	SIENA_DMA_STAT(tx_control, TX_CONTROL_PKTS),
	SIENA_DMA_STAT(tx_unicast, TX_UNICAST_PKTS),
	SIENA_DMA_STAT(tx_multicast, TX_MULTICAST_PKTS),
	SIENA_DMA_STAT(tx_broadcast, TX_BROADCAST_PKTS),
	SIENA_DMA_STAT(tx_lt64, TX_LT64_PKTS),
	SIENA_DMA_STAT(tx_64, TX_64_PKTS),
	SIENA_DMA_STAT(tx_65_to_127, TX_65_TO_127_PKTS),
	SIENA_DMA_STAT(tx_128_to_255, TX_128_TO_255_PKTS),
	SIENA_DMA_STAT(tx_256_to_511, TX_256_TO_511_PKTS),
	SIENA_DMA_STAT(tx_512_to_1023, TX_512_TO_1023_PKTS),
	SIENA_DMA_STAT(tx_1024_to_15xx, TX_1024_TO_15XX_PKTS),
	SIENA_DMA_STAT(tx_15xx_to_jumbo, TX_15XX_TO_JUMBO_PKTS),
	SIENA_DMA_STAT(tx_gtjumbo, TX_GTJUMBO_PKTS),
	SIENA_OTHER_STAT(tx_collision),
	SIENA_DMA_STAT(tx_single_collision, TX_SINGLE_COLLISION_PKTS),
	SIENA_DMA_STAT(tx_multiple_collision, TX_MULTIPLE_COLLISION_PKTS),
	SIENA_DMA_STAT(tx_excessive_collision, TX_EXCESSIVE_COLLISION_PKTS),
	SIENA_DMA_STAT(tx_deferred, TX_DEFERRED_PKTS),
	SIENA_DMA_STAT(tx_late_collision, TX_LATE_COLLISION_PKTS),
	SIENA_DMA_STAT(tx_excessive_deferred, TX_EXCESSIVE_DEFERRED_PKTS),
	SIENA_DMA_STAT(tx_non_tcpudp, TX_NON_TCPUDP_PKTS),
	SIENA_DMA_STAT(tx_mac_src_error, TX_MAC_SRC_ERR_PKTS),
	SIENA_DMA_STAT(tx_ip_src_error, TX_IP_SRC_ERR_PKTS),
	SIENA_DMA_STAT(rx_bytes, RX_BYTES),
	SIENA_OTHER_STAT(rx_good_bytes),
	SIENA_DMA_STAT(rx_bad_bytes, RX_BAD_BYTES),
	SIENA_DMA_STAT(rx_packets, RX_PKTS),
	SIENA_DMA_STAT(rx_good, RX_GOOD_PKTS),
	SIENA_DMA_STAT(rx_bad, RX_BAD_FCS_PKTS),
	SIENA_DMA_STAT(rx_pause, RX_PAUSE_PKTS),
	SIENA_DMA_STAT(rx_control, RX_CONTROL_PKTS),
	SIENA_DMA_STAT(rx_unicast, RX_UNICAST_PKTS),
	SIENA_DMA_STAT(rx_multicast, RX_MULTICAST_PKTS),
	SIENA_DMA_STAT(rx_broadcast, RX_BROADCAST_PKTS),
	SIENA_DMA_STAT(rx_lt64, RX_UNDERSIZE_PKTS),
	SIENA_DMA_STAT(rx_64, RX_64_PKTS),
	SIENA_DMA_STAT(rx_65_to_127, RX_65_TO_127_PKTS),
	SIENA_DMA_STAT(rx_128_to_255, RX_128_TO_255_PKTS),
	SIENA_DMA_STAT(rx_256_to_511, RX_256_TO_511_PKTS),
	SIENA_DMA_STAT(rx_512_to_1023, RX_512_TO_1023_PKTS),
	SIENA_DMA_STAT(rx_1024_to_15xx, RX_1024_TO_15XX_PKTS),
	SIENA_DMA_STAT(rx_15xx_to_jumbo, RX_15XX_TO_JUMBO_PKTS),
	SIENA_DMA_STAT(rx_gtjumbo, RX_GTJUMBO_PKTS),
	SIENA_DMA_STAT(rx_bad_gtjumbo, RX_JABBER_PKTS),
	SIENA_DMA_STAT(rx_overflow, RX_OVERFLOW_PKTS),
	SIENA_DMA_STAT(rx_false_carrier, RX_FALSE_CARRIER_PKTS),
	SIENA_DMA_STAT(rx_symbol_error, RX_SYMBOL_ERROR_PKTS),
	SIENA_DMA_STAT(rx_align_error, RX_ALIGN_ERROR_PKTS),
	SIENA_DMA_STAT(rx_length_error, RX_LENGTH_ERROR_PKTS),
	SIENA_DMA_STAT(rx_internal_error, RX_INTERNAL_ERROR_PKTS),
	SIENA_DMA_STAT(rx_nodesc_drop_cnt, RX_NODESC_DROPS),
	GENERIC_SW_STAT(rx_nodesc_trunc),
	GENERIC_SW_STAT(rx_noskb_drops),
	SIENA_DMA_PACKED_STAT(rx_char_error_lane0, rx_char_error_lane1,
			      RX_LANES01_CHAR_ERR),
	SIENA_DMA_PACKED_STAT(rx_char_error_lane2, rx_char_error_lane3,
			      RX_LANES23_CHAR_ERR),
	SIENA_DMA_PACKED_STAT(rx_disp_error_lane0, rx_disp_error_lane1,
			      RX_LANES01_DISP_ERR),
	SIENA_DMA_PACKED_STAT(rx_disp_error_lane2, rx_disp_error_lane3,
			      RX_LANES23_DISP_ERR),
	SIENA_DMA_STAT(rx_match_fault, RX_MATCH_FAULT),
};
static const unsigned long siena_stat_mask[] = {
	[0 ... BITS_TO_LONGS(SIENA_STAT_COUNT) - 1] = ~0UL,
};

static size_t siena_describe_nic_stats(struct efx_nic *efx, u8 *names)
{
	return efx_nic_describe_stats(siena_stat_desc, SIENA_STAT_COUNT,
				      siena_stat_mask, names);
}

static int siena_try_update_nic_stats(struct efx_nic *efx)
{
	struct siena_nic_data *nic_data = efx->nic_data;
	u64 *stats = nic_data->stats;
	__le64 *dma_stats;
	__le64 generation_start, generation_end;

	dma_stats = efx->stats_buffer.addr;

	generation_end = dma_stats[MC_CMD_MAC_GENERATION_END];
	if (generation_end == EFX_MC_STATS_GENERATION_INVALID)
		return 0;
	rmb();
	efx_nic_update_stats(siena_stat_desc, SIENA_STAT_COUNT, siena_stat_mask,
			     stats, efx->stats_buffer.addr, false);
	rmb();
	generation_start = dma_stats[MC_CMD_MAC_GENERATION_START];
	if (generation_end != generation_start)
		return -EAGAIN;

	/* Update derived statistics */
	efx_nic_fix_nodesc_drop_stat(efx,
				     &stats[SIENA_STAT_rx_nodesc_drop_cnt]);
	efx_update_diff_stat(&stats[SIENA_STAT_tx_good_bytes],
			     stats[SIENA_STAT_tx_bytes] -
			     stats[SIENA_STAT_tx_bad_bytes]);
	stats[SIENA_STAT_tx_collision] =
		stats[SIENA_STAT_tx_single_collision] +
		stats[SIENA_STAT_tx_multiple_collision] +
		stats[SIENA_STAT_tx_excessive_collision] +
		stats[SIENA_STAT_tx_late_collision];
	efx_update_diff_stat(&stats[SIENA_STAT_rx_good_bytes],
			     stats[SIENA_STAT_rx_bytes] -
			     stats[SIENA_STAT_rx_bad_bytes]);
	efx_update_sw_stats(efx, stats);
	return 0;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_NETDEV_STATS64)
static size_t siena_update_nic_stats(struct efx_nic *efx, u64 *full_stats,
				     struct rtnl_link_stats64 *core_stats)
#else
static size_t siena_update_nic_stats(struct efx_nic *efx, u64 *full_stats,
				     struct net_device_stats *core_stats)
#endif
{
	struct siena_nic_data *nic_data = efx->nic_data;
	u64 *stats = nic_data->stats;
	int retry;

	spin_lock_bh(&efx->stats_lock);

	/* If we're unlucky enough to read statistics wduring the DMA, wait
	 * up to 10ms for it to finish (typically takes <500us) */
	for (retry = 0; retry < 100; ++retry) {
		if (siena_try_update_nic_stats(efx) == 0)
			break;
		udelay(100);
	}

	if (full_stats)
		memcpy(full_stats, stats, sizeof(u64) * SIENA_STAT_COUNT);

	if (core_stats) {
		core_stats->rx_packets = stats[SIENA_STAT_rx_packets];
		core_stats->tx_packets = stats[SIENA_STAT_tx_packets];
		core_stats->rx_bytes = stats[SIENA_STAT_rx_bytes];
		core_stats->tx_bytes = stats[SIENA_STAT_tx_bytes];
		core_stats->rx_dropped = stats[SIENA_STAT_rx_nodesc_drop_cnt] +
					 stats[GENERIC_STAT_rx_nodesc_trunc] +
					 stats[GENERIC_STAT_rx_noskb_drops];
		core_stats->multicast = stats[SIENA_STAT_rx_multicast];
		core_stats->collisions = stats[SIENA_STAT_tx_collision];
		core_stats->rx_length_errors =
			stats[SIENA_STAT_rx_gtjumbo] +
			stats[SIENA_STAT_rx_length_error];
		core_stats->rx_crc_errors = stats[SIENA_STAT_rx_bad];
		core_stats->rx_frame_errors = stats[SIENA_STAT_rx_align_error];
		core_stats->rx_fifo_errors = stats[SIENA_STAT_rx_overflow];
		core_stats->tx_window_errors =
			stats[SIENA_STAT_tx_late_collision];

		core_stats->rx_errors = (core_stats->rx_length_errors +
					 core_stats->rx_crc_errors +
					 core_stats->rx_frame_errors +
					 stats[SIENA_STAT_rx_symbol_error]);
		core_stats->tx_errors = (core_stats->tx_window_errors +
					 stats[SIENA_STAT_tx_bad]);
	}

	return SIENA_STAT_COUNT;
}

static int siena_mac_reconfigure(struct efx_nic *efx,
		bool mtu_only __always_unused)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_SET_MCAST_HASH_IN_LEN);
	int rc;

	BUILD_BUG_ON(MC_CMD_SET_MCAST_HASH_IN_LEN !=
		     MC_CMD_SET_MCAST_HASH_IN_HASH0_OFST +
		     sizeof(efx->multicast_hash));

	efx_farch_filter_sync_rx_mode(efx);

	WARN_ON(!mutex_is_locked(&efx->mac_lock));

	rc = efx_mcdi_set_mac(efx);
	if (rc != 0)
		return rc;

	memcpy(MCDI_PTR(inbuf, SET_MCAST_HASH_IN_HASH0),
	       efx->multicast_hash.byte, sizeof(efx->multicast_hash));
	return efx_mcdi_rpc(efx, MC_CMD_SET_MCAST_HASH,
			    inbuf, sizeof(inbuf), NULL, 0, NULL);
}

/**************************************************************************
 *
 * Wake on LAN
 *
 **************************************************************************
 */

static void siena_get_wol(struct efx_nic *efx, struct ethtool_wolinfo *wol)
{
	struct siena_nic_data *nic_data = efx->nic_data;

	wol->supported = WAKE_MAGIC;
	if (nic_data->wol_filter_id != -1)
		wol->wolopts = WAKE_MAGIC;
	else
		wol->wolopts = 0;
	memset(&wol->sopass, 0, sizeof(wol->sopass));
}


static int siena_set_wol(struct efx_nic *efx, u32 type)
{
	struct siena_nic_data *nic_data = efx->nic_data;
	int rc;

	if (type & ~WAKE_MAGIC)
		return -EINVAL;

	if (type & WAKE_MAGIC) {
		if (nic_data->wol_filter_id != -1)
			efx_mcdi_wol_filter_remove(efx,
						   nic_data->wol_filter_id);
		rc = efx_mcdi_wol_filter_set_magic(efx, efx->net_dev->dev_addr,
						   &nic_data->wol_filter_id);
		if (rc)
			goto fail;

		pci_wake_from_d3(efx->pci_dev, true);
	} else {
		rc = efx_mcdi_wol_filter_reset(efx);
		nic_data->wol_filter_id = -1;
		pci_wake_from_d3(efx->pci_dev, false);
		if (rc)
			goto fail;
	}

	return 0;
 fail:
	netif_err(efx, hw, efx->net_dev, "%s failed: type=%d rc=%d\n",
		  __func__, type, rc);
	return rc;
}


static void siena_init_wol(struct efx_nic *efx)
{
	struct siena_nic_data *nic_data = efx->nic_data;
	int rc;

	rc = efx_mcdi_wol_filter_get_magic(efx, &nic_data->wol_filter_id);

	if (rc != 0) {
		/* If it failed, attempt to get into a synchronised
		 * state with MC by resetting any set WoL filters */
		efx_mcdi_wol_filter_reset(efx);
		nic_data->wol_filter_id = -1;
	} else if (nic_data->wol_filter_id != -1) {
		pci_wake_from_d3(efx->pci_dev, true);
	}
}

/**************************************************************************
 *
 * MCDI
 *
 **************************************************************************
 */

#define MCDI_PDU(efx)							\
	(efx_port_num(efx) ? MC_SMEM_P1_PDU_OFST : MC_SMEM_P0_PDU_OFST)
#define MCDI_DOORBELL(efx)						\
	(efx_port_num(efx) ? MC_SMEM_P1_DOORBELL_OFST : MC_SMEM_P0_DOORBELL_OFST)
#define MCDI_STATUS(efx)						\
	(efx_port_num(efx) ? MC_SMEM_P1_STATUS_OFST : MC_SMEM_P0_STATUS_OFST)

static void siena_mcdi_request(struct efx_nic *efx,
			       const efx_dword_t *hdr, size_t hdr_len,
			       const efx_dword_t *sdu, size_t sdu_len)
{
	unsigned int pdu = FR_CZ_MC_TREG_SMEM + MCDI_PDU(efx);
	unsigned int doorbell = FR_CZ_MC_TREG_SMEM + MCDI_DOORBELL(efx);
	unsigned int i;
	unsigned int inlen_dw = DIV_ROUND_UP(sdu_len, 4);

	EFX_BUG_ON_PARANOID(hdr_len != 4);

	efx_writed(efx, hdr, pdu);

	for (i = 0; i < inlen_dw; i++)
		efx_writed(efx, &sdu[i], pdu + hdr_len + 4 * i);

	/* Ensure the request is written out before the doorbell */
	wmb();

	/* ring the doorbell with a distinctive value */
	_efx_writed(efx, (__force __le32) 0x45789abc, doorbell);
}

static bool siena_mcdi_poll_response(struct efx_nic *efx)
{
	unsigned int pdu = FR_CZ_MC_TREG_SMEM + MCDI_PDU(efx);
	efx_dword_t hdr;

	efx_readd(efx, &hdr, pdu);

	/* All 1's indicates that shared memory is in reset (and is
	 * not a valid hdr). Wait for it to come out reset before
	 * completing the command
	 */
	return EFX_DWORD_FIELD(hdr, EFX_DWORD_0) != 0xffffffff &&
		EFX_DWORD_FIELD(hdr, MCDI_HEADER_RESPONSE);
}

static void siena_mcdi_read_response(struct efx_nic *efx, efx_dword_t *outbuf,
				     size_t offset, size_t outlen)
{
	unsigned int pdu = FR_CZ_MC_TREG_SMEM + MCDI_PDU(efx);
	unsigned int outlen_dw = DIV_ROUND_UP(outlen, 4);
	int i;

	for (i = 0; i < outlen_dw; i++)
		efx_readd(efx, &outbuf[i], pdu + offset + 4 * i);
}

static int siena_mcdi_poll_reboot(struct efx_nic *efx)
{
	struct siena_nic_data *nic_data = efx->nic_data;
	unsigned int addr = FR_CZ_MC_TREG_SMEM + MCDI_STATUS(efx);
	efx_dword_t reg;
	u32 value;

	efx_readd(efx, &reg, addr);
	value = EFX_DWORD_FIELD(reg, EFX_DWORD_0);

	if (value == 0)
		return 0;

	EFX_ZERO_DWORD(reg);
	efx_writed(efx, &reg, addr);

	/* MAC statistics have been cleared on the NIC; clear the local
	 * copies that we update with efx_update_diff_stat().
	 */
	nic_data->stats[SIENA_STAT_tx_good_bytes] = 0;
	nic_data->stats[SIENA_STAT_rx_good_bytes] = 0;

	if (value == MC_STATUS_DWORD_ASSERT)
		return -EINTR;
	else
		return -EIO;
}

/**************************************************************************
 *
 * MTD
 *
 **************************************************************************
 */

#ifdef CONFIG_SFC_MTD

struct siena_nvram_type_info {
	int port;
	const char *name;
};

static const struct siena_nvram_type_info siena_nvram_types[] = {
	[MC_CMD_NVRAM_TYPE_DISABLED_CALLISTO]	= { 0, "sfc_dummy_phy" },
	[MC_CMD_NVRAM_TYPE_MC_FW]		= { 0, "sfc_mcfw" },
	[MC_CMD_NVRAM_TYPE_MC_FW_BACKUP]	= { 0, "sfc_mcfw_backup" },
	[MC_CMD_NVRAM_TYPE_STATIC_CFG_PORT0]	= { 0, "sfc_static_cfg" },
	[MC_CMD_NVRAM_TYPE_STATIC_CFG_PORT1]	= { 1, "sfc_static_cfg" },
	[MC_CMD_NVRAM_TYPE_DYNAMIC_CFG_PORT0]	= { 0, "sfc_dynamic_cfg" },
	[MC_CMD_NVRAM_TYPE_DYNAMIC_CFG_PORT1]	= { 1, "sfc_dynamic_cfg" },
	[MC_CMD_NVRAM_TYPE_EXP_ROM]		= { 0, "sfc_exp_rom" },
	[MC_CMD_NVRAM_TYPE_EXP_ROM_CFG_PORT0]	= { 0, "sfc_exp_rom_cfg" },
	[MC_CMD_NVRAM_TYPE_EXP_ROM_CFG_PORT1]	= { 1, "sfc_exp_rom_cfg" },
	[MC_CMD_NVRAM_TYPE_PHY_PORT0]		= { 0, "sfc_phy_fw" },
	[MC_CMD_NVRAM_TYPE_PHY_PORT1]		= { 1, "sfc_phy_fw" },
	[MC_CMD_NVRAM_TYPE_FPGA]		= { 0, "sfc_fpga" },
	[MC_CMD_NVRAM_TYPE_FPGA_BACKUP]		= { 0, "sfc_fpgadiag" },
	[MC_CMD_NVRAM_TYPE_FC_FW]		= { 0, "sfc_fcfw" },
	[MC_CMD_NVRAM_TYPE_CPLD]		= { 0, "sfc_cpld" },
	[MC_CMD_NVRAM_TYPE_LICENSE]		= { 0, "sfc_license" },
};

static int siena_mtd_probe_partition(struct efx_nic *efx,
				     struct efx_mcdi_mtd_partition *part,
				     unsigned int type)
{
	const struct siena_nvram_type_info *info;
	size_t size, erase_size, write_size;
	bool protected;
	int rc;

	if (type >= ARRAY_SIZE(siena_nvram_types) ||
	    siena_nvram_types[type].name == NULL)
		return -ENODEV;

	info = &siena_nvram_types[type];

	if (info->port != efx_port_num(efx))
		return -ENODEV;

	rc = efx_mcdi_nvram_info(efx, type, &size, &erase_size, &write_size,
				 &protected);
	if (rc)
		return rc;
	if (protected && !efx_allow_nvconfig_writes)
		return -ENODEV; /* hide it */

	part->nvram_type = type;
	part->common.dev_type_name = "Siena NVRAM manager";
	part->common.type_name = info->name;

	part->common.mtd.type = MTD_NORFLASH;
	part->common.mtd.flags = MTD_CAP_NORFLASH;
	part->common.mtd.size = size;
	part->common.mtd.erasesize = erase_size;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_MTD_WRITESIZE)
	part->common.mtd.writesize = write_size;
#else
	part->common.writesize = write_size;
#endif

	return 0;
}

static int siena_mtd_get_fw_subtypes(struct efx_nic *efx,
				     struct efx_mcdi_mtd_partition *parts,
				     size_t n_parts)
{
	uint16_t fw_subtype_list[
		MC_CMD_GET_BOARD_CFG_OUT_FW_SUBTYPE_LIST_MAXNUM];
	size_t i;
	int rc;

	rc = efx_mcdi_get_board_cfg(efx, NULL, fw_subtype_list, NULL);
	if (rc)
		return rc;

	for (i = 0; i < n_parts; i++)
		parts[i].fw_subtype = fw_subtype_list[parts[i].nvram_type];

	return 0;
}

static int siena_mtd_probe(struct efx_nic *efx)
{
	struct efx_mcdi_mtd_partition *parts;
	u32 nvram_types;
	unsigned int type;
	size_t n_parts;
	int rc;

	ASSERT_RTNL();

	rc = efx_mcdi_nvram_types(efx, &nvram_types);
	if (rc)
		return rc;

	parts = kcalloc(hweight32(nvram_types), sizeof(*parts), GFP_KERNEL);
	if (!parts)
		return -ENOMEM;

	type = 0;
	n_parts = 0;

	while (nvram_types != 0) {
		if (nvram_types & 1) {
			rc = siena_mtd_probe_partition(efx, &parts[n_parts],
						       type);
			if (rc == 0)
				n_parts++;
			else if (rc != -ENODEV)
				goto fail;
		}
		type++;
		nvram_types >>= 1;
	}

	rc = siena_mtd_get_fw_subtypes(efx, parts, n_parts);
	if (rc)
		goto fail;

	rc = efx_mtd_add(efx, &parts[0].common, n_parts, sizeof(*parts));
fail:
	if (rc)
		kfree(parts);
	return rc;
}

#endif /* CONFIG_SFC_MTD */

/**************************************************************************
 *
 * Revision-dependent attributes used by efx.c and nic.c
 *
 **************************************************************************
 */

const struct efx_nic_type siena_a0_nic_type = {
	.is_vf = false,
	.mem_bar = EFX_MEM_BAR,
	.mem_map_size = siena_mem_map_size,
	.probe = siena_probe_nic,
	.dimension_resources = siena_dimension_resources,
	.remove = siena_remove_nic,
	.init = siena_init_nic,
	.fini = efx_port_dummy_op_void,
#ifdef CONFIG_EEH
	.monitor = siena_monitor,
#else
	.monitor = NULL,
#endif
	.map_reset_reason = siena_map_reset_reason,
	.map_reset_flags = siena_map_reset_flags,
	.reset = efx_mcdi_reset,
	.probe_port = efx_mcdi_port_probe,
	.remove_port = efx_mcdi_port_remove,
	.fini_dmaq = efx_farch_fini_dmaq,
	.prepare_flush = siena_prepare_flush,
	.finish_flush = siena_finish_flush,
	.prepare_flr = efx_port_dummy_op_void,
	.finish_flr = efx_farch_finish_flr,
	.describe_stats = siena_describe_nic_stats,
	.update_stats = siena_update_nic_stats,
	.start_stats = efx_mcdi_mac_start_stats,
	.pull_stats = efx_mcdi_mac_pull_stats,
	.stop_stats = efx_mcdi_mac_stop_stats,
	.update_stats_period = efx_mcdi_mac_update_stats_period,
	.set_id_led = efx_mcdi_set_id_led,
	.push_irq_moderation = siena_push_irq_moderation,
	.calc_mac_mtu = efx_nic_calc_mac_mtu,
	.reconfigure_mac = siena_mac_reconfigure,
	.check_mac_fault = efx_mcdi_mac_check_fault,
	.reconfigure_port = efx_mcdi_port_reconfigure,
	.get_wol = siena_get_wol,
	.set_wol = siena_set_wol,
	.resume_wol = siena_init_wol,
	.test_chip = siena_test_chip,
	.test_memory = siena_test_tables,
	.test_nvram = efx_mcdi_nvram_test_all,
	.mcdi_request = siena_mcdi_request,
	.mcdi_poll_response = siena_mcdi_poll_response,
	.mcdi_read_response = siena_mcdi_read_response,
	.mcdi_poll_reboot = siena_mcdi_poll_reboot,
	.irq_enable_master = efx_farch_irq_enable_master,
	.irq_test_generate = efx_farch_irq_test_generate,
	.irq_disable_non_ev = efx_farch_irq_disable_master,
	.irq_handle_msi = efx_farch_msi_interrupt,
	.irq_handle_legacy = efx_farch_legacy_interrupt,
	.tx_probe = efx_farch_tx_probe,
	.tx_init = efx_farch_tx_init,
	.tx_remove = efx_farch_tx_remove,
	.tx_write = efx_farch_tx_write,
	.tx_notify = efx_farch_notify_tx_desc,
	.tx_limit_len = efx_farch_tx_limit_len,
	.rx_push_rss_config = siena_rx_push_rss_config,
	.rx_pull_rss_config = siena_rx_pull_rss_config,
	.rx_probe = efx_farch_rx_probe,
	.rx_init = efx_farch_rx_init,
	.rx_remove = efx_farch_rx_remove,
	.rx_write = efx_farch_rx_write,
	.rx_defer_refill = efx_farch_rx_defer_refill,
	.ev_probe = efx_farch_ev_probe,
	.ev_init = efx_farch_ev_init,
	.ev_fini = efx_farch_ev_fini,
	.ev_remove = efx_farch_ev_remove,
	.ev_process = efx_farch_ev_process,
	.ev_read_ack = efx_farch_ev_read_ack,
	.ev_test_generate = efx_farch_ev_test_generate,
	.filter_table_probe = efx_farch_filter_table_probe,
	.filter_table_restore = efx_farch_filter_table_restore,
	.filter_table_remove = efx_farch_filter_table_remove,
	.filter_match_supported = efx_farch_filter_match_supported,
	.filter_update_rx_scatter = efx_farch_filter_update_rx_scatter,
	.filter_insert = efx_farch_filter_insert,
	.filter_remove_safe = efx_farch_filter_remove_safe,
	.filter_get_safe = efx_farch_filter_get_safe,
	.filter_clear_rx = efx_farch_filter_clear_rx,
	.filter_redirect = efx_farch_filter_redirect,
	.filter_count_rx_used = efx_farch_filter_count_rx_used,
	.filter_get_rx_id_limit = efx_farch_filter_get_rx_id_limit,
	.filter_get_rx_ids = efx_farch_filter_get_rx_ids,
#if (defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SARFS)) || defined(CONFIG_RFS_ACCEL)
	.filter_async_insert = efx_farch_filter_async_insert,
#endif
#ifdef CONFIG_RFS_ACCEL
	.filter_rfs_expire_one = efx_farch_filter_rfs_expire_one,
#endif
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_SARFS)
	.filter_async_remove = efx_farch_filter_async_remove,
#endif
#ifdef EFX_NOT_UPSTREAM
	.filter_block_kernel = efx_farch_filter_block_kernel,
	.filter_unblock_kernel = efx_farch_filter_unblock_kernel,
	.vport_filter_insert = efx_farch_vport_filter_insert,
	.vport_filter_remove = efx_farch_vport_filter_remove,
#endif
#ifdef CONFIG_SFC_MTD
	.mtd_probe = siena_mtd_probe,
	.mtd_rename = efx_mcdi_mtd_rename,
	.mtd_read = efx_mcdi_mtd_read,
	.mtd_erase = efx_mcdi_mtd_erase,
	.mtd_write = efx_mcdi_mtd_write,
	.mtd_sync = efx_mcdi_mtd_sync,
#endif
#ifdef CONFIG_SFC_PTP
	.ptp_write_host_time = siena_ptp_write_host_time,
	.ptp_set_ts_config = siena_ptp_set_ts_config,
#endif
	.sriov_init = efx_siena_sriov_init,
	.sriov_fini = efx_siena_sriov_fini,
	.sriov_wanted = efx_siena_sriov_wanted,
	.sriov_reset = efx_siena_sriov_reset,
	.sriov_configure = efx_siena_sriov_configure,
	.sriov_flr = efx_siena_sriov_flr,
	.sriov_set_vf_mac = efx_siena_sriov_set_vf_mac,
	.sriov_set_vf_vlan = efx_siena_sriov_set_vf_vlan,
	.sriov_set_vf_spoofchk = efx_siena_sriov_set_vf_spoofchk,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_SET_VF_MAC)
	.sriov_get_vf_config = efx_siena_sriov_get_vf_config,
#endif
	.vswitching_probe = efx_port_dummy_op_int,
	.vswitching_restore = efx_port_dummy_op_int,
	.vswitching_remove = efx_port_dummy_op_void,
	.set_mac_address = efx_siena_sriov_mac_address_changed,

	.revision = EFX_REV_SIENA_A0,
	.txd_ptr_tbl_base = FR_BZ_TX_DESC_PTR_TBL,
	.rxd_ptr_tbl_base = FR_BZ_RX_DESC_PTR_TBL,
	.buf_tbl_base = FR_BZ_BUF_FULL_TBL,
	.evq_ptr_tbl_base = FR_BZ_EVQ_PTR_TBL,
	.evq_rptr_tbl_base = FR_BZ_EVQ_RPTR,
	.max_dma_mask = DMA_BIT_MASK(FSF_AZ_TX_KER_BUF_ADDR_WIDTH),
	.rx_prefix_size = FS_BZ_RX_PREFIX_SIZE,
	.rx_hash_offset = FS_BZ_RX_PREFIX_HASH_OFST,
	.rx_buffer_padding = 0,
	.can_rx_scatter = true,
	.option_descriptors = false,
	.min_interrupt_mode = EFX_INT_MODE_LEGACY,
	.max_interrupt_mode = EFX_INT_MODE_MSIX,
	.timer_period_max = 1 << FRF_CZ_TC_TIMER_VAL_WIDTH,
	.farch_resources = {
		.hdr.next = ((struct efx_dl_device_info *)
			     &siena_a0_nic_type.dl_hash_insertion.hdr),
		.hdr.type = EFX_DL_FALCON_RESOURCES,
		.rxq_min = 0, .rxq_lim = 1024,
		.txq_min = 0, .txq_lim = 1024,
		.evq_int_min = 0, .evq_int_lim = 64,
		.evq_timer_min = 64, .evq_timer_lim = 1024,
	},
	.dl_hash_insertion = {
		.hdr.type = EFX_DL_HASH_INSERTION,
		.data_offset = FS_BZ_RX_PREFIX_SIZE,
		.hash_offset = FS_BZ_RX_PREFIX_HASH_OFST,
		.flags = (EFX_DL_HASH_TOEP_TCPIP4 | EFX_DL_HASH_TOEP_IP4 |
			  EFX_DL_HASH_TOEP_TCPIP6 | EFX_DL_HASH_TOEP_IP6),
	},
#if !defined(EFX_USE_KCOMPAT) || defined(NETIF_F_IPV6_CSUM)
	.offload_features = (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
			     NETIF_F_RXHASH | NETIF_F_NTUPLE),
#else
	.offload_features = NETIF_F_HW_CSUM | NETIF_F_RXHASH | NETIF_F_NTUPLE,
#endif
	.mcdi_max_ver = 1,
	.max_rx_ip_filters = FR_BZ_RX_FILTER_TBL0_ROWS,
	.hwtstamp_filters = (1 << HWTSTAMP_FILTER_NONE |
			     1 << HWTSTAMP_FILTER_PTP_V1_L4_EVENT |
			     1 << HWTSTAMP_FILTER_PTP_V2_L4_EVENT),
	.rx_hash_key_size = 16,
};
