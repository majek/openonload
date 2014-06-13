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

#include <ci/efrm/nic_table.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efrm/private.h>
#include <ci/efrm/vi_resource_private.h>
#include <ci/efrm/vf_resource_private.h>
#include <etherfabric/ef_vi.h>
#include "efrm_internal.h"


static volatile char __iomem *
falcon_eventq_timer_reg(struct efrm_vi* virs, struct efhw_nic *nic)
{
  return nic->bar_ioaddr + falcon_timer_page_addr(virs->rs.rs_instance);
}


static volatile char __iomem * 
falcon_pt_attach_doorbells(volatile char __iomem *bar_ioaddr, 
                           int tx /* or rx */, int instance)
{
  /* direct attach onto a pt resource's doorbells */
  volatile char __iomem * ptr_kva = bar_ioaddr;
  if (tx) ptr_kva += falcon_tx_dma_page_addr(instance);
  else    ptr_kva += falcon_rx_dma_page_addr(instance);
  return ptr_kva;
}


static void falcon_vi_get_mappings(struct efrm_vi* vi_rs,
				   struct efhw_nic* nic,
                                   volatile char __iomem *bar_ioaddr, 
                                   int instance, void *out)
{
  struct vi_mappings* vm = (struct vi_mappings*)out;

  memset(vm, 0, sizeof(*vm));
  vm->signature = VI_MAPPING_SIGNATURE;

  vm->nic_type.arch = EF_VI_ARCH_FALCON;
  vm->nic_type.variant = nic->devtype.variant;
  vm->nic_type.revision = (unsigned char) nic->devtype.revision;

  vm->evq_bytes = efrm_vi_rm_evq_bytes(vi_rs, -1);
  vm->evq_base = NULL;
  vm->evq_timer_reg = NULL;
  if( vm->evq_bytes != 0 ) {
    vm->evq_base = efhw_iopages_ptr(&vi_rs->q[EFHW_EVQ].pages);
    vm->evq_timer_reg = 
      (ef_vi_ioaddr_t)falcon_eventq_timer_reg(vi_rs, nic);
  }
  vm->timer_quantum_ns = nic->timer_quantum_ns;

  vm->vi_instance = instance;
  vm->rx_queue_capacity = vi_rs->q[EFHW_RXQ].capacity;
  vm->rx_dma_falcon = NULL;
  vm->rx_bell = NULL;
  if( vm->rx_queue_capacity != 0 ) {
    vm->rx_dma_falcon =
	    efhw_iopages_ptr(&vi_rs->q[EFHW_RXQ].pages);

    vm->rx_bell = (ef_vi_ioaddr_t)
      falcon_pt_attach_doorbells(bar_ioaddr, /*is_tx*/0, instance);
  }

  vm->tx_queue_capacity = vi_rs->q[EFHW_TXQ].capacity;
  vm->tx_dma_falcon = NULL;
  vm->tx_bell = NULL;
  if( vm->tx_queue_capacity != 0 ) {
    vm->tx_dma_falcon =
	    efhw_iopages_ptr(&vi_rs->q[EFHW_TXQ].pages);

    vm->tx_bell = (ef_vi_ioaddr_t)
      falcon_pt_attach_doorbells(bar_ioaddr, /*is_tx*/1, instance);
  }
}


void efrm_vi_resource_mappings(struct efrm_vi* vi, void* out_vi_data)
{
  struct efhw_nic *nic = vi->rs.rs_client->nic;

  EFRM_RESOURCE_ASSERT_VALID(&vi->rs, 0);
  EFRM_ASSERT(out_vi_data);

  switch( nic->devtype.arch ) {
  case EFHW_ARCH_FALCON:
    falcon_vi_get_mappings(vi, nic, nic->bar_ioaddr,
			   vi->rs.rs_instance, out_vi_data);
    break;
  default:
    EFRM_ASSERT(0);
    break;
  }
}
EXPORT_SYMBOL(efrm_vi_resource_mappings);


int efrm_vi_timer_page_offset(struct efrm_vi* vi)
{
  struct efhw_nic *nic = vi->rs.rs_client->nic;

  EFRM_RESOURCE_ASSERT_VALID(&vi->rs, 0);

  switch( nic->devtype.arch ) {
  case EFHW_ARCH_FALCON:
    return falcon_timer_page_offset(vi->rs.rs_instance);
    break;
  default:
    EFRM_ASSERT(0);
    break;
  }
  /* Should never get here */
  return 0;
}
EXPORT_SYMBOL(efrm_vi_timer_page_offset);


struct efrm_pd *efrm_vi_get_pd(struct efrm_vi *virs)
{
	return virs->pd;
}
EXPORT_SYMBOL(efrm_vi_get_pd);


struct pci_dev *efrm_vi_get_pci_dev(struct efrm_vi *virs)
{
#ifdef CONFIG_SFC_RESOURCE_VF
	if (virs->allocation.vf)
		return virs->allocation.vf->pci_dev;
	else
#endif
		return virs->rs.rs_client->nic->pci_dev;
}
EXPORT_SYMBOL(efrm_vi_get_pci_dev);


struct efrm_vf *efrm_vi_get_vf(struct efrm_vi *virs)
{
	return virs->allocation.vf;
}
