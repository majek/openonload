/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/driver/internal.h>
#include "linux_char_internal.h"
#include "char_internal.h"
#include <driver/linux_resource/kernel_compat.h>
#include <driver/linux_resource/compat_pat_wc.h>


#if defined(__PPC64__) || defined(__aarch64__)
/* HACK FIXME: PPC and ARM64 kernels that we support do have pgprot_writecombine(),
 * but kernel-compat doesn't detect (I think because it is a macro).
 */
#ifndef EFRM_HAVE_PGPROT_WRITECOMBINE
# define EFRM_HAVE_PGPROT_WRITECOMBINE
#endif
#endif


/****************************************************************************
 *
 * mmap: map userspace onto either pinned down memory or PCI space
 *
 ****************************************************************************/

int 
ci_mmap_bar(struct efhw_nic* nic, off_t base, size_t len, void* opaque,
	    int* map_num, unsigned long* offset, int set_wc)
{
  struct vm_area_struct* vma = (struct vm_area_struct*) opaque;

  if( len == 0 ) {
    EFCH_WARN("%s: ERROR: map_num=%d offset=%lx len=0",
              __FUNCTION__, *map_num, *offset);
    return 0;
  }

  ci_assert(vma);
  ci_assert((len &~ CI_PAGE_MASK) == 0);
  ci_assert((*offset &~ CI_PAGE_MASK) == 0);
  ci_assert(*map_num == 0 || *offset > 0);

  vma->vm_flags |= EFRM_VM_IO_FLAGS;

  if( set_wc ) {
#ifdef CONFIG_FORCE_PIO_NON_CACHED
    EFCH_WARN("%s: mapping PIO in non cached mode", __FUNCTION__);
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
#elif defined EFRM_HAVE_PGPROT_WRITECOMBINE 
    vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
#elif defined HAS_COMPAT_PAT_WC
    if( !compat_pat_wc_is_initialized() ) {
      EFCH_WARN("%s: ERROR: write combining compatibility module not initialized",
         __FUNCTION__);
      return -EINVAL;
    }
    else
      vma->vm_page_prot = compat_pat_wc_pgprot_writecombine(vma->vm_page_prot);
#else
    EFCH_WARN("%s: ERROR: This kernel version does not support writecombining",
              __FUNCTION__);
    return -EINVAL;
#endif
  }
  else
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

  EFCH_TRACE("%s: pages=%d offset=0x%x phys=0x%llx prot=0x%lx",
             __FUNCTION__, (int) (len >> CI_PAGE_SHIFT),
             (int) (*offset >> CI_PAGE_SHIFT),
             (unsigned long long) (nic->ctr_ap_dma_addr + base),
             (unsigned long) pgprot_val(vma->vm_page_prot));

  ++*map_num;
  *offset += len;

  return ci_io_remap_pfn_range(vma, vma->vm_start + *offset - len,
			       (nic->ctr_ap_dma_addr + base) >> PAGE_SHIFT, len,
			       vma->vm_page_prot);
}


void ci_mmap_iopages(struct efhw_iopages* p, unsigned offset,
                     unsigned max_bytes, unsigned long* bytes, void* opaque,
                     int* map_num, unsigned long* p_offset)
{
  unsigned n;

  ci_assert(opaque);
  ci_assert(map_num);
  ci_assert(p_offset);
  ci_assert((*p_offset &~ PAGE_MASK) == 0);
  ci_assert(*map_num == 0 || *p_offset > 0);

  EFCH_TRACE("%s: offset=0x%x max_bytes=0x%x *bytes=0x%lx *p_offset=0x%lx",
             __FUNCTION__, offset, max_bytes, *bytes, *p_offset);

  n = efhw_iopages_size(p) - offset;
  n = CI_MIN(n, max_bytes);
  n = CI_MIN(n, *bytes);
  *bytes -= n;
  ++*map_num;
  *p_offset += n;
}

