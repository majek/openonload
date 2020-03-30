/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Pinning down buffers on Linux.
**   \date  2003/??
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_driver_linux */
#include <ci/driver/internal.h>
#include <onload/debug.h>

/* This controls whether we see error messages from my_follow_page(). */
#define FPL(x)		CI_DEBUG(x)

/**********************************************************************
 * Internal implementation.
 */

struct page* ci_follow_page(ci_addr_spc_t addr_spc, caddr_t uaddr)
{
#ifdef p4d_page
  p4d_t* p4d;
#endif
  pgd_t* pgd;
  pmd_t* pmd;
  pte_t* ptep;
  pte_t  pte;
  pud_t* pud;
  struct page* pg = 0;
  ci_uintptr_t address = (ci_uintptr_t)uaddr;

  /* ?? Can we avoid a lock per page? */
  spin_lock(&addr_spc->page_table_lock);

  pgd = pgd_offset(addr_spc, address);
  if( CI_UNLIKELY(pgd_none(*pgd) | pgd_bad(*pgd)) ) {
    FPL(ci_log("follow_page: %lx pgd_none=%d pgd_bad=%d",
	       (long)address, (int) pgd_none(*pgd), (int) pgd_bad(*pgd)));
    goto done;
  }

#ifdef p4d_page
  p4d = p4d_offset(pgd, address);
  if( CI_UNLIKELY(p4d_none(*p4d) | p4d_bad(*p4d)) ) {
    FPL(ci_log("follow_page: %lx p4d_none=%d p4d_bad=%d",
	       (long)address, (int) p4d_none(*p4d), (int) p4d_bad(*p4d)));
    goto done;
  }
  pud = pud_offset(p4d, address);
#else
  pud = pud_offset(pgd, address);
#endif
  if( CI_UNLIKELY(pud_none(*pud) | pud_bad(*pud)) ) {
    FPL(ci_log("follow_page: %lx pud_none=%d pud_bad=%d",
	       (long)address, (int) pud_none(*pud), (int) pud_bad(*pud)));
    goto done;
  }
  pmd = pmd_offset(pud, address);

  if( CI_UNLIKELY(pmd_none(*pmd) | pmd_bad(*pmd)) ) {
    FPL(ci_log("follow_page: %lx pmd_none=%d pmd_bad=%d",
	       (long)address, (int) pmd_none(*pmd), (int) pmd_bad(*pmd)));
    goto done;
  }

  ptep = pte_offset_map(pmd, address);
  if( CI_UNLIKELY(!ptep) ) {
    FPL(ci_log("follow_page: %lx no pte", (long)address));
    goto done;
  }

  pte = *ptep;
  pte_unmap(ptep);
  if( CI_LIKELY(pte_present(pte)) ) {
    if( ci_pte_valid(pte) )
      pg = pte_page(pte);
    else
      FPL(ci_log("follow_page: %lx pfn=%lx not valid", (long)address, 
                 (long)pte_pfn(pte)));
    get_page(pg);
  }
  else
    OO_DEBUG_VERB(ci_log("follow_page: %lx not present", (long)address));

 done:
  spin_unlock(&addr_spc->page_table_lock);

  return pg;
}

/*! \cidoxg_end */
