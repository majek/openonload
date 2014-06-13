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
*//*! \file driver.c mmap file operation--for onload and sfc_char driver
** <L5_PRIVATE L5_SOURCE>
** \author  slp
**  \brief  Package - driver/linux	Linux driver support
**     $Id$
**   \date  2002/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux */


/*--------------------------------------------------------------------
 *
 * Compile time assertions for this file
 *
 *--------------------------------------------------------------------*/

#define __ci_driver_shell__	/* implements driver to kernel interface */

/*--------------------------------------------------------------------
 *
 * CI headers
 *
 *--------------------------------------------------------------------*/

#include "linux_char_internal.h"
#include "efch.h"
#include <ci/efhw/public.h>
#include <ci/efch/op_types.h>
#include <ci/tools/dllist.h>
#include "char_internal.h"


struct mm_hash {
  ci_dllink         link;
  struct mm_struct *mm;
  unsigned          ref;
  unsigned          magic;
};

/* All valid mm_hash structures have their 'magic' member set to this */
enum {MM_ENTRY_MAGIC = 0xabadf00l};

/* No. of entries in the mm hash-table.  The usual tradeoff -- bigger number
 * uses more mem but with shorter chains, so potentially better performance
 */
enum {MM_HASH_SIZE=256};

/* The hash-table is an array of lists of mm_hash structures. */
static ci_dllist mm_hash_tbl[MM_HASH_SIZE];

/* A lock to protect the hash-table.  If we really wanted to go mad we could
 * have one lock per entry in the table.  But the hash-table is infrequently
 * updated, so a single r/w lock should suffice.
 */
DEFINE_RWLOCK(ci_mm_tbl_lock);


/* Function to hash an 'mm' pointer */
static inline unsigned int
hash_mm (struct mm_struct *mm) {
  ci_uintptr_t t = (ci_uintptr_t)mm;
  ci_assert (t);
  /* The mm was allocated from a slab cache and so for normal builds is 
  * aligned to L1 cache line. No point using always zero bits in the hash. */
  return (t / (unsigned)L1_CACHE_BYTES) & (MM_HASH_SIZE-1);
}

/* Utility function to find current process's entry in the mm hash table.
 * Returns pointer to current process's mm-hash struct, or NULL if not found
 * Hash table lock must be held in read or write mode by caller.
 *
 * Lock must be held in read or write mode
 */
static struct mm_hash*
ci_mm_tbl_lookup(struct mm_struct *mm)
{
  struct mm_hash *p;
  int hash = hash_mm (mm);
  ci_assert (mm_hash_tbl [hash].l.next);
  ci_assert (mm_hash_tbl [hash].l.prev);
  for (p = (struct mm_hash*) ci_dllist_head (&mm_hash_tbl [hash]);
       !ci_dllist_is_anchor (&mm_hash_tbl [hash], &p->link);
       p = (struct mm_hash*) p->link.next) {
    ci_assert (p->magic == MM_ENTRY_MAGIC);
    if (p->mm == mm)
      return p;
  }

  return NULL;
}
 

/* Add a new item to the mm hash table.  At the point of calling, the
 * table must be locked in write mode, and the entry to add be not already
 * present in the hash table.  The newly added entry will have a
 * reference-count of zero.
 *
 * Returns a pointer to the newly added entry
 * Returns with the lock still held
 */
static struct mm_hash*
efch_create_mm_entry (struct mm_struct *mm) {
  struct mm_hash *p;

  ci_assert( ! ci_mm_tbl_lookup(mm));

  p = kmalloc (sizeof *p, 0);
  if (p) {
    EFCH_TRACE("%s: made mm_hash %p for mm %p", __FUNCTION__, p, mm);
    p->magic = MM_ENTRY_MAGIC;
    p->mm = mm;
    p->ref = 0;               // Will be inc-ed by caller
    ci_dllist_push (&mm_hash_tbl [hash_mm (mm)], &p->link);
  }

  return p;
}


/* Incrememnts a reference count on an item in the MM hash table.  If there is
 * no record of key 'mm' in the table, one is created.  In this case it's
 * reference count is '1' when the function returns.
 *
 * Must be called with a non-NULL 'mm' pointer
 * Must be called with the table lock NOT held.
 *
 * Returns zero on success, or -ve error code on failure.
 */
static int efch_add_mm_ref (struct mm_struct *mm) {

#if defined(__PPC__)		/* TEMP ONLY until trampoline system is supported */
  return 0;
#endif

  int rc = 0;
  struct mm_hash *p;

  ci_assert (mm);
  write_lock (&ci_mm_tbl_lock);
 
  /* Does this mm already exists in the hash table? */
  p = ci_mm_tbl_lookup(mm);
  if (!p) {
    /* Nope -- create one */
    p = efch_create_mm_entry (mm);
    if (!p) {
      rc = -ENOMEM;
      goto exit;
    }
  }

  ci_assert (p);
  p->ref++;

  write_unlock (&ci_mm_tbl_lock);
exit:
  return rc;
}

/* Decrements a reference on an item in the MM hash-table.
 * 'mm' must be in the table at the time of calling.
 * If the reference count decrements to zero, the item is removed from the
 * table (and its associated storage freed).
 * 
 * Must be called with the lock NOT held
 */
static void efch_del_mm_ref (struct mm_struct *mm) {

#if defined(__PPC__)		/* TEMP ONLY until trampoline system is supported */
  return;
#endif

  struct mm_hash *p;

  write_lock (&ci_mm_tbl_lock);

  p = ci_mm_tbl_lookup(mm);
  ci_assert (p);
  ci_assert (p->mm == mm);

  if (!--p->ref) {
    EFCH_TRACE("%s: deleting mm_hash %p for mm %p", __FUNCTION__, p, mm);
    ci_dllist_remove (&p->link);
    kfree (p);
  }

  write_unlock (&ci_mm_tbl_lock);
}


void ci_mm_tbl_init(void)
{
  int i;
  for( i = 0; i < MM_HASH_SIZE; i++ )
    ci_dllist_init(&mm_hash_tbl[i]);
}


/****************************************************************************
 *
 * mmap: need VM operations to keep track of mmaps onto resources
 *
 ****************************************************************************/

static void vm_op_open(struct vm_area_struct* vma)
{
  struct efrm_resource *rs = vma->vm_private_data;

  EFRM_RESOURCE_ASSERT_VALID(rs, 0);

  EFCH_TRACE("%s: "EFRM_RESOURCE_FMT" vma=%p",
             __FUNCTION__, EFRM_RESOURCE_PRI_ARG(rs), vma);

  efch_add_mm_ref (vma->vm_mm); /* Shit -- what if we ENOMEM? */
  efrm_resource_ref(rs);
}


static void vm_op_close(struct vm_area_struct* vma)
{
  struct efrm_resource *rs = vma->vm_private_data;

  EFCH_TRACE("%s: "EFRM_RESOURCE_FMT" vma=%p",
             __FUNCTION__, EFRM_RESOURCE_PRI_ARG(rs), vma);

  efch_del_mm_ref(vma->vm_mm);
  EFRM_RESOURCE_ASSERT_VALID(rs, 0);
  efrm_resource_release(rs);
}


#define VMA_OFFSET(vma)  ((vma)->vm_pgoff << PAGE_SHIFT)

#ifndef NOPAGE_SIGBUS
#  define NOPAGE_SIGBUS (NULL)
#endif

static struct page* vm_op_nopage(struct vm_area_struct* vma, 
				  unsigned long address,
				  int* type)
{
  struct efrm_resource *rs = vma->vm_private_data;
  efch_resource_ops *ops;

  EFRM_RESOURCE_ASSERT_VALID(rs, 0);

  ops = efch_ops_table[rs->rs_type];
  if( ops->rm_nopage ) {
    unsigned pfn;
    struct page *pg;
    pfn = ops->rm_nopage(rs, vma, address - vma->vm_start,
                         vma->vm_end - vma->vm_start);
    if( pfn != (unsigned) -1 ) {
      pg = pfn_to_page(pfn);

      /* Linux 2.6.15 introduce VM_PFNMAP.  At that stage, put_page
       * was modified to decrement the page reference count even if
       * PG_reserved is set.  The idea is that put_page is never
       * called for areas with VM_PFNMAP set and that the two flags
       * match up.  Under some circumstances (2.6.13/x86_64) we have
       * PG_reserved set, but never have VM_PFNMAP set.  We need to
       * know if get_page needs to be called.  Really, get_page should
       * never have incremented the reference count if put_page wasn't
       * going to decrement it, but it's a bit late now.
       */
#ifdef VM_PFNMAP
      get_page(pg);
#else
      if(!PageReserved(pg))
        get_page(pg);
#endif

      if( type )  *type = VM_FAULT_MINOR;

      EFCH_TRACE("%s: "EFRM_RESOURCE_FMT" vma=%p sz=%lx pageoff=%lx id=%d "
                 "pfn=%x", __FUNCTION__, EFRM_RESOURCE_PRI_ARG(rs),
                 vma, vma->vm_end - vma->vm_start,
                 (address - vma->vm_start) >> CI_PAGE_SHIFT,
                 EFAB_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma)), pfn);
      return pg;
    }
  }

  /* Linux walks VMAs on core dump, suppress the message */
  if( ~current->flags & PF_DUMPCORE )
    CI_DEBUG(ci_log("%s: "EFRM_RESOURCE_FMT" vma=%p sz=%lx pageoff=%lx id=%d FAILED%s",
		    __FUNCTION__, EFRM_RESOURCE_PRI_ARG(rs),
		    vma, vma->vm_end - vma->vm_start,
		    (address - vma->vm_start) >> CI_PAGE_SHIFT,
                    EFAB_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma)),
		    ops->rm_nopage ? "":" NO HANDLER"));

  return NOPAGE_SIGBUS;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
static int vm_op_fault(struct vm_area_struct *vma, struct vm_fault *vmf) {
  struct page* ret;

  ret = vm_op_nopage(vma, (long int)vmf->virtual_address, NULL);
  vmf->page = ret;
  return (ret==NOPAGE_SIGBUS) ? VM_FAULT_SIGBUS : 0; 
}
#endif

static struct vm_operations_struct vm_ops = {
  .open  = vm_op_open,
  .close = vm_op_close,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
  .nopage = vm_op_nopage
#else
  .fault = vm_op_fault
#endif
};


/****************************************************************************
 *
 * mmap: map userspace onto either pinned down memory or PCI space
 *
 ****************************************************************************/

int
ci_char_fop_mmap(struct file* file, struct vm_area_struct* vma)
{
  ci_private_char_t* priv = (ci_private_char_t*) file->private_data;
  efch_resource_t* rs;
  efch_resource_id_t rsid;
  off_t offset;
  unsigned long bytes, map_offset;
  int rc, map_num;

  if( !priv )  return -EBADF;

  offset = VMA_OFFSET(vma);
  bytes = vma->vm_end - vma->vm_start;

  if( bytes == 0 ) {
    ci_log("ci_char_fop_mmap: bytes == 0");
    return -EINVAL;
  }

  ci_assert((offset & PAGE_MASK) == offset);

  /* NB. Resources can never be freed from the resource_table, so no need
  ** to take a lock here to do resource lookup.
  */
  rsid = EFAB_MMAP_OFFSET_TO_RESOURCE_ID(offset);
  if( (rc = efch_resource_id_lookup(rsid, &priv->rt, &rs)) < 0 )
    return rc;

  if( (rc = efch_add_mm_ref (vma->vm_mm)) < 0 )
    return rc;

  /* VM_RESERVED prevents the MM from attempting to swap-out these
   * pages.
   *
   * VM_IO is there to avoid people getting references to our pages to
   * do direct-IO.  This has been recommended on the LKML.
   * http://www.forbiddenweb.org/viewtopic.php?id=83167&page=3#347912
   */
  vma->vm_flags |= VM_RESERVED | VM_IO;

  /* Hook into the VM so we can keep a proper reference count on this
  ** resource.
  */
  vma->vm_ops = &vm_ops;
  vma->vm_private_data = rs->rs_base;
  efrm_resource_ref(rs->rs_base);

  EFCH_TRACE("%s: "EFCH_RESOURCE_ID_FMT " -> " EFRM_RESOURCE_FMT 
             " %d pages offset=0x%lx vma=%p ptr=0x%lx-%lx", 
             __FUNCTION__, EFCH_RESOURCE_ID_PRI_ARG(rsid),
             EFRM_RESOURCE_PRI_ARG(rs->rs_base),
             (int) (bytes >> CI_PAGE_SHIFT), offset, 
             vma, vma->vm_start, vma->vm_end);

  map_offset = map_num = 0;

  rc = rs->rs_ops->rm_mmap(rs->rs_base, &bytes, vma, &map_num, &map_offset,
                           EFAB_MMAP_OFFSET_TO_MAP_ID(offset));
  if( rc < 0 ) {
    efrm_resource_release(rs->rs_base);
    efch_del_mm_ref (vma->vm_mm);
  }

  /* the call to rm_mmap should have decremented bytes according to the
     amount of memory it filled. If we've got any left, the user asked for
     too much, which is worrying */
#ifndef NDEBUG
  if( bytes && rc == 0 )
    ci_log("mmap: "EFRM_RESOURCE_FMT" %d pages unmapped (offset=%lx "
           "map_id=%d res_id="EFCH_RESOURCE_ID_FMT")",
           EFRM_RESOURCE_PRI_ARG(rs->rs_base),
           (int) (bytes>>CI_PAGE_SHIFT),
           (unsigned long) offset, (int) EFAB_MMAP_OFFSET_TO_MAP_ID(offset),
           EFCH_RESOURCE_ID_PRI_ARG(rsid));
#endif

  return rc;
}

