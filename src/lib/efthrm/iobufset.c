/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains non-contiguous I/O buffers support.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#include <ci/efhw/iopage.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efrm/resource.h>
#include <ci/efrm/vf_resource.h>
#include <ci/efrm/pd.h>
#include <onload/iobufset.h>
#include <onload/debug.h>
#include <onload/tcp_driver.h>


/************** IO page operations ****************/

static void oo_iobufset_kfree(struct oo_buffer_pages *pages)
{

  if( (void *)(pages + 1) != (void *)pages->pages )
    kfree(pages->pages);
  kfree(pages);
}

#ifdef OO_DO_HUGE_PAGES

#ifdef CLONE_NEWIPC
#include <linux/nsproxy.h>
#endif

#define OO_SHM_KEY_BASE 0xefab
#define OO_SHM_KEY(id) (OO_SHM_KEY_BASE | (id << 16))
#define OO_SHM_KEY_ID_MASK 0xffff
#define OO_SHM_NEXT_ID(id) ((id + 1) & OO_SHM_KEY_ID_MASK)

static int oo_bufpage_huge_alloc(struct oo_buffer_pages *p, int *flags)
{
  int shmid = -1;
  long uaddr;
  static unsigned volatile last_key_id = 0;
  unsigned start_key_id;
  unsigned id;
  int rc;
  int restore_creds = 0;
#ifdef current_cred
  struct cred *creds;
#endif

  /* sys_shmat does not work when the process is shutting down. */
  if( current->mm == NULL )
    return -EFAULT;

  /* sys_shmget(SHM_HUGETLB) need CAP_IPC_LOCK.
   * So, we give this capability and reset it back.
   * Since we modify per-thread capabilities,
   * there are no side effects. */
#ifdef current_cred
  if (~current_cred()->cap_effective.cap[0] & (1 << CAP_IPC_LOCK)) {
    creds = prepare_creds();
    if( creds != NULL ) {
      creds->cap_effective.cap[0] |= 1 << CAP_IPC_LOCK;
      commit_creds(creds);
      restore_creds = 1;
    }
  }
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24) || \
  !defined(CONFIG_SECURITY)
  /* we need security_capset_set to be inline here */

#ifdef STRICT_CAP_T_TYPECHECKS
#define cap2int(cap) ((cap).cap)
#else
#define cap2int(cap) (cap)
#endif

  if (~cap2int(current->cap_effective) & (1 << CAP_IPC_LOCK)) {
    /* This is bad.
     * We should take non-exported task_capability_lock.
     * Or we should use sys_capset, but we do not have
     * user-space memory to give it to syscall. */
    kernel_cap_t eff = current->cap_effective;
    cap2int(eff) |= 1 << CAP_IPC_LOCK;
    security_capset_set(current, &eff, &current->cap_inheritable,
                        &current->cap_permitted);
    restore_creds = 1;
  }
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,24)
  /* CONFIG_SECURITY, 2.6.24 */

#ifdef STRICT_CAP_T_TYPECHECKS
#define cap2int(cap) ((cap).cap)
#else
#define cap2int(cap) (cap)
#endif

  if (~cap2int(current->cap_effective) & (1 << CAP_IPC_LOCK)) {
    static int printed = 0;
    if (!printed) {
      ci_log("%s: can't allocate huge pages without CAP_IPC_LOCK", __func__);
      printed = 1;
    }
    return -EPERM;
  }
#else
  /* CONFIG_SECURITY, 2.6.25 <= linux <= 2.6.28
   * (2.6.29 is where current_cred defined) */
  if (~current->cap_effective.cap[0] & (1 << CAP_IPC_LOCK)) {
    static int printed = 0;
    if (!printed) {
      ci_log("%s: can't allocate huge pages without CAP_IPC_LOCK", __func__);
      printed = 1;
    }
    return -EPERM;
  }
#endif

  /* Simultaneous access to last_key_id is possible, but we do not care.
   * It is just a hint where we should look for free ids. */
  start_key_id = last_key_id;

  for (id = OO_SHM_NEXT_ID(start_key_id);
       id != start_key_id;
       id = OO_SHM_NEXT_ID(id)) {
    shmid = efab_linux_sys_shmget(OO_SHM_KEY(id), HPAGE_SIZE,
                                  SHM_HUGETLB | IPC_CREAT | IPC_EXCL |
                                  SHM_R | SHM_W);
    if (shmid == -EEXIST)
      continue; /* try another id */
    if (shmid < 0) {
      if (shmid == -ENOMEM && !(*flags & OO_IOBUFSET_FLAG_HUGE_PAGE_FAILED) )
        *flags |= OO_IOBUFSET_FLAG_HUGE_PAGE_FAILED;
      rc = shmid;
      goto out;
    }
    last_key_id = id;
    break;
  }
  if (shmid < 0) {
    ci_log("%s: Failed to allocate huge page: EEXIST", __func__);
    last_key_id = 0; /* reset last_key_id */
    rc = shmid;
    goto out;
  }

  /* We do not need UL mapping, but the only way to obtain the page
   * is to create (and destroy) UL mapping */
  uaddr = efab_linux_sys_shmat(shmid, NULL, 0);
  if (uaddr < 0) {
    rc = (int)uaddr;
    goto fail3;
  }

  down_read(&current->mm->mmap_sem);
  rc = get_user_pages(current, current->mm, (unsigned long)uaddr, 1,
                      1/*write*/, 0/*force*/, &(p->pages[0]), NULL);
  up_read(&current->mm->mmap_sem);
  if (rc < 0)
    goto fail2;
  rc = efab_linux_sys_shmdt((char __user *)uaddr);
  if (rc < 0)
    goto fail1;

  p->shmid = shmid;
#ifdef CLONE_NEWIPC
  p->ipc_ns = current->nsproxy->ipc_ns;
#endif
  rc = 0;
  goto out;

fail1:
fail2:
  put_page(p->pages[0]);
fail3:
  efab_linux_sys_shmctl(shmid, IPC_RMID, NULL);
out:
  if (restore_creds) {
#ifdef current_cred
    creds = prepare_creds();
    if( creds != NULL ) {
      creds->cap_effective.cap[0] &= ~(1 << CAP_IPC_LOCK);
      commit_creds(creds);
    }
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    kernel_cap_t eff = current->cap_effective;
    cap2int(eff) &= ~(1 << CAP_IPC_LOCK);
    security_capset_set(current, &eff, &current->cap_inheritable,
                        &current->cap_permitted);
#else
    ci_assert(0);
#endif
  }
  return rc;
}

#ifdef CLONE_NEWIPC
static void oo_bufpage_huge_free(struct oo_buffer_pages *p);

static void oo_bufpage_huge_free_work(struct work_struct *data)
{
  oo_bufpage_huge_free(container_of(data, struct oo_buffer_pages, wi));
}
#endif

static void oo_bufpage_huge_free(struct oo_buffer_pages *p)
{
  ci_assert(p->shmid >= 0);
  ci_assert(current);
#ifdef CLONE_NEWIPC
  if( current->nsproxy == NULL ) {
    INIT_WORK(&p->wi, oo_bufpage_huge_free_work);
    queue_work(CI_GLOBAL_WORKQUEUE, &p->wi);
  }
  else if( CI_UNLIKELY( current->nsproxy->ipc_ns != p->ipc_ns ) ) {
    /* Ideally, we'd like to call switch_task_namespaces() to get old
     * namespace - but it is not exported.
     * Moreover, it may be destroyed - (get|put)_ipc_ns() are not exported
     * so we can't prevent it. */
    ci_log("Onload does not support applications which use CLONE_NEWIPC "
           "together with huge pages.");
    ci_log("Leaking 1 huge page.");
    put_page(p->pages[0]);
    oo_iobufset_kfree(p);
  }
  else
#endif
  {
    put_page(p->pages[0]);
    efab_linux_sys_shmctl(p->shmid, IPC_RMID, NULL);
    oo_iobufset_kfree(p);
  }
}
#endif
 

/************** Alloc/free page set ****************/

static void oo_iobufset_free_pages(struct oo_buffer_pages *pages)
{
#ifdef OO_DO_HUGE_PAGES
  if( pages->shmid >= 0 )
    oo_bufpage_huge_free(pages);
  else
#endif
  {
    int i;

    for (i = 0; i < pages->n_bufs; ++i)
      __free_pages(pages->pages[i], compound_order(pages->pages[i]));
    oo_iobufset_kfree(pages);
  }
}

static int oo_bufpage_alloc(struct oo_buffer_pages **pages_out,
                            int user_order, int low_order,
                            int *flags, int gfp_flag)
{
  int i;
  struct oo_buffer_pages *pages;
  int n_bufs = 1 << (user_order - low_order);
  int size = sizeof(struct oo_buffer_pages) + n_bufs * sizeof(struct page *);

  if( size < PAGE_SIZE ) {
    pages = kmalloc(size, gfp_flag);
    if( pages == NULL )
      return -ENOMEM;
    pages->pages = (void *)(pages + 1);
  }
  else {
    /* Avoid multi-page allocations */
    pages = kmalloc(sizeof(struct oo_buffer_pages), gfp_flag);
    if( pages == NULL )
      return -ENOMEM;
    ci_assert_le(n_bufs * sizeof(struct page *), PAGE_SIZE);
    pages->pages = kmalloc(n_bufs * sizeof(struct page *), gfp_flag);
    if( pages->pages == NULL ) {
      kfree(pages);
      return -ENOMEM;
    }
  }

  pages->n_bufs = n_bufs;
  oo_atomic_set(&pages->ref_count, 1);

#ifdef OO_DO_HUGE_PAGES
  if( (*flags & (OO_IOBUFSET_FLAG_TRY_HUGE_PAGE |
                 OO_IOBUFSET_FLAG_FORCE_HUGE_PAGE)) &&
      gfp_flag == GFP_KERNEL &&
      low_order == HPAGE_SHIFT - PAGE_SHIFT ) {
    if (oo_bufpage_huge_alloc(pages, flags) == 0) {
      *pages_out = pages;
      return 0;
    }
  }
  pages->shmid = -1;
  if( *flags & OO_IOBUFSET_FLAG_FORCE_HUGE_PAGE ) {
    ci_assert_equal(low_order, HPAGE_SHIFT - PAGE_SHIFT);
    return -ENOMEM;
  }
#endif

  if( low_order > 0 ) {
#ifdef OO_HAVE_COMPOUND_PAGES
    /* __GFP_COMP hint stolen from http://samirdas.blog.com/
     * __GFP_NOWARN is necessary because we properly handle high-order page
     * allocation failure by allocating pages one-by-one. */
    gfp_flag |= __GFP_COMP | __GFP_NOWARN;
#else
    return -EINVAL;
#endif
  }

  for( i = 0; i < n_bufs; ++i ) {
    pages->pages[i] = alloc_pages_node(numa_node_id(), gfp_flag, low_order);
    if( pages->pages[i] == NULL ) {
      OO_DEBUG_VERB(ci_log("%s: failed to allocate page (i=%u) "
                           "user_order=%d page_order=%d",
                           __FUNCTION__, i, user_order, low_order));
      pages->n_bufs = i;
      oo_iobufset_free_pages(pages);
      return -ENOMEM;
    }
    memset(page_address(pages->pages[i]), 0, PAGE_SIZE << low_order);
  }
  
  *pages_out = pages;
  return 0;
}

/************** Alloc/free oo_buffer_pages structure ****************/

void oo_iobufset_pages_release(struct oo_buffer_pages *pages)
{
  if (oo_atomic_dec_and_test(&pages->ref_count))
    oo_iobufset_free_pages(pages);
}

int
oo_iobufset_pages_alloc(int nic_order, int *flags,
                        struct oo_buffer_pages **pages_out)
{
  int rc;
  int gfp_flag = (in_atomic() || in_interrupt()) ? GFP_ATOMIC : GFP_KERNEL;
  int order = nic_order - fls(EFHW_NIC_PAGES_IN_OS_PAGE) + 1;

  ci_assert(pages_out);

#if CI_CFG_PKTS_AS_HUGE_PAGES
  if( *flags & OO_IOBUFSET_FLAG_FORCE_HUGE_PAGE ) {
# ifdef OO_DO_HUGE_PAGES
    rc = oo_bufpage_alloc(pages_out, order, order, flags, gfp_flag);
# else
    rc = -ENOMEM;
# endif
  } else
#endif
  {
#ifdef OO_HAVE_COMPOUND_PAGES
    int low_order = order;
    do {
      /* It is better to allocate high-order pages for many reasons:
       * - in theory, access to continious memory is faster;
       * - with high-order pages, we get small size for dma_addrs array
       *   and it fits into one or two pages.
       *
       * So, if one-compound-page-for-all failed, we try lower order in
       * hope to keep both dma_addrs array and the packet buffers themselves
       * to use not-very-high-order allocations.
       *
       * TODO: it may be useful to go through EF10 page orders:
       * x86: 9(hugepage),8,4,0
       * ppc: 4(max,=9nic),3(=8nic),0(=5nic)
       */
      rc = oo_bufpage_alloc(pages_out, order, low_order, flags, gfp_flag);
      if( rc == 0 || low_order == 0 )
        break;
      low_order -= 3;
      if( low_order < 0 )
        low_order = 0;
    } while( 1 );
#elif defined(OO_DO_HUGE_PAGES) && CI_CFG_PKTS_AS_HUGE_PAGES
    rc = -ENOMEM;
    if( *flags & (OO_IOBUFSET_FLAG_TRY_HUGE_PAGE |
                 OO_IOBUFSET_FLAG_FORCE_HUGE_PAGE) )
      rc = oo_bufpage_alloc(pages_out, order, order, flags, gfp_flag);
    if( rc != 0 )
      rc = oo_bufpage_alloc(pages_out, order, 0, flags, gfp_flag);
#else
    rc = oo_bufpage_alloc(pages_out, order, 0, flags, gfp_flag);
#endif
  }

  OO_DEBUG_VERB(ci_log("%s: [%p] order %d", __FUNCTION__, *pages_out, order));

  return rc;
}

/************** Alloc/free iobufset structure ****************/

static void oo_iobufset_free_memory(struct oo_iobufset *rs)
{
  if( (void *)rs->dma_addrs != (void *)(rs + 1) )
    kfree(rs->dma_addrs);
  kfree(rs);

}
static void oo_iobufset_resource_free(struct oo_iobufset *rs)
{
  efrm_pd_dma_unmap(rs->pd, rs->pages->n_bufs,
                    compound_order(rs->pages->pages[0]),
                    &rs->dma_addrs[0], sizeof(rs->dma_addrs[0]),
                    &rs->buf_tbl_alloc);

  if (rs->pd != NULL)
    efrm_pd_release(rs->pd);
  oo_iobufset_pages_release(rs->pages);

  oo_iobufset_free_memory(rs);
}


void oo_iobufset_resource_release(struct oo_iobufset *iobrs)
{
  if (oo_atomic_dec_and_test(&iobrs->ref_count))
    oo_iobufset_resource_free(iobrs);
}

static void put_user_fake(uint64_t v, uint64_t *p)
{
  *p = v;
}

int
oo_iobufset_resource_alloc(struct oo_buffer_pages * pages, struct efrm_pd *pd,
                           struct oo_iobufset **iobrs_out, uint64_t *hw_addrs)
{
  struct oo_iobufset *iobrs;
  int rc;
  int gfp_flag = (in_atomic() || in_interrupt()) ? GFP_ATOMIC : GFP_KERNEL;
  int size = sizeof(struct oo_iobufset) + pages->n_bufs * sizeof(dma_addr_t);

  ci_assert(iobrs_out);
  ci_assert(pd);

  if( size <= PAGE_SIZE ) {
    iobrs = kmalloc(size, gfp_flag);
    if( iobrs == NULL )
      return -ENOMEM;
    iobrs->dma_addrs = (void *)(iobrs + 1);
  }
  else {
    /* Avoid multi-page allocations */
    iobrs = kmalloc(sizeof(struct oo_iobufset), gfp_flag);
    if( iobrs == NULL )
      return -ENOMEM;
    ci_assert_le(pages->n_bufs * sizeof(dma_addr_t), PAGE_SIZE);
    iobrs->dma_addrs = kmalloc(pages->n_bufs * sizeof(dma_addr_t), gfp_flag);
    if( iobrs->dma_addrs == NULL ) {
      kfree(iobrs);
      return -ENOMEM;
    }

  }

  oo_atomic_set(&iobrs->ref_count, 1);
  iobrs->pd = pd;
  iobrs->pages = pages;

  rc = efrm_pd_dma_map(iobrs->pd, pages->n_bufs,
                       compound_order(pages->pages[0]),
                       &pages->pages[0], sizeof(pages->pages[0]),
                       &iobrs->dma_addrs[0], sizeof(iobrs->dma_addrs[0]),
                       hw_addrs, sizeof(hw_addrs[0]),
                       put_user_fake, &iobrs->buf_tbl_alloc);
  if( rc < 0 )
    goto fail;

  OO_DEBUG_VERB(ci_log("%s: [%p] %d pages", __FUNCTION__,
                       iobrs, iobrs->pages->n_bufs));

  efrm_resource_ref(efrm_pd_to_resource(pd));
  oo_atomic_inc(&pages->ref_count);
  *iobrs_out = iobrs;
  return 0;

fail:
  oo_iobufset_free_memory(iobrs);
  return rc;
}


int oo_iobufset_resource_remap_bt(struct oo_iobufset *iobrs, uint64_t *hw_addrs)
{
  return efrm_pd_dma_remap_bt(iobrs->pd, iobrs->pages->n_bufs,
                              compound_order(iobrs->pages->pages[0]),
                              &iobrs->dma_addrs[0], sizeof(iobrs->dma_addrs[0]),
                              hw_addrs, sizeof(hw_addrs[0]),
                              put_user_fake,
                              &iobrs->buf_tbl_alloc);
}
