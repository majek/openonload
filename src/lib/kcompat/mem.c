/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/kcompat.h>

void kfree(void *objp)
{
  ci_free(objp);
}

void *__vmalloc(unsigned long size, gfp_t gfp_mask, pgprot_t prot)
{
  /* We need somewhere to put the allocated size (for munmap). No callers
   * actually need the returned value to be page-aligned so we could have
   * stuck it just before, however many callers have already page-aligned the
   * 'size' parameter so doing that wouldn't save us any space. Fortunately
   * no allocations from this function last beyond completion of JITting, so
   * we don't care much about the waste of 4088 bytes. */
  size += CI_PAGE_SIZE;
  void* p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if( p == MAP_FAILED )
    return NULL;
  memcpy(p, &size, sizeof(size));
  return (char*)p + CI_PAGE_SIZE;
}

void *vzalloc(unsigned long size)
{
  return __vmalloc(size, 0, 0);
}

void vfree(void *addr)
{
  if( addr ) {
    unsigned long size;
    addr = (char*)addr - CI_PAGE_SIZE;
    memcpy(&size, addr, sizeof(size));
    munmap(addr, size);
  }
};

void *kcalloc(size_t n, size_t size, gfp_t flags)
{
  return ci_calloc(n, size);
}

void *kzalloc(size_t size, gfp_t flags)
{
  return ci_calloc(1, size);
}

void *kmalloc_array(size_t n, size_t size, gfp_t flags)
{
  return ci_alloc(n * size);
}

int copy_from_user(void* dst, const void* src, size_t n)
{
  memcpy(dst, src, n);
  return 0;
}

int copy_to_user(void* dst, const void* src, size_t n)
{
  memcpy(dst, src, n);
  return 0;
}


#if BITS_PER_LONG > 32
# define BPF_JIT_CAN_ACCESS_FULL_ADDRESS_SPACE 0
#else
# define BPF_JIT_CAN_ACCESS_FULL_ADDRESS_SPACE 1
#endif


#if BPF_JIT_CAN_ACCESS_FULL_ADDRESS_SPACE

void* module_alloc(unsigned long size)
{
  char* p = mmap(NULL, size + CI_PAGE_SIZE, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if( p == MAP_FAILED )
    return NULL;
  p += CI_PAGE_SIZE;
  ((unsigned long*)p)[-1] = size + CI_PAGE_SIZE;
  return p;
}


void module_memfree(void *module_region)
{
  unsigned long size = ((unsigned long*)module_region)[-1];
  munmap((char*)module_region - CI_PAGE_SIZE, size);
}


#else /* ! BPF_JIT_CAN_ACCESS_FULL_ADDRESS_SPACE */


#define BPF_CODE_NUM_PAGES  1024   /* 4MB */
static char bpf_malloc_area[BPF_CODE_NUM_PAGES * CI_PAGE_SIZE]
                                                       CI_ALIGN(CI_PAGE_SIZE);
static ci_uint8 bpf_malloc_pages[BPF_CODE_NUM_PAGES];
static pthread_mutex_t bpf_malloc_mtx = PTHREAD_MUTEX_INITIALIZER;

void* module_alloc(unsigned long size)
{
  /* For best efficiency, we need to allocate space within +/-2GB of our own
   * code, because x86-64 doesn't have a 64-bit immediate call opcode in order
   * to call from JITted BPF to precompiled helper functions. The kernel gets
   * away with this because its module_alloc() knows enough about internals
   * to make the guarantee.
   * Options for this evil code are:
   *  - Use our driver to find and call vm_unmapped_area to use the kernel's
   *    more efficient implementation of that phase of this algorithm
   *  - Preallocate a big chunk of empty space in our binary (e.g.
   *    static char empty[1048576];) and write our own allocator to use it
   *  - Randomly poke around using mmap(addr)
   *  - Inject a bunch of thunk indirect jmp opcodes within the generated code
   *    so that we can short-call them and long jmp from there
   *  - Significant modifications to both the verifier and amd64 JIT to
   *    generate long jmps instead (the boundary between verifier and JIT
   *    stores the function offset in a 32-bit space inside the bpf_insn)
   *
   * This code implements option 2 (for now). */
  int pages_needed = (size + CI_PAGE_SIZE - 1) / CI_PAGE_SIZE;
  int start, i;
  void* result = NULL;

  if( pages_needed <= 0 || pages_needed >= 255 )
    return NULL;    /* This would be an implausibly large BPF programme,
                       and we only use bytes for size storage */

  pthread_mutex_lock(&bpf_malloc_mtx);
  /* Dumb linear search. It's only a small number of elements */
  for( i = 0; i < BPF_CODE_NUM_PAGES; ) {
    if( bpf_malloc_pages[i] ) {
      ci_assert_nequal(bpf_malloc_pages[i], 0xff);
      i += bpf_malloc_pages[i];
      ci_assert_le(i, BPF_CODE_NUM_PAGES);
    }
    else {
      start = i;
      for( ++i; i < BPF_CODE_NUM_PAGES; ++i ) {
        if( i - start == pages_needed ) {
          /* found a big enough space: allocate it */
          bpf_malloc_pages[start] = pages_needed;
          /* we could fill the remaining pages with any value and this code
           * would still work. I use a special value solely for
           * debuggability */
          for( i = start + 1; i < start + pages_needed; ++i )
            bpf_malloc_pages[i] = 0xff;
          result = bpf_malloc_area + start * CI_PAGE_SIZE;
          pthread_mutex_unlock(&bpf_malloc_mtx);
          mprotect(result, pages_needed * CI_PAGE_SIZE, PROT_READ | PROT_WRITE);
          return result;
        }
        if( bpf_malloc_pages[i] )
          break;
      }
    }
  }
  pthread_mutex_unlock(&bpf_malloc_mtx);
  return NULL;
}


void module_memfree(void *base)
{
  int ix;
  int npages;

  ci_assert_equal((uintptr_t)base & (CI_PAGE_SIZE - 1), 0);
  pthread_mutex_lock(&bpf_malloc_mtx);
  ci_assert_ge((char*)base, bpf_malloc_area);
  ci_assert_lt((char*)base, bpf_malloc_area + sizeof(bpf_malloc_area));
  ix = ((char*)base - bpf_malloc_area) / CI_PAGE_SIZE;
  npages = bpf_malloc_pages[ix];
  ci_assert_nequal(npages, 0);
  ci_assert_nequal(npages, 0xff);
  mprotect(base, npages * CI_PAGE_SIZE, PROT_NONE);
  bpf_malloc_pages[ix] = 0;
  for( ++ix, --npages; npages; ++ix, --npages) {
    ci_assert_equal(bpf_malloc_pages[ix], 0xff);
    bpf_malloc_pages[ix] = 0;
  }
  pthread_mutex_unlock(&bpf_malloc_mtx);
}

#endif /* BPF_JIT_CAN_ACCESS_FULL_ADDRESS_SPACE */

int set_memory_ro(unsigned long addr, int numpages)
{
  return mprotect((void*)(addr & CI_PAGE_MASK), numpages * CI_PAGE_SIZE,
                  PROT_READ);
}

int set_memory_x(unsigned long addr, int numpages)
{
  return mprotect((void*)(addr & CI_PAGE_MASK), numpages * CI_PAGE_SIZE,
                  PROT_READ | PROT_EXEC);
}

int set_memory_rw(unsigned long addr, int numpages)
{
  return mprotect((void*)(addr & CI_PAGE_MASK), numpages * CI_PAGE_SIZE,
                  PROT_READ | PROT_WRITE);
}

