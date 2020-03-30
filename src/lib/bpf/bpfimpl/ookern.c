/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/*************************************************************************
 * This file contains the onload implementation of the non-exported kernel
 * functionality that is used by our kernel eBPF components.
 * It is only used by the actual kernel implementation.  The userspace
 * variants are provided by the kernel compat lib.
 *************************************************************************/

#ifdef __KERNEL__
#include "bpfimpl_kernel_config.h"
#include "bpf_kernel_compat.h"
#include <ci/tools/sysdep.h>

/* Bit of a hack: sysdep_linux.h pulls in too many other headers */
extern void *efrm_find_ksym(const char *name);

void* module_alloc(unsigned long size)
{
  /* We must use the real function, not a vmalloc emulation, because only the
   * real one will allocate memory close to the kernel code (+/-2GB, as
   * required by the JIT) and it needs to know about the kASLR shift */
  typedef void* kfunc_t(unsigned long);
  static kfunc_t* static_kfunc;
  kfunc_t* kfunc = READ_ONCE(static_kfunc);
  if( ! kfunc ) {
    kfunc = efrm_find_ksym("module_alloc");
    WRITE_ONCE(static_kfunc, kfunc);
    if( ! kfunc )
      return NULL;
  }
  return kfunc(size);
}

void module_memfree(void *module_region)
{
  vfree(module_region);
}

int __bpf_prog_charge(struct user_struct *user, u32 pages)
{
  return 0;
}

void __bpf_prog_uncharge(struct user_struct *user, u32 pages)
{
}


typedef int (*set_memory_generic_t)(unsigned long, int);

static int set_memory_generic(set_memory_generic_t* static_kfunc,
                              const char* name, unsigned long addr,
                              int numpages)
{
  set_memory_generic_t kfunc = READ_ONCE(*static_kfunc);
  if( ! kfunc ) {
    kfunc = efrm_find_ksym(name);
    WRITE_ONCE(*static_kfunc, kfunc);
  }
  if( ! kfunc )   /* Not all architectures have this function */
    return 0;
  return kfunc(addr, numpages);
}


int set_memory_ro(unsigned long addr, int numpages)
{
  static set_memory_generic_t static_kfunc;
  return set_memory_generic(&static_kfunc, "set_memory_ro", addr, numpages);
}


int set_memory_rw(unsigned long addr, int numpages)
{
  static set_memory_generic_t static_kfunc;
  return set_memory_generic(&static_kfunc, "set_memory_rw", addr, numpages);
}


int set_memory_x(unsigned long addr, int numpages)
{
  static set_memory_generic_t static_kfunc;
  return set_memory_generic(&static_kfunc, "set_memory_x", addr, numpages);
}


void sha_init(__u32 *buf)
{
  buf[0] = 0x67452301;
  buf[1] = 0xefcdab89;
  buf[2] = 0x98badcfe;
  buf[3] = 0x10325476;
  buf[4] = 0xc3d2e1f0;
}

#endif /* __KERNEL__ */
