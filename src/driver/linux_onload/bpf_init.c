/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file bpf_init.c Kernel-side setup and teardown of Onload BPF
**                     programmes, maps and associated API entry points
** <L5_PRIVATE L5_SOURCE>
** \author  rch
**  \brief  Package - driver/linux	Linux IP driver support
**   \date  2019/01
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_driver_linux */
#include <onload/linux_onload.h>
#include "onload_internal.h"
#include <onload/bpf_ioctl.h>
#include <onload/bpf_internal.h>
#include <linux/anon_inodes.h>
#include <linux/ktime.h>
#include <linux/fs.h>
#include <ci/driver/chrdev.h>
#include <onload/bpf_map_op_wrap.h>
#include <onload/bpf_jitintf.h>
#if CI_HAVE_KERNEL_BPF
#include <uapi/linux/bpf.h>
#include <linux/bpf.h>
#endif

/* We use two devices: this and this+1 */
#define DEV_BPF_MINOR_VERSION   0

static struct ci_chrdev_registration* oo_bpf_chrdevs;
static int oo_perf_ok;

#if CI_HAVE_KERNEL_BPF
static unsigned kbpf_map_get_flags(struct bpf_map* kmap);
static int is_onload_bpf_map(struct bpf_map* map);

/* Value of 'bpf_map_ops' from the kernel. We need this to be able to validate
 * the parameter in lookup/update/delete/etc calls. This field is filled in
 * by map_create, so it's possible that we won't have seen (and hence grabbed)
 * the correct value prior to the first call to a manipulation ioctl, however
 * it'd be a really weird system in which that was the case so we don't worry
 * about it too much. */
static const struct file_operations* copy_kbpf_map_fops;
#else
static struct file_operations oo_bpf_map_fops;
#endif


static int check_and_copy_arg(unsigned cmd, unsigned long argi,
                              void* dst, size_t dst_size)
{
  ci_assert_le(_IOC_SIZE(cmd), dst_size);
  if( _IOC_DIR(cmd) & _IOC_WRITE )
    if( copy_from_user(dst, (const void __user*)argi, _IOC_SIZE(cmd)) )
      return -EFAULT;
  return 0;
}


#if CI_HAVE_KERNEL_BPF
static int call_sys_bpf(int cmd, union bpf_attr* attr)
{
  int rc;
  mm_segment_t old_fs = get_fs();
  set_fs(KERNEL_DS);
  /* sys_bpf() isn't exported, hence the trickery */
  rc = efab_linux_sys_bpf(cmd, attr, sizeof(*attr));
  set_fs(old_fs);
  return rc;
}
#endif


#ifdef __KERNEL__
ci_uint64 ook_bpf_ktime_get_ns(void)
{
  /* The kernel BPF implementation uses ktime_get_mono_fast_ns(), however
   * that's only available on 3.17+. Fortunately, we don't need to be NMI-safe
   * so we can just use the normal function. Note that this has to be the same
   * clock as CLOCK_MONOTONIC, otherwise a BPF programme may observe time
   * jumping around as it executes in both userspace and kernelspace. */
  struct timespec ts;
  ktime_get_ts(&ts);
  return ts.tv_sec * 1000000000ll + ts.tv_nsec;
}
#endif


int oo_have_perf(void)
{
  return oo_perf_ok;
}


/* -*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*- */
/*                             prog file ops                               */

static int oo_bpf_prog_file_release(struct inode* inode, struct file* filp)
{
  ci_assert_nequal(filp->private_data, NULL);
  ook_bpf_prog_decref(filp->private_data);
  return 0;
}


static long oo_bpf_prog_file_ioctl(struct file* filp, unsigned cmd,
                                   unsigned long argi)
{
  ci_assert_nequal(filp->private_data, NULL);

  switch( cmd ) {
  case OO_BPF_IOC_PROG_TEST_RUN: {
    struct oo_bpf_prog_test_run_arg arg;
    int rc = check_and_copy_arg(cmd, argi, &arg, sizeof(arg));
    if( rc )
      return rc;
    return ook_bpf_prog_test_run(filp->private_data, (void __user*)argi, &arg);
  }
  case OO_BPF_IOC_PROG_GET_INFO:
    /* It makes little sense to have a common 'arg' here since
     * ook_bpf_prog_get_info expects a pointer to a struct containing
     * other userspace pointers, which will all be written to. */
    return ook_bpf_prog_get_info(filp->private_data,
                                 (struct oo_bpf_prog_info __user*)argi,
                                 ci_is_sysadmin());
  }
  return -EINVAL;
}



static inline int pages_for(size_t bytes)
{
  return (bytes + CI_PAGE_SIZE - 1) / CI_PAGE_SIZE;
}


#define SIZEOF_BPF_INSN  8
#if CI_HAVE_KERNEL_BPF
/* This assertion is true elsewhere, we just don't have a struct bpf_insn to
 * check it (hence having the macro at all). The size can never change in
 * the future - it's part of the kernel ABI. */
CI_BUILD_ASSERT(SIZEOF_BPF_INSN == sizeof(struct bpf_insn));
#endif


static size_t get_mmap_hdr_len(struct oo_bpf_prog* prog)
{
  return sizeof(struct oo_bpf_prog_mmap_header) +
         sizeof(struct oo_bpf_prog_mmap_map) * prog->used_maps_cnt +
         SIZEOF_BPF_INSN * prog->insn_cnt;
}

static size_t get_mmap_len(struct oo_bpf_prog* prog)
{
  size_t i;
  size_t pages = pages_for(get_mmap_hdr_len(prog));
  /* FIXME: the documentation of oo_bpf_map::data currently promises that you
   * don't have to use that field. That's a lie, given this code. */
  for( i = 0 ; i < prog->used_maps_cnt; ++i )
    pages += prog->used_maps[i]->data_pages;
  return pages * CI_PAGE_SIZE;
}


static loff_t oo_bpf_prog_file_llseek(struct file* filp, loff_t ofs,
                                      int whence)
{
  struct oo_bpf_prog* prog = filp->private_data;
  loff_t len;

  ci_assert_nequal(prog, NULL);
  /* Seeking doesn't actually work in these files. We use this function
   * solely as a method for delivering to userspace the number of bytes that
   * they should call mmap() with. This is all safe because prog fds (and the
   * metadata of the maps to which they refer) are immutable once loaded */
  len = get_mmap_len(prog);
  switch( whence ) {
  case SEEK_SET:
    break;
  case SEEK_CUR:
    ofs += filp->f_pos;
    break;
  case SEEK_END:
    ofs += len;
    break;
  default:
    return -EINVAL;
  }
  if( ofs < 0 )
    ofs = 0;
  if( ofs > len )
    ofs = len;
  filp->f_pos = ofs;
  return ofs;
}

static int oo_bpf_prog_file_mmap(struct file* filp, struct vm_area_struct* vma)
{
  struct oo_bpf_prog* prog = filp->private_data;
  size_t vma_bytes = vma->vm_end - vma->vm_start;
  size_t hdrlen = get_mmap_hdr_len(prog);
  struct oo_bpf_prog_mmap_header* hdr;
  struct oo_bpf_prog_mmap_map* maps;
  int rc = 0;
  size_t i, map_offset;

  ci_assert_nequal(prog, NULL);
  if( vma_bytes == 0 || vma_bytes > get_mmap_len(prog) )
    return -EINVAL;
  hdr = vmalloc_user(hdrlen);
  if( ! hdr )
    return -ENOMEM;

  hdr->insn_cnt = prog->insn_cnt;
  hdr->map_cnt = prog->used_maps_cnt;
  hdr->prog_type = prog->type;
  memcpy(hdr + 1, prog->insns, SIZEOF_BPF_INSN * prog->insn_cnt);

  maps = (void*)((char*)(hdr + 1) + SIZEOF_BPF_INSN * prog->insn_cnt);
  map_offset = pages_for(hdrlen) * CI_PAGE_SIZE;
  for( i = 0; i < prog->used_maps_cnt; ++i ) {
    const struct oo_bpf_map* map = prog->used_maps[i];
    maps[i].offset = map_offset;
    maps[i].meta.map_type = map->map_type;
    maps[i].meta.key_size = map->key_size;
    maps[i].meta.value_size = map->value_size;
    maps[i].meta.max_entries = map->max_entries;
    maps[i].meta.map_flags = map->map_flags;
    /* numa_node currently unused */
    strncpy(maps[i].meta.map_name, map->name, sizeof(maps[i].meta.map_name));

    rc = remap_vmalloc_range_partial(vma, vma->vm_start + map_offset,
                                     map->data,
                                     map->data_pages * CI_PAGE_SIZE);
    if( rc )
      break;
    map_offset += map->data_pages * CI_PAGE_SIZE;
  }

  if( rc == 0 ) {
    rc = remap_vmalloc_range_partial(vma, vma->vm_start, hdr,
                                     pages_for(hdrlen) * CI_PAGE_SIZE);
  }
  /* The page tables took a refcount, so we can free */
  vfree(hdr);
  return rc;
}


static struct file_operations oo_bpf_prog_fops = {
  .owner          = THIS_MODULE,
  .release        = oo_bpf_prog_file_release,
  .unlocked_ioctl = oo_bpf_prog_file_ioctl,
  .compat_ioctl   = oo_bpf_prog_file_ioctl,
  .llseek         = oo_bpf_prog_file_llseek,
  .mmap           = oo_bpf_prog_file_mmap,
};


static int create_prog_fd(struct oo_bpf_prog* prog, int flags)
{
  struct fd f;
  int rc = anon_inode_getfd("oo-bpf-prog", &oo_bpf_prog_fops, prog, flags);
  if( rc < 0 )
    return rc;
  f = fdget(rc);
  if( ! f.file ) {
    /* really ought to be impossible */
    efab_linux_sys_close(rc);
    return -EBADF;
  }
  f.file->f_mode |= FMODE_LSEEK;
  fdput(f);
  return rc;
}


/* -*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*- */
/*                              map file ops                               */

#if CI_HAVE_KERNEL_BPF

/* In order to make our maps substitutable in to kernel functions (so you can
 * share the same map between Onload BPF and kernel BPF programmes), we need
 * to start with a kernel struct bpf_map and whip it in to shape for our own
 * purposes. (In theory we could create a completely new fd ourselves and make
 * it look exactly like a kernel one, but that's a compatibility nightmare).
 *
 * This is not as complicated as it sounds, because we can simply pretend to
 * be a new type of map (i.e. behave exactly as if the kernel had invented a
 * new BPF_MAP_TYPE_BOGOMAP - the core BPF code doesn't care that it's a
 * bogomap because everything goes through the 'ops' vtable).
 *
 * To shoehorn ourselves in, we need to change two things: the 'ops' pointer,
 * and 8 bytes somewhere to point to our struct oo_bpf_map. The "8 bytes
 * somewhere" are defined by the oo_map_priv macro below.
 *
 * The best place to put these 8 bytes would have been immediately before
 * bpf_map::user, where there's a massive alignment hole. Unfortunately,
 * there's no way to verify (at compile time) that the current kernel hasn't
 * been updated to use that alignment hole for anything useful, so instead we
 * put it after the end of the bpf_map, in the space which is private to the
 * specific type of map. This does, of course, assume that there is *some*
 * private data, but that's true currently for all map types and it's
 * difficult to imagine a future map type which didn't need to store
 * something. This location is less cache-optimal than before bpf_map::user
 * but we can optimise-away that inefficiency when the map is used in an
 * Onload BPF programme.
 */

/* See discussion above. Mixed macro/function implementation in order to get
 * both type-checking and an lvalue */
static inline struct oo_bpf_map** oo_map_priv_ptr(struct bpf_map* m)
{
    return (struct oo_bpf_map**)(m + 1);
}
#define oo_map_priv(m)   (*oo_map_priv_ptr((m)))


typedef long (*kmap_manip_op_t)(int, struct bpf_map*, const void __user*,
                                void __user*, ci_uint64);

/* These functions are equivalent to the ook_bpf_map_* implementations, but
 * they call sys_bpf to do their thing, rather than doing it directly, so
 * they're compatible with all the kernel's map types as well as Onload's */

static long kbpf_map_lookup_elem(int fd, struct bpf_map* map,
                                 const void __user* ukey,
                                 void __user* uvalue, ci_uint64 flags)
{
  int rc;
  char stackk[MAX_STACK_SCRATCH_BYTES];
  char* k = map->key_size + map->value_size > sizeof(stackk) ?
              ci_alloc(map->key_size + map->value_size) : stackk;

  (void)flags;
  if( copy_from_user(k, ukey, map->key_size) ) {
    rc = -EFAULT;
  }
  else {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = (uintptr_t)k;
    attr.value = (uintptr_t)(k + map->key_size);
    rc = call_sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr);
    if( rc >= 0 )
      if( copy_to_user(uvalue, (void*)(uintptr_t)attr.value, map->value_size) )
        rc = -EFAULT;
  }
  if( k != stackk )
    ci_free(k);
  return rc;
}


static long kbpf_map_update_elem(int fd, struct bpf_map* map,
                                 const void __user* ukey,
                                 void __user* uvalue, ci_uint64 flags)
{
  MAP_UPDATE_PREFIX
    if( is_onload_bpf_map(map) && oo_map_priv(map)->ops->update_special ) {
      struct oo_bpf_map* oo = oo_map_priv(map);
      oo_map_lock();
      rc = oo->ops->update_special(fd, oo, k, k + map->key_size, flags);
      oo_map_unlock();
    }
    else {
      union bpf_attr attr;
      memset(&attr, 0, sizeof(attr));
      attr.map_fd = fd;
      attr.key = (uintptr_t)k;
      attr.value = (uintptr_t)(k + map->key_size);
      attr.flags = flags;
      rc = call_sys_bpf(BPF_MAP_UPDATE_ELEM, &attr);
    }
  MAP_UPDATE_SUFFIX
}


static long kbpf_map_delete_elem(int fd, struct bpf_map* map,
                                 const void __user* ukey,
                                 void __user* uvalue, ci_uint64 flags)
{
  MAP_DELETE_PREFIX
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = (uintptr_t)k;
    rc = call_sys_bpf(BPF_MAP_DELETE_ELEM, &attr);
  MAP_DELETE_SUFFIX
}


static long kbpf_map_get_next_key(int fd, struct bpf_map* map,
                                  const void __user* ukey,
                                  void __user* unext_key, ci_uint64 flags)
{
  MAP_GET_NEXT_PREFIX
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = ukey ? (uintptr_t)k : (uintptr_t)NULL;
    attr.next_key = (uintptr_t)(k + map->key_size);
    rc = call_sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr);
  MAP_GET_NEXT_SUFFIX
}


static int kbpf_map_get_info(struct bpf_map* kmap,
                             struct oo_bpf_map_info __user* uinfo);

#endif /* CI_HAVE_KERNEL_BPF */


static int/*bool*/ is_bpf_map(struct file* f)
{
#if CI_HAVE_KERNEL_BPF
  const struct file_operations* fops = READ_ONCE(copy_kbpf_map_fops);
  if( f->f_op == fops )
    return 1;
  if( fops == NULL )
    printk_once(KERN_WARNING
                "Onload kernel BPF fops has not yet been initialized\n");
  return 0;
#else
  return f->f_op == &oo_bpf_map_fops;
#endif
}


static long do_map_manip_op(const struct oo_bpf_map_manip_arg* arg,
                            fmode_t mode_required, unsigned bad_map_flags,
                            CI_IF_KBPF(kmap_manip_op_t, oo_map_manip_op_t) op)
{
  int rc;
  struct file* filp = fget(arg->map_fd);

  if( ! filp )
    return -EBADF;
  if( ! is_bpf_map(filp) )
    rc = -EINVAL;
  else if( ! (filp->f_mode & mode_required) )
    rc = -EPERM;
  else {
    /* TODO: this implementation is wrong for per-cpu map types (which are not
     * yet implemented) because it acts on only the current CPU's element. The
     * kernel's struct bpf_map_ops doesn't have appropriate function pointers
     * for doing those operations, so the implementations of map_lookup_elem
     * et al have a block of nasty if statements.
     *
     * The kernel's API isn't really going to work for us for per-CPU maps
     * because it's specified to assume that userspace knows exactly how many
     * elements there are going to be (i.e. num_possible_cpus()) whereas our
     * count is variable and potentially large. I'm currently thinking that we
     * should design ourselves a new API for accessing per-CPU maps. In that
     * case the implementation here is 'good enough' in that it doesn't crash
     * and it does something sort-of unsurprising. */
#if CI_HAVE_KERNEL_BPF
    if( kbpf_map_get_flags(filp->private_data) & bad_map_flags ) {
      fput(filp);
      return -EPERM;
    }
#else
    (void)bad_map_flags;   /* got correctly applied to f_mode, so doesn't need
                              rechecking */
#endif
    rc = op(arg->map_fd, filp->private_data, (const void*)arg->key,
            (void*)arg->value, arg->flags);
  }
  fput(filp);
  return rc;
}


union map_ioctl_args {
  struct oo_bpf_map_manip_arg manip;
  struct oo_bpf_map_get_info_arg get_info;
};


static long common_map_ioctls(unsigned cmd, const union map_ioctl_args* arg)
{
  switch( cmd ) {
  case OO_BPF_IOC_MAP_LOOKUP_ELEM:
    return do_map_manip_op(&arg->manip, FMODE_READ, OO_BPF_F_WRONLY,
                           CI_IF_KBPF(kbpf_map_lookup_elem,
                                      ook_bpf_map_lookup_elem));
  case OO_BPF_IOC_MAP_UPDATE_ELEM:
    return do_map_manip_op(&arg->manip, FMODE_WRITE, OO_BPF_F_RDONLY,
                           CI_IF_KBPF(kbpf_map_update_elem,
                                      ook_bpf_map_update_elem));
  case OO_BPF_IOC_MAP_DELETE_ELEM:
    return do_map_manip_op(&arg->manip, FMODE_WRITE, OO_BPF_F_RDONLY,
                           CI_IF_KBPF(kbpf_map_delete_elem,
                                      ook_bpf_map_delete_elem));
  case OO_BPF_IOC_MAP_GET_NEXT_KEY:
    return do_map_manip_op(&arg->manip, FMODE_READ, OO_BPF_F_WRONLY,
                           CI_IF_KBPF(kbpf_map_get_next_key,
                                      ook_bpf_map_get_next_key));

  case OO_BPF_IOC_MAP_GET_INFO: {
    struct fd f = fdget(arg->get_info.map_fd);
    int rc;

    if( ! f.file )
      return -EBADF;
    if( ! is_bpf_map(f.file) ) {
      rc = -EINVAL;
    }
    else {
#if CI_HAVE_KERNEL_BPF
      rc = kbpf_map_get_info(f.file->private_data, (void*)arg->get_info.info);
#else
      rc = ook_bpf_map_get_info(f.file->private_data,
                                (void*)arg->get_info.info);
#endif
    }
    fdput(f);
    return rc;
  }
  }
  return -EINVAL;
}


#if ! CI_HAVE_KERNEL_BPF

static int oo_bpf_map_file_release(struct inode* inode, struct file* filp)
{
  struct oo_bpf_map* map;

  ci_assert_nequal(filp->private_data, NULL);

  map = filp->private_data;
  if( map->ops->release )
    map->ops->release(map, filp);

  ook_bpf_map_decref(filp->private_data);
  return 0;
}


static long oo_bpf_map_file_ioctl(struct file* filp, unsigned cmd,
                                  unsigned long argi)
{
  int rc;
  union map_ioctl_args arg;

  if( (rc = check_and_copy_arg(cmd, argi, &arg, sizeof(arg))) != 0 )
    return rc;

  /* These interfaces (by accident) allow you to do a manipulation on any
   * other map fd than this one. That's not a security hole, because you've
   * already got both fds */
  return common_map_ioctls(cmd, &arg);
}


static struct file_operations oo_bpf_map_fops = {
  .owner          = THIS_MODULE,
  .release        = oo_bpf_map_file_release,
  .unlocked_ioctl = oo_bpf_map_file_ioctl,
  .compat_ioctl   = oo_bpf_map_file_ioctl,
};

#else /* CI_HAVE_KERNEL_BPF */

static void* kernel_map_redirect_lookup_elem(struct bpf_map* map, void* key)
{
  struct oo_bpf_map* oo = oo_map_priv(map);

  /* All supported map types have a lookup op */
  ci_assert(oo->ops->lookup);

  return oo->ops->lookup(oo, key);
}


static int kernel_map_redirect_update_elem(struct bpf_map* map, void* key,
                                           void* value, u64 flags)
{
  struct oo_bpf_map* oo = oo_map_priv(map);

  if( oo->ops->update )
    return oo->ops->update(oo, key, value, flags);
  else
    return -EINVAL;
}


static int kernel_map_redirect_delete_elem(struct bpf_map* map, void* key)
{
  struct oo_bpf_map* oo = oo_map_priv(map);

  /* All supported map types have a delete op */
  ci_assert(oo->ops->delete);

  return oo->ops->delete(oo, key);
}


static int kernel_map_redirect_get_next_key(struct bpf_map* map, void* key,
                                            void* next_key)
{
  struct oo_bpf_map* oo = oo_map_priv(map);

  /* All supported map types have a get_next_key op */
  ci_assert(oo->ops->get_next_key);

  return oo->ops->get_next_key(oo, key, next_key);
}


#ifdef EFRM_BPF_MAP_OPS_HAS_RELEASE
static void kernel_map_redirect_release(struct bpf_map* map, struct file* file)
{
  struct oo_bpf_map* oo = oo_map_priv(map);

  if( oo->ops->release )
    oo->ops->release(oo, file);
}
#endif


static void kernel_map_redirect_free(struct bpf_map* map)
{
  struct oo_bpf_map* oo = oo_map_priv(map);
  oo_map_priv(map) = oo->replaced_kernel_priv;
  /* <=4.0 map->ops was non-const, hence the cast */
  map->ops = (struct bpf_map_ops*)oo->replaced_kernel_ops;
  map->map_type = oo->map_type;
  ook_bpf_map_decref(oo);
  map->ops->map_free(map);
  module_put(THIS_MODULE);
}


#ifdef EFRM_BPF_MAP_OPS_HAS_GEN_LOOKUP
static u32 kernel_map_redirect_gen_lookup(struct bpf_map* map,
                                          struct bpf_insn* insn_buf)
{
  const struct oo_bpf_map* oo = oo_map_priv(map);
  return oo->ops->gen_lookup(oo, insn_buf);
}
#endif


/* This represents the minimal set of operations that the kernel will allow
 * us to get away with (as of 4.20). New operations may be added here if
 * you're willing to implement them. Note that if we add support for queue or
 * stack map types then push/pop/peek become mandatory too. Likewise, if we
 * pass through the BTF fields to map creation then seq_show_elem becomes
 * mandatory.
 *
 * Note that there are two mutually incompatible copies of this same thing:
 * 1) This one is for giving to the real kernel (if such kernel supports BPF)
 *    so that it may use one of our maps in kernel BPF programmes
 * 2) The one in bpfimpl.a for passing to our own copy of the kernel verifier.
 * The two copies could be identical, if not for the fact that
 * struct bpf_map_ops itself may differ between the two. */
static const struct bpf_map_ops oo_kernel_redirect_map_ops = {
  /* map_alloc_check and map_alloc are required by the kernel
   * implementation, but we never go through their 'create' code path so
   * we don't need to emulate them. */
  .map_lookup_elem = kernel_map_redirect_lookup_elem,
  .map_update_elem = kernel_map_redirect_update_elem,
  .map_delete_elem = kernel_map_redirect_delete_elem,
  .map_get_next_key = kernel_map_redirect_get_next_key,
#ifdef EFRM_BPF_MAP_OPS_HAS_RELEASE
  .map_release = kernel_map_redirect_release,
#endif
  .map_free = kernel_map_redirect_free,
};

/* The verifier uses the NULLness-or-otherwise of .map_gen_lookup to determine
 * whether to call it: there's no way for it to return a 'do nothing' value. */
static const struct bpf_map_ops oo_kernel_redirect_map_ops_with_gen_lookup = {
  .map_lookup_elem = kernel_map_redirect_lookup_elem,
  .map_update_elem = kernel_map_redirect_update_elem,
  .map_delete_elem = kernel_map_redirect_delete_elem,
  .map_get_next_key = kernel_map_redirect_get_next_key,
#ifdef EFRM_BPF_MAP_OPS_HAS_RELEASE
  .map_release = kernel_map_redirect_release,
#endif
  .map_free = kernel_map_redirect_free,
#ifdef EFRM_BPF_MAP_OPS_HAS_GEN_LOOKUP
  .map_gen_lookup = kernel_map_redirect_gen_lookup,
#endif
};


static int is_onload_bpf_map(struct bpf_map* map)
{
  return map->ops == &oo_kernel_redirect_map_ops ||
         map->ops == &oo_kernel_redirect_map_ops_with_gen_lookup;
}


/* Given an fd returned by bpf(BPF_MAP_CREATE), play around with the innards
 * of it in order to turn it in to an Onload map of the same type, i.e. one
 * which is entirely compatible with the original but which is also mappable
 * into userspace */
static int adapt_kernel_bpf_map(int fd, struct oo_bpf_map_create_arg* attr)
{
  struct file* filp = fget(fd);
  struct bpf_map* kmap = filp->private_data;
  struct oo_bpf_map* oomap;
  int rc;

  rc = ook_bpf_map_create(attr, &oomap);
  if( rc >= 0 ) {
    oomap->replaced_kernel_ops = kmap->ops;
    oomap->replaced_kernel_priv = oo_map_priv(kmap);
    /* There are a few places in the kernel which use conditionals rather than
     * going through the ops table (e.g. map_lookup_elem()). Change the map
     * type to be invalid so that those checks always fail */
    kmap->map_type = BPF_MAP_TYPE_UNSPEC;
    kmap->ops = oomap->ops->gen_lookup ?
                    &oo_kernel_redirect_map_ops_with_gen_lookup :
                    &oo_kernel_redirect_map_ops;
    oo_map_priv(kmap) = oomap;

    /* We must prevent ourselves being unloaded while there are pointers to us
     * hanging around in kernel map instances */
    __module_get(THIS_MODULE);
  }
  fput(filp);
  return rc;
}


static unsigned kbpf_map_get_flags(struct bpf_map* kmap)
{
  if( is_onload_bpf_map(kmap) ) {
    struct oo_bpf_map* oomap = oo_map_priv(kmap);
    return oomap->map_flags;
  }
#ifdef BPF_F_NO_PREALLOC
  return kmap->map_flags;
#else
  /* The map flags aren't kept anywhere so we can't check rdonly/wronly.
   * This map is a kernel map, however, so the user has no expectation that
   * the feature is supported on the kernel they're using */
  return 0;
#endif
}


static int kbpf_map_get_info(struct bpf_map* kmap,
                             struct oo_bpf_map_info __user* uinfo)
{
  /* Avoid call_sys_bpf(BPF_OBJ_GET_INFO_BY_FD, ...) because it's new in 4.13
   * and the workaround we implement here is sufficiently simple that we might
   * as well use it even when the official API is present. */
  int rc;
  struct oo_bpf_map_info ooinfo;

  memset(&ooinfo, 0, sizeof(ooinfo));
  /* adapt_kernel_bpf_map lied to the kernal about the map type, for the
   * reason described therein */
  if( is_onload_bpf_map(kmap) ) {
    struct oo_bpf_map* oomap = oo_map_priv(kmap);
    ooinfo.type = oomap->map_type;
    ooinfo.map_flags = oomap->map_flags;
  }
  else {
    ooinfo.type = kmap->map_type;
#ifdef BPF_F_NO_PREALLOC
    /* Field added in 4.6 (to support prealloc mode) */
    ooinfo.map_flags = kmap->map_flags;
#endif
  }
#ifdef EFRM_BPF_MAP_HAS_ID
  /* Field added in 4.13 */
  ooinfo.id = kmap->id;
#endif
  ooinfo.key_size = kmap->key_size;
  ooinfo.value_size = kmap->value_size;
  ooinfo.max_entries = kmap->max_entries;
  rc = copy_to_user(uinfo, &ooinfo, sizeof(*uinfo));
  if( rc != 0 )
    rc = -EFAULT;
  return rc;
}

#endif /* CI_HAVE_KERNEL_BPF */


struct oo_bpf_map* get_oo_map(struct file* f)
{
  if( ! is_bpf_map(f) )
    return NULL;
  return CI_IF_KBPF(oo_map_priv,)(f->private_data);
}


/* -*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*- */
/*                        /dev/onload_bpf file ops                         */

#ifdef BPF_F_RDONLY
CI_BUILD_ASSERT(OO_BPF_F_RDONLY == BPF_F_RDONLY);
#endif

#ifdef BPF_F_WRONLY
CI_BUILD_ASSERT(OO_BPF_F_WRONLY == BPF_F_WRONLY);
#endif

static int translate_fd_flags(int flags)
{
  int ro = flags & OO_BPF_F_RDONLY;
  int wo = flags & OO_BPF_F_WRONLY;

  ci_assert(! (ro && wo));  /* Callers should have checked for this already,
                             * typically with check_map_or_prog_flags() */
  if( ro )
    return O_RDONLY | O_CLOEXEC;
  if( wo )
    return O_WRONLY | O_CLOEXEC;
  return O_RDWR | O_CLOEXEC;
}


int ook_get_prog_fd_for_onload(enum oo_bpf_attach_point attach_point,
                               const char* stack_name, ci_hwport_id_t hwport)
{
  struct oo_bpf_prog* prog;
  int rc = ook_get_prog_for_onload(attach_point, stack_name, hwport,
                                   &prog);
  if( rc < 0 )
    return rc;
  if( prog->kernel_only )
    rc = -EOPNOTSUPP;
  else
    rc = create_prog_fd(prog, O_RDWR | O_CLOEXEC);
  if( rc < 0 )
    ook_bpf_prog_decref(prog);
  return rc;
}


#ifdef BPF_F_NUMA_NODE
#define OO_KMAP_CREATE_FLAGS (OO_BPF_F_RDONLY | OO_BPF_F_WRONLY | \
                              BPF_F_NUMA_NODE)
#else
#define OO_KMAP_CREATE_FLAGS (OO_BPF_F_RDONLY | OO_BPF_F_WRONLY)
#endif

static long oo_bpf_file_ioctl(struct file* filp, unsigned cmd,
                              unsigned long argi)
{
  int rc;
  union {
    oo_version_check_t ver;
    struct oo_bpf_prog_load_arg load;
    struct oo_bpf_prog_attach_arg attach;
    struct oo_bpf_prog_test_run_arg test_run;
    struct oo_bpf_prog_get_all_arg get_all;
    struct oo_bpf_map_create_arg create;
    union map_ioctl_args map;
  } arg;

  /* If this build assert fails then it's time to think about using a more
   * complex storage strategy, to avoid using so much kernel stack */
  CI_BUILD_ASSERT(sizeof(arg) <= 128);

  if( ! ci_is_sysadmin() )
    return -EPERM;

  if( (rc = check_and_copy_arg(cmd, argi, &arg, sizeof(arg))) != 0 )
    return rc;

  /* For documentation of the parameters and semantics of these ioctls, see
   * the prototypes of the userspace wrapper functions in oobpf.h. */
  switch( cmd ) {
  case OO_BPF_IOC_CHECK_VERSION:
    return ook_bpf_version_check(arg.ver.in_version, arg.ver.in_uk_intf_ver,
                                 arg.ver.debug);

  case OO_BPF_IOC_PROG_LOAD: {
    struct oo_bpf_prog* prog;
    int rc = ook_bpf_prog_load(&arg.load, &prog);
    if( rc )
      return rc;
    rc = create_prog_fd(prog, translate_fd_flags(arg.load.prog_flags));
    if( rc < 0 )
      ook_bpf_prog_decref(prog);
    return rc;
  }

  case OO_BPF_IOC_PROG_ATTACH: {
    int rc;
    struct fd f;
    if( arg.attach.prog_fd < 0 )
      return -EINVAL;
    f = fdget(arg.attach.prog_fd);
    if( ! f.file )
      return -EBADF;
    if( f.file->f_op != &oo_bpf_prog_fops )
      rc = -EBADF;
    else
      rc = ook_bpf_prog_attach(f.file->private_data, &arg.attach);
    fdput(f);
    return rc;
  }

  case OO_BPF_IOC_PROG_DETACH: {
    int rc = 0;
    struct fd f = { .file = NULL };

    if( arg.attach.prog_fd >= 0 ) {
      f = fdget(arg.attach.prog_fd);
      if( ! f.file )
        return -EBADF;
      if( f.file->f_op != &oo_bpf_prog_fops )
        rc = -EBADF;
    }
    if( rc == 0 )
      rc = ook_bpf_prog_detach(f.file ? f.file->private_data : NULL,
                               &arg.attach);
    if( f.file )
      fdput(f);
    return rc;
  }

  case OO_BPF_IOC_PROG_GET_BY_ATTACHMENT: {
    struct oo_bpf_prog* prog;
    int rc = ook_bpf_prog_get_by_attachment(&arg.attach, &prog);
    if( rc < 0 )
      return rc;
    rc = create_prog_fd(prog, translate_fd_flags(0));
    if( rc < 0 )
      ook_bpf_prog_decref(prog);
    return rc;
  }

  case OO_BPF_IOC_PROG_GET_ALL:
    return ook_bpf_prog_get_all(arg.get_all.attach_cnt,
                                (void*)arg.get_all.attaches);

  case OO_BPF_IOC_MAP_CREATE:
    {
      int rc = check_map_or_prog_flags(arg.create.map_flags, OO_BPF_F__MAP_ALL);
      if( rc < 0 )
        return rc;
    }
#if CI_HAVE_KERNEL_BPF
    {
      int fd;
      union bpf_attr attr;
      memset(&attr, 0, sizeof(attr));
      /* The set of map types that we support is not supported on all kernel
       * versions that count as CI_HAVE_KERNEL_BPF.  That means we can't
       * rely on being able to create a map of the proper type.  We only use
       * the kernel map to give us something legitimate to use with the bpf
       * syscall, rather than for storing data, so it doesn't really matter
       * what map type we create.  As such we always create a hashmap, because
       * it's always supported.
       *
       * We also limit the flags to only those that are relevant for the
       * kernel part of the map.  Those that are specific to how the data is
       * handled will be validated by onload, and by restricting them here we
       * avoid some painful compat.  */
      attr.map_type = BPF_MAP_TYPE_HASH;
      attr.key_size = arg.create.key_size;
      attr.value_size = arg.create.value_size;
      attr.max_entries = arg.create.max_entries;
#ifdef BPF_F_NO_PREALLOC
      attr.map_flags = arg.create.map_flags & OO_KMAP_CREATE_FLAGS;
      /* We always turn off prealloc, to avoid some of the unnecessary
       * allocation that comes with creating this extra kernel map. */
      attr.map_flags |= BPF_F_NO_PREALLOC;
#ifndef BPF_F_RDONLY
      /* Pre-4.15 kernels don't have these flags. Our options are to disallow
       * the feature (which creates an odd gap in functionality, where non-BPF
       * kernels support it, newer old kernels don't, new kernels do), or to
       * check it ourselves in our ioctls but let the bpf syscall go through
       * unchecked. We choose the latter, on the grounds that it's less weird
       * and it's helpful for making the selftests pass. Fiddling with f_mode
       * after the fact is fraught with danger due to things like
       * i_readcount_inc().
       * The original arg.create.map_flags are passed to adapt_kernel_bpf_map
       * below because our code does support the full flag set. */
      attr.map_flags &= ~(OO_BPF_F_RDONLY | OO_BPF_F_WRONLY);
#endif
#endif
#ifdef BPF_F_NUMA_NODE
      attr.numa_node = arg.create.numa_node;
#endif
#ifdef EFRM_BPF_MAP_HAS_NAME
      strncpy(attr.map_name, arg.create.map_name, sizeof(attr.map_name));
#endif
      fd = call_sys_bpf(BPF_MAP_CREATE, &attr);
      if( fd < 0 )
        return fd;
      if( ! READ_ONCE(copy_kbpf_map_fops) ) {
        struct file* filp = fget(fd);
        WRITE_ONCE(copy_kbpf_map_fops, filp->f_op);
        fput(filp);
      }
      rc = adapt_kernel_bpf_map(fd, &arg.create);
      if( rc < 0 ) {
        efab_linux_sys_close(fd);
        return rc;
      }
      return fd;
    }
#else
    {
      struct oo_bpf_map* map;
      rc = ook_bpf_map_create(&arg.create, &map);
      if( rc < 0 )
        return rc;
      rc = anon_inode_getfd("oo-bpf-map", &oo_bpf_map_fops, map,
                            translate_fd_flags(arg.create.map_flags));
      if( rc < 0 )
        ook_bpf_map_decref(map);
      return rc;
    }
#endif

  default:
    return common_map_ioctls(cmd, &arg.map);
  }
  /* unreachable */
}


static struct file_operations oo_bpf_fops = {
  .owner          = THIS_MODULE,
  .unlocked_ioctl = oo_bpf_file_ioctl,
  .compat_ioctl   = oo_bpf_file_ioctl,
};


/* -*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*- */
/*                         driver setup and teardown                       */


int __init oo_bpf_ctor(void)
{
  const struct ci_chrdev_node_params dev_nodes[] = {
    {
      .name = OO_BPF_DEVICE_NAME,
      .fops = &oo_bpf_fops,
      .mode = 0600,
    }
  };

  int rc = ook_bpf_progs_ctor();
  if( rc < 0 ) {
    /* already logged something */
    return rc;
  }

  rc = create_chrdev_and_mknod(0, 0, "onload_bpf",
                               sizeof(dev_nodes) / sizeof(dev_nodes[0]),
                               dev_nodes, &oo_bpf_chrdevs);
  if( rc < 0 )
    goto fail_chrdev;

  rc = oo_init_perf();
  if( rc == 0 )
    oo_perf_ok = 1;

  return 0;

 fail_chrdev:
  ook_bpf_progs_dtor();
  return rc;
}


void oo_bpf_dtor(void)
{
  oo_release_perf();
  destroy_chrdev_and_mknod(oo_bpf_chrdevs);
  ook_bpf_progs_dtor();
}
