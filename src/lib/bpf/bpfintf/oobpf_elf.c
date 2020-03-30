/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <onload/oobpf.h>
#include <onload/bpf_api.h>
#include <onload/version.h>
#include <onload/common.h>
#include <ci/kcompat.h>
#include <uapi/linux/bpf.h>
#include "libc_compat.h"

#if CI_HAVE_LIBELF
#include <libbpf/libbpf.h>


struct oo_bpf_elf {
  struct bpf_object* obj;
  struct oo_bpf_map_info* map_infos;
  ssize_t map_cnt;
  bool is_loaded;
};

static int libbpf_errno_translate(int err)
{
  /* We don't want to expose libbpf errno numbers to callers (who aren't
   * supposed to know that we use libbpf under the hood). These mapping are
   * invented based on a combination of what seems logical and an attempt to
   * disambiguate likely causes of errors as much as possible. */
  switch((enum libbpf_errno)err) {
	case LIBBPF_ERRNO__LIBELF:   return ELIBBAD;
	case LIBBPF_ERRNO__FORMAT:   return ENOEXEC;
	case LIBBPF_ERRNO__KVERSION: return ENOPROTOOPT;
	case LIBBPF_ERRNO__ENDIAN:   return EPROTOTYPE;
	case LIBBPF_ERRNO__INTERNAL: return ELIBSCN;
	case LIBBPF_ERRNO__RELOC:    return EBADF;
	case LIBBPF_ERRNO__LOAD:     return EIO;
	case LIBBPF_ERRNO__VERIFY:   return EILSEQ;
	case LIBBPF_ERRNO__PROG2BIG: return E2BIG;
	case LIBBPF_ERRNO__KVER:     return EPROTONOSUPPORT;
	case LIBBPF_ERRNO__PROGTYPE: return EOPNOTSUPP;
	case LIBBPF_ERRNO__WRNGPID:  return ENODEV;
	case LIBBPF_ERRNO__INVSEQ:   return ESPIPE;
	case LIBBPF_ERRNO__NLPARSE:  return EIO;
	case __LIBBPF_ERRNO__END:    break;
  }
  return EINVAL;
}


static int elf_open_impl(struct bpf_object* obj, struct oo_bpf_elf** elf_out)
{
  if( IS_ERR(obj) ) {
    errno = libbpf_errno_translate(-PTR_ERR(obj));
    return -1;
  }
  *elf_out = calloc(1, sizeof(struct oo_bpf_elf));
  if( ! *elf_out ) {
    bpf_object__close(obj);
    errno = ENOMEM;
    return -1;
  }
  (*elf_out)->map_cnt = -1;
  (*elf_out)->obj = obj;
  return 0;
}


int oo_bpf_open_elf(const char* filename, struct oo_bpf_elf** elf_out)
{
  struct bpf_object_open_attr attr = {
    .file = filename,
    .prog_type = BPF_PROG_TYPE_XDP,  /* Not necessarily correct, but libbpf
                                      * only uses this to determine if it
                                      * should expect a kernel version
                                      * variable */
  };
  return elf_open_impl(bpf_object__open_xattr(&attr), elf_out);
}


int oo_bpf_open_elf_memory(const char* image, size_t bytes,
                           struct oo_bpf_elf** elf_out)
{
  struct bpf_object* obj = bpf_object__open_buffer((char*)image, bytes, NULL,
                                                   BPF_PROG_TYPE_XDP, 0);
  return elf_open_impl(obj, elf_out);
}


void oo_bpf_close_elf(struct oo_bpf_elf* elf)
{
  if( ! elf )
    return;
  bpf_object__close(elf->obj);
  free(elf->map_infos);
  free(elf);
}


ssize_t oo_bpf_elf_get_maps(const struct oo_bpf_elf* elf,
                            struct oo_bpf_elf_map* maps, size_t maps_cnt,
                            size_t sizeof_elf_map)
{
  struct bpf_map* map;
  size_t i;

  if( sizeof_elf_map != sizeof(struct oo_bpf_elf_map) ) {
    /* If/when we get more than one struct layout then it'd be polite to
     * implement some backward-compatibility here */
    errno = EINVAL;
    return -1;
  }
  if( elf->map_cnt < 0 ) {
    /* The elf is logically const, so the API is right. These fields are
     * merely a cache, unobservable outside. i.e. they'd be mutable in C++ */
    struct oo_bpf_elf* welf = (struct oo_bpf_elf*)elf;

    welf->map_cnt = 0;
    bpf_map__for_each(map, elf->obj)
      ++welf->map_cnt;

    welf->map_infos = calloc(welf->map_cnt, sizeof(welf->map_infos[0]));
    if( ! welf->map_infos ) {
      welf->map_cnt = -1;
      errno = ENOMEM;
      return -1;
    }

    i = 0;
    bpf_map__for_each(map, elf->obj) {
      const struct bpf_map_def* def = bpf_map__def(map);
      welf->map_infos[i].type = def->type;
      welf->map_infos[i].key_size = def->key_size;
      welf->map_infos[i].value_size = def->value_size;
      welf->map_infos[i].max_entries = def->max_entries;
      welf->map_infos[i].map_flags = def->map_flags;
      ++i;
    }
  }

  i = 0;
  bpf_map__for_each(map, elf->obj) {
    if( i >= maps_cnt )
      break;
    maps[i].info = &elf->map_infos[i];
    maps[i].fd = bpf_map__fd(map);
    maps[i].name = bpf_map__name(map);
    ++i;
  }
  return elf->map_cnt;
}


int oo_bpf_elf_provide_map(int drv, struct oo_bpf_elf* elf, const char* name,
                           int fd)
{
  struct bpf_map* map;

  (void)drv;   /* This parameter exists for future compatibility reasons, in
                * case it later happens that we need to do some unavoidable
                * checking of 'fd'. */
  bpf_map__for_each(map, elf->obj) {
    if( ! strcmp(bpf_map__name(map), name) ) {
      int rc = bpf_map__reuse_fd(map, fd);
      if( rc < 0 ) {
        errno = libbpf_errno_translate(-rc);
        return -1;
      }
      return 0;
    }
  }
  errno = ENOENT;
  return -1;
}


ssize_t oo_bpf_elf_get_progs(const struct oo_bpf_elf* elf,
                             struct oo_bpf_elf_prog* progs, size_t progs_cnt,
                             size_t sizeof_elf_prog)
{
  struct bpf_program* prog;
  size_t i;

  if( sizeof_elf_prog != sizeof(struct oo_bpf_elf_prog) ) {
    /* If/when we get more than one struct layout then it'd be polite to
     * implement some backward-compatibility here */
    errno = EINVAL;
    return -1;
  }

  i = 0;
  bpf_object__for_each_program(prog, elf->obj) {
    if( i < progs_cnt )
      progs[i].section = bpf_program__title(prog, false);
    ++i;
  }
  return i;
}


struct oo_libbpf_ctx {
  int drv;
  char* log_buf;
  size_t log_size;
  unsigned log_level;
};


int oo_bpf_elf_load_prog(int drv, struct oo_bpf_elf* elf, const char* section,
                         enum bpf_prog_type type,
                         struct oo_bpf_elf_load_attrs* attrs)
{
  struct bpf_program* prog;

  if( attrs ) {
    if( attrs->struct_size != sizeof(*attrs) ||
        attrs->flags != 0 ||
        (attrs->log_level && ! attrs->log_buf ) ||
        (attrs->log_size && ! attrs->log_buf ) ) {
      errno = EINVAL;
      return -1;
    }
  }

  if( ! elf->is_loaded ) {
    int rc;
    struct oo_libbpf_ctx ctx = {
      .drv = drv,
      .log_buf = attrs ? attrs->log_buf : NULL,
      .log_size = attrs ? attrs->log_size : 0,
      .log_level = attrs ? attrs->log_level : 0,
    };

    bpf_object__for_each_program(prog, elf->obj) {
      if( type != BPF_PROG_TYPE_UNSPEC ) {
        bpf_program__set_type(prog, type);
      }
      else {
        enum bpf_prog_type use_type;
        enum bpf_attach_type use_attach;
        rc = libbpf_prog_type_by_name(bpf_program__title(prog, false),
                                      &use_type, &use_attach);
        if (rc < 0) {
          errno = libbpf_errno_translate(-rc);
          return -1;
        }
        bpf_program__set_type(prog, use_type);
      }
    }

    bpf_object__set_priv(elf->obj, &ctx, NULL);
    rc = bpf_object__load(elf->obj);
    bpf_object__set_priv(elf->obj, NULL, NULL);
    if( rc < 0 ) {
      errno = libbpf_errno_translate(-rc);
      return -1;
    }
    elf->is_loaded = true;
  }

  bpf_object__for_each_program(prog, elf->obj) {
    if( ! section || ! strcmp(section, bpf_program__title(prog, false)) ) {
      int rc = bpf_program__fd(prog);
      if( rc < 0 ) {
        errno = libbpf_errno_translate(-rc);
        rc = -1;
      }
      return rc;
    }
  }

  errno = ENOENT;
  return -1;
}


int oo_bpf_elf_install(const char* filename, const char* section,
                       enum oo_bpf_attach_point attach_point,
                       struct oo_bpf_elf_load_attrs* attrs)
{
  struct oo_bpf_elf* elf;
  int saved_errno;
  int rc;
  enum bpf_prog_type prog_type;
  struct oo_bpf_prog_attach_arg attach;

  switch( attach_point ) {
  case OO_BPF_ATTACH_XDP_INGRESS:
    prog_type = BPF_PROG_TYPE_XDP;
    break;
  default:
    errno = EINVAL;
    return -1;
  }

  int drv = open(OO_BPF_DEVICE, O_RDWR | O_CLOEXEC);
  if( drv < 0 )
    return -1;

  if( (rc = oo_bpf_open_elf(filename, &elf)) != 0 ) {
    saved_errno = errno;
    goto fail_open_elf;
  }
  if( (rc = oo_bpf_elf_load_prog(drv, elf, NULL, prog_type, attrs)) < 0 )
    goto fail_load_prog;

  memset(&attach, 0, sizeof(attach));
  attach.attach_point = attach_point;
  attach.prog_fd = rc;
  rc = oo_bpf_prog_attach(drv, &attach);

 fail_load_prog:
  saved_errno = errno;
  oo_bpf_close_elf(elf);
 fail_open_elf:
  close(drv);
  errno = saved_errno;
  return rc;
}


/* These next two functions are called by libbpf internals, within the context
 * of oo_bpf_elf_load_prog() */

int libbpf_create_map_xattr(struct bpf_object* obj,
                            const struct oo_bpf_map_create_arg *attr)
{
  struct oo_libbpf_ctx* ctx = bpf_object__priv(obj);
  int rc = oo_bpf_map_create(ctx->drv, attr);
  return rc < 0 ? -errno : rc;
}


int libbpf_load_program_xattr(struct bpf_object* obj,
                              const struct oo_bpf_prog_load_arg *attr,
                              char* log_buf, size_t log_buf_sz)
{
  int rc;
  struct oo_libbpf_ctx* ctx = bpf_object__priv(obj);
  struct oo_bpf_prog_load_arg arg = *attr;

  /* Ignore the buffer libbpf allocates - the caller supplied their own */
  (void)log_buf;
  (void)log_buf_sz;
  arg.log_level = ctx->log_level;
  arg.log_buf = (uintptr_t)ctx->log_buf;
  arg.log_size = ctx->log_size;
  rc = oo_bpf_prog_load(ctx->drv, &arg);
  return rc < 0 ? -errno : rc;
}


#else /* CI_HAVE_LIBELF */

int oo_bpf_open_elf(const char* filename, struct oo_bpf_elf** elf_out)
{
  errno = ENOSYS;
  return -1;
}


int oo_bpf_open_elf_memory(const char* image, size_t bytes,
                           struct oo_bpf_elf** elf_out)
{
  errno = ENOSYS;
  return -1;
}


void oo_bpf_close_elf(struct oo_bpf_elf* elf)
{
}


ssize_t oo_bpf_elf_get_maps(const struct oo_bpf_elf* elf,
                            struct oo_bpf_elf_map* maps, size_t maps_cnt,
                            size_t sizeof_elf_map)
{
  errno = ENOSYS;
  return -1;
}


int oo_bpf_elf_provide_map(int drv, struct oo_bpf_elf* elf, const char* name,
                           int fd)
{
  errno = ENOSYS;
  return -1;
}


ssize_t oo_bpf_elf_get_progs(const struct oo_bpf_elf* elf,
                             struct oo_bpf_elf_prog* progs, size_t progs_cnt,
                             size_t sizeof_elf_prog)
{
  errno = ENOSYS;
  return -1;
}


int oo_bpf_elf_load_prog(int drv, struct oo_bpf_elf* elf, const char* section,
                         enum bpf_prog_type type,
                         struct oo_bpf_elf_load_attrs* attrs)
{
  errno = ENOSYS;
  return -1;
}


int oo_bpf_elf_install(const char* filename, const char* section,
                       enum oo_bpf_attach_point attach_point,
                       struct oo_bpf_elf_load_attrs* attrs)
{
  errno = ENOSYS;
  return -1;
}

#endif /* ! CI_HAVE_LIBELF */


int oo_bpf_elf_uninstall(enum oo_bpf_attach_point attach_point)
{
  struct oo_bpf_prog_attach_arg detach = {
    .attach_point = attach_point,
    .prog_fd = -1,
  };
  int rc;
  int saved_errno;

  int drv = open(OO_BPF_DEVICE, O_RDWR | O_CLOEXEC);
  if( drv < 0 )
    return -1;

  rc = oo_bpf_prog_detach(drv, &detach);
  saved_errno = errno;
  close(drv);
  errno = saved_errno;
  return rc;
}
