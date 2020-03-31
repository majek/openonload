/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <onload/bpf_jitintf.h>
#include <ci/kcompat.h>
#include <onload/bpf_internal.h>
#include <uapi/linux/bpf.h>


int oo_debug_bits = 0;

struct oo_bpf_prog_mmap_header* oo_bpf_prog_mmap(int fd, size_t* length)
{
  struct oo_bpf_prog_mmap_header *hdr;
  off_t len = lseek(fd, 0, SEEK_END);
  if( len == (off_t)-1 )
    return NULL;
  ci_assert_equal(len & (CI_PAGE_SIZE - 1), 0);
  hdr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if( hdr == MAP_FAILED )
    return NULL;
  *length = len;
  return hdr;
}


/* supporting fake functions for verifier & JIT */

static __thread struct oo_bpf_jitted_prog* jit_ctx;

struct fd fdget(unsigned int fd)
{
  struct fd f = { .file = NULL, .flags = 0 };
  if( fd < jit_ctx->mmhdr->map_cnt )
    f.file = (void*)(jit_ctx->map_stubs + fd);
  return f;
}

void fdput(struct fd fd)
{
  (void)fd;
}

struct oo_bpf_map* get_oo_map(struct file* f)
{
  return (struct oo_bpf_map*)f;
}


int oo_bpf_jit(struct oo_bpf_jitted_prog* jp, int fd)
{
  int rc;
  int saved_errno = errno;

  jp->mmhdr = oo_bpf_prog_mmap(fd, &jp->mmlen);
  if( ! jp->mmhdr ) {
    rc = -errno;
    goto fail_mmap;
  }
  jp->map_stubs = NULL;
  if( jp->mmhdr->map_cnt ) {
    const struct oo_bpf_prog_mmap_map* maps;
    unsigned i;
    jp->map_stubs = ci_calloc(jp->mmhdr->map_cnt, sizeof(jp->map_stubs[0]));
    if( ! jp->map_stubs ) {
      rc = -ENOMEM;
      goto fail_maps;
    }
    maps = (void*)((struct bpf_insn*)(jp->mmhdr + 1) + jp->mmhdr->insn_cnt);
    for( i = 0; i < jp->mmhdr->map_cnt; ++i ) {
      rc = oo_bpf_map_init(&jp->map_stubs[i], &maps[i].meta, NULL);
      jp->map_stubs[i].data = (char*)jp->mmhdr + maps[i].offset;
      if( rc )
        goto fail_one_map;
    }
  }
  jp->insns = (struct bpf_insn*)(jp->mmhdr + 1);
  jit_ctx = jp;
  rc = oou_bpf_prog_jit(jp->insns, jp->mmhdr->insn_cnt, jp->mmhdr->prog_type,
                        &jp->subprogs_cnt, &jp->subprogs);
  jit_ctx = NULL;
  if( rc )
    goto fail_jit;
  jp->jitted = jp->subprogs[0].func;
  errno = saved_errno;
  return 0;

 fail_jit:
 fail_one_map:
  ci_free(jp->map_stubs);
 fail_maps:
  munmap(jp->mmhdr, jp->mmlen);
 fail_mmap:
  errno = saved_errno;
  return rc;
}


void oo_bpf_jit_free(struct oo_bpf_jitted_prog* jp)
{
  unsigned i;
  int saved_errno = errno;

  for( i = 0; i < jp->mmhdr->map_cnt; ++i )
    ci_assert_equal(ci_atomic_read(&jp->map_stubs[i].refcount), 1);
  oo_bpf_free_progs_array(&jp->subprogs, &jp->subprogs_cnt);
  munmap(jp->mmhdr, jp->mmlen);
  ci_free(jp->map_stubs);
  memset(jp, 0, sizeof(*jp));
  errno = saved_errno;
}
