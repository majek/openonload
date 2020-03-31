/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef ONLOAD_BPF_JITINTF_H_
#define ONLOAD_BPF_JITINTF_H_
#include <onload/bpf_api.h>
#include <onload/common.h>


struct oo_bpf_prog_mmap_map {
  struct oo_bpf_map_create_arg meta;
  aligned_uint64_t offset CI_ALIGN(8);
};

struct oo_bpf_prog_mmap_header {
  uint32_t insn_cnt;
  uint32_t map_cnt;
  uint32_t prog_type;
  /* then struct bpf_insn insns[]; */
  /* then struct oo_bpf_prog_mmap_map maps[]; */
} CI_ALIGN(8);


/* Memory-map in the program and all its dependent maps indicated by fd. See
 * struct oo_bpf_prog_mmap_header for the layout of the returned entity. The
 * program is given as unbound BPF bytecode; the caller must pass it through
 * a verifier to bind it, then use a JIT.
 *
 * To free the mapping, call munmap with the 'length' parameter returned by
 * this function.
 *
 * On error, NULL is returned and errno is set appropriately. */
struct oo_bpf_prog_mmap_header* oo_bpf_prog_mmap(int fd, size_t* length);


struct oo_bpf_jitted_prog {
  bpf_prog_t* jitted;
  struct bpf_insn* insns;
  struct oo_bpf_prog_mmap_header* mmhdr;
  size_t mmlen;
  struct oo_bpf_map* map_stubs;
  size_t subprogs_cnt;
  struct oo_bpf_prog_func* subprogs;
};


int oo_bpf_jit(struct oo_bpf_jitted_prog* jp, int fd);
void oo_bpf_jit_free(struct oo_bpf_jitted_prog* jp);

#endif
