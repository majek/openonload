/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* This file contains the structures and other definitions representing the
 * user/kernel API to /dev/onload_bpf. This and bpf_ioctl.h are the files
 * which are ABI-checked (by md5sum) to ensure user/kernel consistency of the
 * BPF facilities. This file should be kept free of significant Onload
 * #include dependencies, to make it easy to use it from programmes compiled
 * outside of the Onload tree. */

#ifndef ONLOAD_BPF_API_H_
#define ONLOAD_BPF_API_H_
#ifdef __KERNEL__
# include <linux/types.h>
#else
# include <stdint.h>
#endif

/* NB: this symbol is already defined by the kernel headers. Redefine it
 * verbatim to cope with cases where we don't have the kernel headers and to
 * cause a compiler error if the kernel ever changes their value (which they
 * can't, because it's part of the ABI). */
#define BPF_OBJ_NAME_LEN  16U

/* Again, duplicate verbatim definition from compat/gcc.h */
#define CI_ALIGN(x) __attribute__ ((aligned (x)))

/* A value at least as large as we ever expect CI_CFG_STACK_NAME_LEN to grow
 * in the future */
#define OO_BPF_STACK_NAME_LEN  64


#define OO_BPF_DEVICE_NAME   "onload_bpf"
#define OO_BPF_DEVICE   "/dev/" OO_BPF_DEVICE_NAME


/* Flags for oo_bpf_prog_load_arg::prog_flags and
 * oo_bpf_map_create_arg::map_flags. These values must match the kernel's
 * definitions. */
#define OO_BPF_F_NO_PREALLOC   0x0001
#define OO_BPF_F_RDONLY        0x0008
#define OO_BPF_F_WRONLY        0x0010

#define OO_BPF_F__PROG_ALL  (OO_BPF_F_RDONLY | OO_BPF_F_WRONLY)
#define OO_BPF_F__MAP_ALL   (OO_BPF_F_RDONLY | OO_BPF_F_WRONLY | \
                             OO_BPF_F_NO_PREALLOC)

#ifdef __i386__
# define OO_BPF_JIT_FUNC_ATTR   __attribute__((regparm(3)))
#else
# define OO_BPF_JIT_FUNC_ATTR
#endif


struct bpf_insn;
typedef unsigned bpf_prog_t(const void* ctx, const struct bpf_insn* insns)
        OO_BPF_JIT_FUNC_ATTR;

typedef uint64_t aligned_uint64_t CI_ALIGN(8);

struct oo_bpf_prog_func {
  bpf_prog_t* func;
};

struct oo_bpf_prog_load_arg {
  /* These fields are the same as those in the kernel's bpf(2) syscall: */
  uint32_t prog_type;
  uint32_t insn_cnt;
  aligned_uint64_t insns;
  aligned_uint64_t license;
  uint32_t log_level;
  uint32_t log_size;
  aligned_uint64_t log_buf;
  uint32_t kern_version; /* specific to kprobes, but retained for compat */
  uint32_t prog_flags;
  char prog_name[BPF_OBJ_NAME_LEN];
  uint32_t prog_ifindex;
  uint32_t expected_attach_type; /* not needed for xdp, for compat only */

  /* These fields are specific to Onload: */
  /* <none yet> */
};


struct oo_bpf_prog_info {
  /* These fields are a subset of the ones in the kernel's bpf_prog_info.
   * Hence any naming strangeness. */
  uint32_t type;
  uint32_t jited_prog_len;
  uint32_t xlated_prog_len;
  aligned_uint64_t jited_prog_insns;
  aligned_uint64_t xlated_prog_insns;
  uint32_t nr_map_ids;
  char name[BPF_OBJ_NAME_LEN];
};


enum oo_bpf_attach_point {
  OO_BPF_ATTACH_XDP_INGRESS,
  OO_BPF_ATTACH_MAX
};


#define OO_BPF_PROG_ATTACH_F_REPLACE  0x01

struct oo_bpf_prog_attach_arg {
  int32_t prog_fd;
  uint32_t flags;
  uint32_t attach_point;
  uint32_t ifindex;
  char stack[OO_BPF_STACK_NAME_LEN];
};


struct oo_bpf_prog_test_run_arg {
  uint32_t iterations;  /* in */
  uint32_t result;      /* out */
  aligned_uint64_t ticks;       /* out */
  uint32_t pkt_len;     /* in/out */
  uint32_t max_pkt_len; /* in */
  aligned_uint64_t pkt;     /* in (contents in/out) */
};


struct oo_bpf_prog_get_all_arg {
  uint32_t attach_cnt;
  aligned_uint64_t attaches; /* array of oo_bpf_prog_attach_args */
};


struct oo_bpf_map_create_arg {
  uint32_t map_type;
  uint32_t key_size;
  uint32_t value_size;
  uint32_t max_entries;
  uint32_t map_flags;
  uint32_t numa_node;
  char map_name[BPF_OBJ_NAME_LEN];
};


struct oo_bpf_map_info {
  uint32_t type;
  uint32_t id; /* unused by Onload */
  uint32_t key_size;
  uint32_t value_size;
  uint32_t max_entries;
  uint32_t map_flags;
};


struct oo_bpf_map_get_info_arg {
  uint32_t map_fd;
  aligned_uint64_t info;
};


struct oo_bpf_map_manip_arg {
  uint32_t map_fd;
  aligned_uint64_t key;
  union {
    aligned_uint64_t value;
    aligned_uint64_t next_key;
  };
  aligned_uint64_t flags;
};


#endif
