/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __BPFIMPL_KERNEL_CONFIG__
#define __BPFIMPL_KERNEL_CONFIG__

/* We want these eBPF config options enabled regardless of the kernel config */
#undef CONFIG_BPF_JIT
#define CONFIG_BPF_JIT 1

#undef CONFIG_HAVE_EBPF_JIT
#define CONFIG_HAVE_EBPF_JIT 1

#undef CONFIG_BPF_JIT_ALWAYS_ON
#define CONFIG_BPF_JIT_ALWAYS_ON 1

#undef CONFIG_BPF_SYSCALL
#define CONFIG_BPF_SYSCALL 1

/* We don't support the eBPF handling for perf events, so avoid having to
 * deal with compat for them.
 */
#undef CONFIG_PERF_EVENTS
#undef CONFIG_CGROUP_BPF
#undef CONFIG_CGROUPS
#undef CONFIG_CGROUP_PERF

/* CONFIG_NET is required for the kernel build as we need to match */
#ifdef __KERNEL__
# ifndef CONFIG_NET
#  error "Build is only supported if CONFIG_NET is set"
# endif
# if defined(CONFIG_X86) && !defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
#  define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS 1
# endif
#else
# define CONFIG_NET 1
# define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS 1
#endif

#endif /* __BPFIMPL_KERNEL_CONFIG__ */
