#!/bin/bash -eu
# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
######################################################################

me=$(basename "$0")

######################################################################
# Symbol definition map

function generate_kompat_symbols() {
    echo "
EFRM_HAVE_PROC_CREATE		symtype	proc_create	include/linux/proc_fs.h struct proc_dir_entry *(const char *name, mode_t mode, struct proc_dir_entry *parent, const struct file_operations *proc_fops)
EFRM_HAVE_PROC_CREATE_DATA	symtype	proc_create_data	include/linux/proc_fs.h struct proc_dir_entry *(const char *name, mode_t mode, struct proc_dir_entry *parent, const struct file_operations *proc_fops, void *data)
EFRM_HAVE_PROC_CREATE_DATA_UMODE	symtype	proc_create_data	include/linux/proc_fs.h struct proc_dir_entry *(const char *name, umode_t mode, struct proc_dir_entry *parent, const struct file_operations *proc_fops, void *data)
EFRM_HAVE_PDE_DATA		symtype	PDE_DATA	include/linux/proc_fs.h void *(const struct inode *inode)

EFRM_HAVE_NSPROXY		file	include/linux/nsproxy.h
EFRM_OLD_DEV_BY_IDX		symtype	__dev_get_by_index	include/linux/netdevice.h struct net_device *(int)

EFRM_HAVE_NETDEV_NOTIFIER_INFO	symbol	netdev_notifier_info_to_dev	include/linux/netdevice.h

EFRM_HAVE_PGPROT_WRITECOMBINE	symtype	pgprot_writecombine 	include/linux/mm.h pgprot_t(pgprot_t)
EFRM_HAVE_IOREMAP_WC		symbol	ioremap_wc		arch/$SRCARCH/include/asm/io.h include/asm-$SRCARCH/io.h include/asm-generic/io.h

EFRM_HAVE_IOMMU_MAP_OLD	symtype	iommu_map	include/linux/iommu.h int(struct iommu_domain *, unsigned long, phys_addr_t, int, int)
EFRM_HAVE_IOMMU_MAP	symtype	iommu_map	include/linux/iommu.h int(struct iommu_domain *, unsigned long, phys_addr_t, size_t, int)
EFRM_HAVE_IOMMU_GROUP	symbol	iommu_group_add_device	include/linux/iommu.h

EFRM_HAVE_NETFILTER_INDIRECT_SKB		memtype	struct_nf_hook_ops	hook	include/linux/netfilter.h	unsigned int(*)(unsigned int, struct sk_buff **, const struct net_device *, const struct net_device *, int (*)(struct sk_buff *))
EFRM_HAVE_NETFILTER_HOOK_OPS		memtype	struct_nf_hook_ops	hook	include/linux/netfilter.h	unsigned int(*)(const struct nf_hook_ops *, struct sk_buff *, const struct net_device *, const struct net_device *, int (*)(struct sk_buff *))
EFRM_HAVE_NETFILTER_HOOK_STATE		memtype	struct_nf_hook_state	hook	include/linux/netfilter.h int
EFRM_HAVE_NETFILTER_OPS_HAVE_OWNER	memtype	struct_nf_hook_ops	owner	include/linux/netfilter.h struct module

EFRM_HAVE_KSTRTOUL	symbol	kstrtoul	include/linux/kernel.h
EFRM_HAVE_KSTRTOL	symbol	kstrtol 	include/linux/kernel.h
EFRM_HAVE_IN4_PTON	symbol	in4_pton	include/linux/inet.h
EFRM_HAVE_IN6_PTON	symbol	in6_pton	include/linux/inet.h
EFRM_HAVE_STRCASECMP	symbol	strcasecmp	include/linux/string.h

EFRM_HAVE_REINIT_COMPLETION	symbol	reinit_completion	include/linux/completion.h

EFRM_HAVE_GET_UNUSED_FD_FLAGS	export	get_unused_fd_flags	include/linux/file.h	fs/file.c

EFRM_HAVE_WQ_SYSFS	symbol	WQ_SYSFS	include/linux/workqueue.h

EFRM_HAVE_POLL_REQUESTED_EVENTS	symbol	poll_requested_events	include/linux/poll.h
EFRM_POLL_TABLE_HAS_OLD_KEY	memtype	struct_poll_table_struct	key	include/linux/poll.h	unsigned long

ERFM_HAVE_NEW_KALLSYMS	symtype	kallsyms_on_each_symbol	include/linux/kallsyms.h int(int (*)(void *, const char *, struct module *, unsigned long), void *)

EFRM_HAVE_TASK_NSPROXY	symbol	task_nsproxy	include/linux/nsproxy.h

# RHEL5 kernel has iommu_domain_has_cap declared in linux/iommu.h,
# but does not have it even defined, let alone exported.
EFRM_HAVE_IOMMU_DOMAIN_HAS_CAP	export	iommu_domain_has_cap	include/linux/iommu.h
EFRM_HAVE_IOMMU_CAPABLE	symbol	iommu_capable	include/linux/iommu.h

# 2.6.18 has f_dentry as a field,
# 2.6.32 - as a define,
# 3.19 has nothing
EFRM_HAVE_F_DENTRY	memtype	struct_file	f_dentry	include/linux/fs.h	struct dentry *

EFRM_HAVE_MSG_ITER	memtype	struct_msghdr	msg_iter	include/linux/socket.h	struct iov_iter

EFRM_HAVE_TEAMING		file	include/uapi/linux/if_team.h

# we need close_on_exec() function, but there is a catch: close_on_exec is
# also a field in struct fdtable.  It is easier to check fd_is_open().
EFRM_HAVE_CLOEXEC_TEST	symbol	fd_is_open	include/linux/fdtable.h

EFRM_SOCK_SENDMSG_NEEDS_LEN	symtype	sock_sendmsg	include/linux/net.h int(struct socket *, struct msghdr *, size_t)
EFRM_SOCK_RECVMSG_NEEDS_BYTES	symtype sock_recvmsg	include/linux/net.h int(struct socket *, struct msghdr *, size_t, int)

EFRM_HAVE_FOP_READ_ITER	memtype	struct_file_operations	read_iter	include/linux/fs.h ssize_t (*) (struct kiocb *, struct iov_iter *)

EFRM_SOCK_CREATE_KERN_HAS_NET	symtype	sock_create_kern	include/linux/net.h int(struct net *, int, int, int, struct socket **)

EFRM_HAVE_SK_SLEEP_FUNC	symtype	sk_sleep	include/net/sock.h wait_queue_head_t *(struct sock *)

# Before 4.8, set_restore_sigmask() is defined by some architectures only, and
# there's a corresponding HAVE_SET_RESTORE_SIGMASK symbol.  On 4.8, the
# implementation is generic and HAVE_SET_RESTORE_SIGMASK has gone.  This compat
# will not find the pre-4.8 arch-specific and fallback implementations of
# set_restore_sigmask() as they were in different places, so it's necessary
# when using this to check for HAVE_SET_RESTORE_SIGMASK as well as for
# EFRM_HAVE_SET_RESTORE_SIGMASK.
EFRM_HAVE_SET_RESTORE_SIGMASK	symbol	set_restore_sigmask	include/linux/sched.h
EFRM_HAVE_SET_RESTORE_SIGMASK1	symbol	set_restore_sigmask	include/linux/sched/signal.h

EFRM_ALLOC_FILE_TAKES_STRUCT_PATH	symtype	alloc_file	include/linux/file.h struct file *(struct path *, fmode_t, const struct file_operations *)
EFRM_ALLOC_FILE_TAKES_CONST_STRUCT_PATH	symtype	alloc_file	include/linux/file.h struct file *(const struct path *, fmode_t, const struct file_operations *)
EFRM_FSTYPE_HAS_INIT_PSEUDO		symbol	init_pseudo	include/linux/pseudo_fs.h
EFRM_FSTYPE_HAS_MOUNT_PSEUDO		symbol	mount_pseudo	include/linux/fs.h
EFRM_NEED_VFSMOUNT_PARAM_IN_GET_SB	memtype	struct_file_system_type	get_sb	include/linux/fs.h	int (*)(struct file_system_type *, int, const char *, void *, struct vfsmount *)
EFRM_HAVE_KERN_UMOUNT			symbol	kern_unmount		include/linux/fs.h
EFRM_HAVE_ALLOC_FILE_PSEUDO		symbol	alloc_file_pseudo	include/linux/file.h

# Note this is the only place where the first test is needed to perform the subsequent kcompat tests
EFRM_HAVE_KMEM_CACHE_S			custom
EFRM_HAVE_KMEM_CACHE_DTOR		symtype	kmem_cache_create	include/linux/slab.h struct kmem_cache *(const char *, size_t, size_t, unsigned long, void (*ctor)(void*, struct kmem_cache *, unsigned long), void (*dtor)(void*, struct kmem_cache *, unsigned long))
EFRM_HAVE_KMEM_CACHE_FLAGS		symtype	kmem_cache_create	include/linux/slab.h struct kmem_cache *(const char *, size_t, size_t, unsigned long, void (*ctor)(void*, struct kmem_cache *, unsigned long))
EFRM_HAVE_KMEM_CACHE_CACHEP		symtype	kmem_cache_create	include/linux/slab.h struct kmem_cache *(const char *, size_t, size_t, unsigned long, void (*ctor)(struct kmem_cache *, void*))
EFRM_NET_HAS_PROC_INUM			member	struct_net proc_inum	include/net/net_namespace.h
EFRM_NET_HAS_USER_NS			member	struct_net user_ns	include/net/net_namespace.h

EFRM_HAVE_PRANDOM_U32			symbol  prandom_u32             include/linux/random.h

EFRM_HAVE_OLD_FAULT			memtype struct_vm_operations_struct	fault	include/linux/mm.h	int (*)(struct vm_area_struct *vma, struct vm_fault *vmf)
EFRM_HAVE_NEW_FAULT			memtype struct_vm_operations_struct	fault	include/linux/mm.h	vm_fault_t (*)(struct vm_fault *vmf)

EFRM_HAVE_SCHED_TASK_H			file	include/linux/sched/task.h
EFRM_HAVE_CRED_H			file	include/linux/cred.h

EFRM_OLD_NEIGH_UPDATE	symtype	neigh_update	include/net/neighbour.h int(struct neighbour *neigh, const u8 *lladdr, u8 new, u32 flags)

EFRM_HAVE_WAIT_QUEUE_ENTRY	memtype	struct_wait_queue_entry	flags	include/linux/wait.h	unsigned int
EFRM_HAVE_NF_NET_HOOK	symbol	nf_register_net_hook	include/linux/netfilter.h

EFRM_GUP_RCINT_TASK_SEPARATEFLAGS symtype get_user_pages include/linux/mm.h int(struct task_struct *, struct mm_struct *, unsigned long, int, int, int, struct page **, struct vm_area_struct **)
EFRM_GUP_RCLONG_TASK_SEPARATEFLAGS symtype get_user_pages include/linux/mm.h long(struct task_struct *, struct mm_struct *, unsigned long, unsigned long, int, int, struct page **, struct vm_area_struct **)
EFRM_GUP_RCLONG_TASK_COMBINEDFLAGS symtype get_user_pages include/linux/mm.h long(struct task_struct *, struct mm_struct *, unsigned long, unsigned long, unsigned int, struct page **, struct vm_area_struct **)
EFRM_GUP_RCLONG_NOTASK_COMBINEDFLAGS symtype get_user_pages include/linux/mm.h long(unsigned long, unsigned long, unsigned int, struct page **, struct vm_area_struct **)

EFRM_HAVE_USERMODEHELPER_SETUP		symbol	call_usermodehelper_setup	include/linux/kmod.h
EFRM_HAVE_USERMODEHELPER_SETUP_INFO	symtype	call_usermodehelper_setup	include/linux/kmod.h	struct subprocess_info*(char *path, char **argv, char **envp, gfp_t gfp_mask, int (*init)(struct subprocess_info *info, struct cred *new), void (*cleanup)(struct subprocess_info *), void *data)

EFRM_RTMSG_IFINFO_EXPORTED		export	rtmsg_ifinfo	include/linux/rtnetlink.h	net/core/rtnetlink.c
EFRM_RTMSG_IFINFO_NEEDS_GFP_FLAGS	symtype	rtmsg_ifinfo	include/linux/rtnetlink.h	void(int type, struct net_device *dev, unsigned int change, gfp_t flags)

EFRM_DEV_GET_BY_NAME_TAKES_NS	symtype	dev_get_by_name	include/linux/netdevice.h	struct net_device*(struct net*, const char* name)

EFRM_HAVE_NS_SYSCTL_TCP_MEM		nsymbol sysctl_tcp_wmem include/net/tcp.h

EFRM_HAVE_CONST_KERNEL_PARAM            symtype param_get_int include/linux/moduleparam.h int(char *, const struct kernel_param *)
EFRM_HAVE_KERNEL_PARAM_OPS		symbol kernel_param_ops	include/linux/moduleparam.h

EFRM_HAVE_TIMER_SETUP                   symbol timer_setup include/linux/timer.h
EFRM_HAVE_READ_SEQCOUNT_LATCH           symbol raw_read_seqcount_latch include/linux/seqlock.h
EFRM_HAVE_WRITE_SEQCOUNT_LATCH          symbol raw_write_seqcount_latch include/linux/seqlock.h
EFRM_HAVE_RBTREE                        symbol rb_link_node_rcu include/linux/rbtree.h
EFRM_HAVE_SKB_METADATA                  symbol skb_metadata_len include/linux/skbuff.h
EFRM_HAVE_BIN2HEX                       symbol bin2hex include/linux/kernel.h
EFRM_HAVE_ALLSYMS_SHOW_VALUE            symbol kallsyms_show_value include/linux/kallsyms.h
EFRM_HAVE_PRANDOM_INIT_ONCE             symbol prandom_init_once include/linux/random.h
EFRM_HAVE_PRANDOM_U32_STATE             symbol prandom_u32_state include/linux/random.h
EFRM_PRANDOM_SEED_FULL_EXPORT           export prandom_seed_full_state include/linux/random.h lib/random32.c
EFRM_HAVE_ARRAY_SIZE                    symbol array_size include/linux/overflow.h
EFRM_HAVE_WRITE_ONCE                    symbol WRITE_ONCE include/linux/compiler.h
EFRM_HAVE_INIT_LIST_HEAD_RCU            symbol INIT_LIST_HEAD_RCU include/linux/rculist.h
EFRM_HAVE_S_MIN_MAX                     symbol S32_MIN include/linux/kernel.h include/linux/limits.h

EFRM_DO_COREDUMP_BINFMTS_SIGNR          symtype	do_coredump	include/linux/binfmts.h	void(long, int, struct pt_regs*)
EFRM_DO_COREDUMP_COREDUMP_SIGNR         symtype	do_coredump	include/linux/coredump.h	void(long, int, struct pt_regs*)
EFRM_RTNL_LINK_OPS_HAS_GET_LINK_NET	member	struct_rtnl_link_ops	get_link_net	include/net/rtnetlink.h

EFRM_ACCESS_OK_HAS_2_ARGS    custom

EFRM_HAVE_DEVICE_DEVNODE_UMODE	memtype	struct_class devnode	include/linux/device.h char* (*)(struct device*, umode_t*)
EFRM_MAP_VM_AREA_TAKES_PAGESTARSTAR	symtype map_vm_area	include/linux/vmalloc.h	int(struct vm_struct*, pgprot_t, struct page**)

EFRM_IP6_ROUTE_INPUT_LOOKUP_EXPORTED	export	ip6_route_input_lookup	include/net/ip6_route.h	net/ipv6/route.c

EFRM_HAVE_DEV_GET_IF_LINK		symbol	dev_get_iflink	include/linux/netdevice.h

EFRM_IP6_ROUTE_INPUT_LOOKUP_TAKES_SKB	symtype ip6_route_input_lookup	include/net/ip6_route.h	struct dst_entry* (struct net*, struct net_device*, struct flowi6*, const struct sk_buff*, int)

EFRM_RTABLE_HAS_RT_GW4		memtype struct_rtable rt_gw4 include/net/route.h __be32
EFRM_HAVE_FILE_INODE			symbol file_inode include/linux/fs.h

EFRM_HAVE_UNMAP_KERNEL_RANGE	export	unmap_kernel_range	include/linux/vmalloc.h	mm/vmalloc.c


# TODO move onload-related stuff from net kernel_compat
" | egrep -v -e '^#' -e '^$' | sed 's/[ \t][ \t]*/:/g'
}

######################################################################
# Implementation for more tricky types

function do_EFRM_HAVE_KMEM_CACHE_S
{
    # This uses test_compile such that the subsquent defer_test_compile
    # based tests can consume from _autocompat.h
    test_compile "
#include <linux/slab.h>

__typeof(struct kmem_cache_s *(const char *, size_t, size_t, unsigned long, \
void (*ctor)(void*, struct kmem_cache_s *, unsigned long), \
void (*dtor)(void*, kmem_cache_t *, unsigned long))) *kernel_compat_dummy = \
&kmem_cache_create;
"
}

function do_EFRM_ACCESS_OK_HAS_2_ARGS
{
    test_compile "
#include <linux/uaccess.h>

int func(unsigned long addr, unsigned long size)
{
    return access_ok(addr, size);
}
"
}

source $(dirname "$0")/../linux_net/kernel_compat_funcs.sh
