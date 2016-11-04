#!/bin/bash -eu
######################################################################

me=$(basename "$0")

err  () { echo >&2 "$*";    }
log  () { err "$me: $*";    }
vlog () { $verbose && err "$me: $*"; }
fail () { log "$*"; exit 1; }
try  () { "$@" || fail "'$*' failed"; }
vmsg () { $quiet || log "$@"; }

function usage()
{
    err
    err "usage:"
    err "  $me [options] <symbol1> <symbol2>"
    err
    err "description:"
    err "  Produce a list of kernel compatability macros to match the "
    err "  kernel_compat.c and kernel_compat.h files"
    err
    err "options:"
    err "  -k KPATH        -- Specify the path to the kernel build source tree"
    err "                     defaults to /lib/modules/VERSION/build"
    err "  -r VERSION      -- Specify the kernel version instead to test"
    err '                     defaults to `uname -r`'
    err "  -a ARCH         -- Set the architecture to ARCH"
    err "                     defaults to `uname -m`"
    err "  -m MAP          -- Specify a System map for the build kernel."
    err "                     By default will look in KPATH and /boot"
    err "  -q              -- Quieten the checks"
    err "  -v              -- Verbose output"
    err "  -s              -- Symbol list to use"
    err "  <symbol>        -- Symbol to evaluate."
    err "                     By default every symbol is evaluated"

}

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

EFRM_HAVE___VFS_READ_EXPORTED	export	__vfs_read	include/linux/fs.h

EFRM_HAVE_FOP_READV	memtype	struct_file_operations	readv	include/linux/fs.h ssize_t (*) (struct file *, const struct iovec *, unsigned long, loff_t *)
EFRM_HAVE_FOP_AIO_READ	memtype	struct_file_operations	aio_read	include/linux/fs.h ssize_t (*) (struct kiocb *, const struct iovec *, unsigned long, loff_t)
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

# TODO move onload-related stuff from net kernel_compat
" | egrep -v -e '^#' -e '^$' | sed 's/[ \t][ \t]*/:/g'
}

######################################################################
# Generic methods for standard symbol types

# Look for up to 3 numeric components separated by dots and stop when
# we find anything that doesn't match this.  Convert to a number like
# the LINUX_VERSION_CODE macro does.
function string_to_version_code
{
    local ver="$1"
    local code=0
    local place=65536
    local num

    while [ -n "$ver" ]; do
	# Look for numeric component; if none found then we're done;
	# otherwise add to the code
	num=${ver%%[^0-9]*}
	test -n "$num" || break
	code=$((code + $num * $place))

	# If this was the last component (place value = 1) then we're done;
	# otherwise update place value
	test $place -gt 1 || break
	place=$((place / 256))

	# Move past numeric component and following dot (if present)
	ver=${ver#$num}
	ver=${ver#.}
    done

    echo $code
}

# Test cases for string_to_version_code:
# test $(string_to_version_code 1.2.3) = $((1 * 65536 + 2 * 256 + 3))
# test $(string_to_version_code 12.34.56) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56foo) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56.78) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56.foo) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34.56-foo) = $((12 * 65536 + 34 * 256 + 56))
# test $(string_to_version_code 12.34) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34.0) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34foo) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34-56) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34.foo) = $((12 * 65536 + 34 * 256))
# test $(string_to_version_code 12.34-foo) = $((12 * 65536 + 34 * 256))

function do_kver()
{
    shift 2;
    local op="$1"
    local right_ver="$2"

    local left=$(string_to_version_code "$KVER")
    local right=$(string_to_version_code "$right_ver")

    local result=$((1 - ($left $op $right)))
    local msg="$KVER $op $right_ver == $left $op $right == "
    if [ $result = 0 ]; then
	msg="$msg true"
    else
	msg="$msg false"
    fi
    vmsg "$msg"
    return $result
}

function do_symbol()  { shift 2; test_symbol "$@"; }
function do_nsymbol() { shift 2; ! test_symbol "$@"; }
function do_symtype() { shift 2; defer_test_symtype pos "$@"; }
function do_nsymtype() { shift 2; defer_test_symtype neg "$@"; }
function do_member() { shift 2; defer_test_memtype pos "$@" void; }
function do_nmember() { shift 2; defer_test_memtype neg "$@" void; }
function do_memtype() { shift 2; defer_test_memtype pos "$@"; }
function do_nmemtype() { shift 2; defer_test_memtype neg "$@"; }
function do_export()
{
    local sym=$3
    shift 3

    # Only scan header files for the symbol
    test_symbol $sym $(echo "$@" | sed -r 's/ [^ ]+\.c/ /g') || return
    test_export $sym "$@"
}
function do_nexport() { ! do_export "$@"; }
function do_file()
{
    for file in "$@"; do
        if [ -f $KBUILD_SRC/$file ]; then
            return 0
        fi
    done
    return 1
}
function do_nfile()   { ! do_file "$@"; }

function do_custom()  { do_$1; }

######################################################################
# Implementation of kernel feature checking

# Special return value for deferred test
DEFERRED=42

function atexit_cleanup()
{
  rc=$?
  [ -n "$rmfiles" ] && rm -rf $rmfiles
  return $rc
}

function strip_comments()
{
    local file=$1

    cat $1 | sed -e '
/\/\*/!b
:a
/\*\//!{
N
ba
}
s:/\*.*\*/::'
}

function test_symbol()
{
    local symbol=$1
    shift
    local file
    local prefix
    local prefix_list

    for file in "$@"; do
        # For speed, lets just grep through the file. The symbol may
        # be of any of these forms:
        #     #define SYMBOL
        #     typedef void (SYMBOL)(void)
        #     extern void SYMBOL(void)
        #     void (*SYMBOL)(void)
        #     enum { SYMBOL, } void
        #
	# Since 3.7 headers can be in both $KBUILD_SRC/include
	#     or $KBUILD_SRC/include/uapi so check both
	# If the file contains "include/linux" then build set of
        # prefixes 

        prefix=$(dirname $file)
	file=$(basename $file)
        if [ "$prefix" == "include/linux" ]; then
            prefix_list="include/linux/ include/uapi/linux/"
	else
            prefix_list="$prefix/"
        fi

	for prefix in $prefix_list; do
            if [ $verbose = true ]; then
                echo >&2 "Looking for '$symbol' in '$KBUILD_SRC/$prefix$file'"
            fi
            [ -f "$KBUILD_SRC/$prefix$file" ] &&  \
                strip_comments $KBUILD_SRC/$prefix$file | \
                egrep -w "$symbol" >/dev/null && \
                return 0
        done
    done
    return 1
}

function defer_test_symtype()
{
    local sense=$1
    local symbol=$2
    local file=$3
    shift 3
    local type="$*"

    if [ ${file:0:8} != "include/" ]; then
	fail "defer_test_symtype() can work in include/ - request was '$file'"
    fi

    defer_test_compile $sense "
#include <linux/types.h>
#include <${file:8}>

#include \"_autocompat.h\"
#if defined(EFX_HAVE_KMEM_CACHE_S)
  #define kmem_cache kmem_cache_s
#endif

__typeof($type) *kernel_compat_dummy = &$symbol;
"
}

function defer_test_memtype()
{
    local sense=$1
    local aggtype="${2/_/ }"
    local memname=$3
    local file=$4
    shift 4
    local memtype="$*"

    if [ ${file:0:8} != "include/" ]; then
	fail "defer_test_symtype() can work in include/ - request was '$file'"
    fi

    defer_test_compile $sense "
#include <${file:8}>
$aggtype kernel_compat_dummy_1;
__typeof($memtype) *kernel_compat_dummy_2 = &kernel_compat_dummy_1.$memname;
"
}

function test_inline_symbol()
{
    local symbol=$1
    local file=$2
    local t=$(mktemp)
    rmfiles="$rmfiles $t"

    [ -f "$KBUILD_SRC/$file" ] || return

    # TODO: This isn't very satisfactory. Alternative options are:
    #   1. Come up with a clever sed version
    #   2. Do a test compile, and look for an undefined symbol (extern)

    # look for the inline..symbol. This is complicated since the inline
    # and the symbol may be on different lines.
    strip_comments $KBUILD_SRC/$file | \
	egrep -m 1 -B 1 '(^|[,\* \(])'"$symbol"'($|[,; \(\)])' > $t
    [ $? = 0 ] || return $?
        
    # there is either an inline on the final line, or an inline and
    # no semicolon on the previous line
    head -1 $t | egrep -q 'inline[^;]*$' && return
    tail -1 $t | egrep -q 'inline' && return

    return 1
}

function test_export()
{
    local symbol=$1
    shift
    local files="$@"
    local file match

    # Looks for the given export symbol $symbol, defined in $file
    # Since this symbol is exported, we can look for it in:
    #     1. $KPATH/Module.symvers
    #     2. If the full source is installed, look in there.
    #        May give a false positive if the export is conditional.
    #     3. The MAP file if present. May give a false positive
    #        because it lists all extern (not only exported) symbols.
    if [ -f $KPATH/Module.symvers ]; then
        if [ $verbose = true ]; then
            echo >&2 "Looking for export of $symbol in $KPATH/Module.symvers"
	fi
	[ -n "$(awk '/0x[0-9a-f]+[\t ]+'$symbol'[\t ]+/' $KPATH/Module.symvers)" ]
    else
	for file in $files; do
            if [ $verbose = true ]; then
		echo >&2 "Looking for export of $symbol in $KBUILD_SRC/$file"
            fi
            if [ -f $KBUILD_SRC/$file ]; then
		egrep -q 'EXPORT_(PER_CPU)?SYMBOL(_GPL)?\('"$symbol"'\)' $KBUILD_SRC/$file && return
            fi
	done
	if [ -n "$MAP" ]; then
            if [ $verbose = true ]; then
		echo >&2 "Looking for export of $symbol in $MAP"
            fi
	    egrep -q "[A-Z] $symbol\$" $MAP && return
	fi
	return 1
    fi
}

function test_compile()
{
    local source="$1"
    local rc
    local dir=$(mktemp -d)
    echo "$source" > $dir/test.c
    cat > $dir/Makefile <<EOF
$makefile_prefix
obj-m := test.o
EOF
    make -C $KPATH M=$dir >$dir/log 2>&1
    rc=$?

    if [ $verbose = true ]; then
	echo >&2 "tried to compile:"
	sed >&2 's/^/    /' $dir/test.c
	echo >&2 "compiler output:"
	sed >&2 's/^/    /' $dir/log
    fi

    rm -rf $dir
    return $rc
}

function defer_test_compile()
{
    local sense=$1
    local source="$2"
    echo "$source" > "$compile_dir/test_$key.c"
    echo "obj-m += test_$key.o" >> "$compile_dir/Makefile"
    eval deferred_$sense=\"\$deferred_$sense $key\"
    return $DEFERRED
}

function read_make_variables()
{
    local regexp=''
    local split='('
    local variable
    local variables="$@"
    local dir=$(mktemp -d)

    for variable in $variables; do
	echo "\$(warning $variable=\$($variable))" >> $dir/Makefile
	regexp=$regexp$split$variable
	split='|'
    done
    make -C $KPATH $EXTRA_MAKEFLAGS M=$dir 2>&1 >/dev/null | sed -r "s#$dir/Makefile:.*: ($regexp)=.*$)#\1#; t; d"
    rc=$?

    rm -rf $dir
    return $rc
}

function read_define()
{
    local variable="$1"
    local file="$2"
    cat $KPATH/$2 | sed -r 's/#define '"$variable"' (.*)/\1/; t; d'
}

######################################################################
# Implementation for more tricky types

function do_EFX_HAVE_KMEM_CACHE_S
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


quiet=false
verbose=false

KVER=
KPATH=
FILTER=
unset ARCH  # avoid exporting ARCH during initial checks
ARCH=
MAP=
EXTRA_MAKEFLAGS=
kompat_symbols=

# These variables from an outer build will interfere with our test builds
unset KBUILD_EXTMOD
unset KBUILD_SRC
unset M
unset TOPDIR

# Filter out make options except for job-server (parallel make)
set +u
old_MAKEFLAGS="$MAKEFLAGS"
set -u
MAKEFLAGS=
for word in $old_MAKEFLAGS; do
    case "$word" in
	'-j' | '--jobserver='*)
	    export MAKEFLAGS="$MAKEFLAGS $word"
	    ;;
	*)
	    ;;
    esac
done

# Clean-up temporary files when we exit.
rmfiles=
trap atexit_cleanup EXIT

while [ $# -gt 0 ]; do
    case "$1" in
	-r) KVER=$2; shift;;
	-k) KPATH=$2; shift;;
	-q) quiet=true;;
	-m) MAP=$2; shift;;
	-v) verbose=true;;
	-s) kompat_symbols="$2"; shift;;
	-*) usage; exit -1;;
	*)  [ -z $FILTER ] && FILTER=$1 || FILTER="$FILTER|$1";;
	*)  break;
    esac
    shift
done

# resolve KVER and KPATH
[ -z "$KVER" ] && [ -z "$KPATH" ] && KVER=`uname -r`
[ -z "$KPATH" ] && KPATH=/lib/modules/$KVER/build

# Need to set CC explicitly on the kernel make line
# Needs to override top-level kernel Makefile setting
set +u
if [ -n "$CC" ]; then
    EXTRA_MAKEFLAGS="CC=$CC"
fi
set -u

# Select the right warnings - complicated by working out which options work
makefile_prefix='
ifndef try-run
try-run = $(shell set -e;		\
	TMP="$(obj)/.$$$$.tmp";		\
	TMPO="$(obj)/.$$$$.o";		\
	if ($(1)) >/dev/null 2>&1;	\
	then echo "$(2)";		\
	else echo "$(3)";		\
	fi;				\
	rm -f "$$TMP" "$$TMPO")
endif
ifndef cc-disable-warning
cc-disable-warning = $(call try-run,\
	$(CC) $(KBUILD_CPPFLAGS) $(KBUILD_CFLAGS) -W$(strip $(1)) -c -xc /dev/null -o "$$TMP",-Wno-$(strip $(1)))
endif
EXTRA_CFLAGS = -Werror $(call cc-disable-warning, unused-but-set-variable)
'

# Ensure it looks like a build tree and we can build a module
[ -d "$KPATH" ] || fail "$KPATH is not a directory"
[ -f "$KPATH/Makefile" ] || fail "$KPATH/Makefile is not present"
test_compile "#include <linux/module.h>" || \
    fail "Kernel build tree is unable to build modules"

# strip the KVER out of UTS_RELEASE, and compare to the specified KVER
_KVER=
for F in include/generated/utsrelease.h include/linux/utsrelease.h include/linux/version.h; do
    [ -f $KPATH/$F ] && _KVER="$(eval echo $(read_define UTS_RELEASE $F))" && break
done
[ -n "$_KVER" ] || fail "Unable to identify kernel version from $KPATH"
if [ -n "$KVER" ]; then
    [ "$KVER" = "$_KVER" ] || fail "$KPATH kernel version $_KVER does not match $KVER"
fi
KVER=$_KVER
unset _KVER

vmsg "KVER       := $KVER"
vmsg "KPATH      := $KPATH"

# Read the following variables from the Makefile:
#     KBUILD_SRC:         Root of source tree (not the same as KPATH under SUSE)
#     ARCH:               Target architecture name
#     SRCARCH:            Target architecture directory name (2.6.24 onward)
#     CONFIG_X86_{32,64}: Work around ARCH = x86 madness
[ -n "$ARCH" ] && export ARCH
eval $(read_make_variables KBUILD_SRC ARCH SRCARCH CONFIG_X86_32 CONFIG_X86_64)

# Define:
#     KBUILD_SRC:         If not already set, same as KPATH
#     SRCARCH:            If not already set, same as ARCH
#     WORDSUFFIX:         Suffix added to some filenames by the i386/amd64 merge
[ -n "$KBUILD_SRC" ] || KBUILD_SRC=$KPATH
[ -n "$SRCARCH" ] || SRCARCH=$ARCH
if [ "$ARCH" = "i386" ] || [ "$CONFIG_X86_32" = "y" ]; then
    WORDSUFFIX=_32
elif [ "$ARCH" = "x86_64" ] || [ "$CONFIG_X86_64" = "y" ]; then
    WORDSUFFIX=_64
else
    WORDSUFFIX=
fi
[ -f "$KBUILD_SRC/arch/$SRCARCH/Makefile" ] || fail "$KBUILD_SRC doesn't directly build $SRCARCH"

vmsg "KBUILD_SRC := $KBUILD_SRC"
vmsg "SRCARCH    := $SRCARCH"
vmsg "WORDSUFFIX := $WORDSUFFIX"

# try and find the System map [used by test_export]
if [ -z "$MAP" ]; then
    if [ -f /boot/System.map-$KVER ]; then
	MAP=/boot/System.map-$KVER
    elif [ $KVER = "`uname -r`" ] && [ -f /proc/kallsyms ]; then
	MAP=/proc/kallsyms
    elif [ -f $KPATH/Module.symvers ]; then
	# can use this to find external symbols only
	true
    else
	vmsg "!!Unable to find a valid System map. Export symbol checks may not work"
    fi
fi

if [ "$kompat_symbols" == "" ]; then
    kompat_symbols="$(generate_kompat_symbols)"
fi

# filter the available symbols
if [ -n "$FILTER" ]; then
    kompat_symbols="$(echo "$kompat_symbols" | egrep "^($FILTER):")"
fi

compile_dir="$(mktemp -d)"
rmfiles="$rmfiles $compile_dir"
echo >"$compile_dir/Makefile" "$makefile_prefix"
echo >"$compile_dir/_autocompat.h"
deferred_pos=
deferred_neg=

# Note that for deferred tests this runs after the Makefile has run all tests
function do_one_symbol() {
    local key=$1
    shift
    # NB work is in the following if clause "do_${method}"
    if "$@"; then
	echo "#define $key yes"
	# So that future compile tests can consume this
	echo "#define $key yes" >> "${compile_dir}/_autocompat.h"
    elif [ $? -ne $DEFERRED ]; then
	echo "// #define $key"
    fi
}

# process each symbol
for symbol in $kompat_symbols; do
    # split symbol at colons; disable globbing (pathname expansion)
    set -o noglob
    IFS=:
    set -- $symbol
    unset IFS
    set +o noglob

    key="$1"
    method="$2"
    do_one_symbol $key do_${method} "$@"
done

# Run the deferred compile tests
make -C $KPATH -k $EXTRA_MAKEFLAGS M="$compile_dir" \
    >"$compile_dir/log" 2>&1 \
    || true
if [ $verbose = true ]; then
    echo >&2 "compiler output:"
    sed >&2 's/^/    /' "$compile_dir/log"
fi
for key in $deferred_pos; do
    # Use existence of object file as evidence of compile without warning/errors
    do_one_symbol $key test -f "$compile_dir/test_$key.o"
done
for key in $deferred_neg; do
    do_one_symbol $key test ! -f "$compile_dir/test_$key.o"
done
