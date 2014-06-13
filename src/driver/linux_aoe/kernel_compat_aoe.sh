#!/bin/bash -eu

KOMPAT_SCRIPT="$(dirname "$0")/../linux_net/kernel_compat.sh"

function aoe_generate_kompat_symbols() {
    echo "
AOE_HAVE_PARAM_BOOL_INT			kver    <	2.6.31
AOE_NEED_ROOT_DEVICE_REGISTER		nsymbol root_device_register	include/linux/device.h
AOE_NEED_KOBJECT_INIT_AND_ADD		nsymbol kobject_init_and_add	include/linux/kobject.h
AOE_NEED_KOBJECT_SET_NAME_VARGS		nsymbol kobject_set_name_vargs	include/linux/kobject.h
AOE_HAVE_OLD_STRUCT_MODULE_MKOBJ_PTR	memtype struct_module mkobj include/linux/module.h struct module_kobject*
AOE_NEED_TIMESPEC_ADD			nsymbol timespec_add		include/linux/time.h
AOE_NEED_TIMESPEC_ADD_NS		nsymbol	timespec_add_ns		include/linux/time.h
AOE_NEED_TIMESPEC_SUB			nsymbol	timespec_sub		include/linux/time.h
AOE_NEED_TIMESPEC_COMPARE		nsymbol	timespec_compare	include/linux/time.h
AOE_NEED_NS_TO_TIMESPEC			nexport ns_to_timespec		include/linux/time.h	kernel/time.c
AOE_HAVE_DIV_S64_REM			symbol	div_s64_rem		include/linux/math64.h
AOE_NEED_IS_ERR_OR_NULL			nsymbol IS_ERR_OR_NULL		include/linux/err.h
" | egrep -v -e '^#' -e '^$' | sed 's/[ \t][ \t]*/:/g'
}

exec "$KOMPAT_SCRIPT" "$@" -s "$(aoe_generate_kompat_symbols)"
