# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
ifndef KPATH
$(shell echo >&2 "KPATH is not set.")
$(error KPATH is not set.)
endif

LINUX		   := 1

LINUX_VERSION_3	   := $(shell cat $(KPATH)/include/{linux/utsrelease.h,generated/utsrelease.h,linux/version.h} 2>/dev/null | sed 's/^\#define UTS_RELEASE \"\([0-9]\+\.[0-9]\+\.[0-9]\+\).*/\1/; t; d')

DRIVER		   := 1
MMAKE_USE_KBUILD   := 1
MMAKE_NO_RULES	   := 1

# Itanium on linux2.6 is very strict that for a given library/module,
# all objects must be compiled with the same flags. For some reason
# the linux kbuild environment doesn't satisfy this condition
include $(KPATH)/.config
ifdef CONFIG_IA64
CFLAGS_KERNEL :=
endif

ifdef CONFIG_ARM64
EXTRA_CFLAGS += -mcmodel=large
endif

# To build without -g set CONFIG_DEBUG_INFO to empty string
# (-g does make kernel modules quite big, but only on disk).
ifdef NO_DEBUG_INFO
MMAKE_KBUILD_ARGS_DBG := CONFIG_DEBUG_INFO=
endif

# Setting KBUILD_VERBOSE=1 is quite useful here
MMAKE_KBUILD_ARGS_CONST := -C $(KPATH) NDEBUG=$(NDEBUG) GCOV=$(GCOV) CC=$(CC)
MMAKE_KBUILD_ARGS = $(MMAKE_KBUILD_ARGS_CONST) $(MMAKE_KBUILD_ARGS_DBG)

# From Linux 2.6.17 onward, modpost reads and writes symbols for
# out-of-tree modules in a Module.symvers file in the module build
# directory.  We then copy this between directories to ensure that our
# modules that import from each other have version information.  For
# earlier kernel versions we have to bodge it.
# Various versions of modpost will crash if we don't:
# - set the environment variable MODVERDIR
# - include a slash in object file paths
# - limit output lines (which include object file paths) to 128 characters
MMAKE_KBUILD_ARGS += symverfile=$(CURDIR)/Module.symvers
MMAKE_KBUILD_PRE_COMMAND := \
	[ -f Module.symvers ] || cp -f $(KPATH)/Module.symvers .
MMAKE_KBUILD_POST_COMMAND = \
	MODVERDIR=.tmp_versions $(KPATH)/scripts/mod/modpost \
		$(if $(CONFIG_MODVERSIONS),-m) \
		$(if $(CONFIG_MODULE_SRCVERSION_ALL),-a) \
		-i Module.symvers -o Module.symvers $(addprefix ./,$(TARGETS))

