# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

SUBDIRS		:= citools ciapp

ifeq ($(LINUX),1)
DRIVER_SUBDIRS	:= citools ciul cplane bpf transport
OTHER_SUBDIRS	:= spektor
SUBDIRS		+= sfcaffinity onload_ext
endif

ifeq ($(GNU),1)
# N.B.: The order matters here.
SUBDIRS		+= ciul kcompat
SUBDIRS		+= cplane bpf transport tools
ifneq ($(ONLOAD_ONLY),1)
SUBDIRS         += activation
ifeq (${PLATFORM},gnu_x86_64)
ifndef PREBUILD_ZF
ifneq ($(NO_ZF),1)
SUBDIRS         += zf
endif
endif
endif
endif
endif


all:
	+@(export MMAKE_NO_CSTYLE=1; $(MakeSubdirs))

clean:
	@$(MakeClean)

