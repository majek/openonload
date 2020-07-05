# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
ifeq ($(GNU),1)
SUBDIRS		:= ciul \
                   ip \
                   citools \
                   driver \
                   ef_vi \
                   onload \
                   runbench_scripts \
		   rtt \
                   syscalls \
                   tap \
		   trade_sim \

OTHER_SUBDIRS	:=

ifeq ($(ONLOAD_ONLY),1)
SUBDIRS		:= ef_vi \
                   onload \
                   rtt \
                   trade_sim
endif

ifneq ($(NO_ZF),1)
ifeq (${PLATFORM},gnu_x86_64)
ifeq ($(shell $(TOP)/$(CURRENT)/zf_apps/zf_supported.sh),1)
SUBDIRS         += zf_apps zf_internal
endif
ifndef PREBUILD_ZF
ifneq ($(ONLOAD_ONLY),1)
OTHER_SUBDIRS         += packetdrill
ifdef ZF_DEVEL
SUBDIRS         += zf_unit
endif
endif
endif
endif
endif
endif

DRIVER_SUBDIRS	:=

ifeq ($(FREEBSD),1)
SUBDIRS         := ip
DRIVER_SUBDIRS	:=
OTHER_SUBDIRS	:=
endif

ifeq ($(MACOSX),1)
SUBDIRS         := ip
DRIVER_SUBDIRS	:=
OTHER_SUBDIRS	:=
endif

ifeq ($(SOLARIS),1)
SUBDIRS       	:= ip
DRIVER_SUBDIRS	:=
OTHER_SUBDIRS	:=
endif

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

