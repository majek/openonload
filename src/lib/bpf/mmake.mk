# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
SUBDIRS		:= bpfimpl

ifeq ($(PLATFORM),gnu_x86_64)
SUBDIRS		+= bpfintf
endif

DRIVER_SUBDIRS	:= bpfimpl

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

