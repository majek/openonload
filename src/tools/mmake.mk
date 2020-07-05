# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

ifeq ($(LINUX),1)
SUBDIRS		:= ip sfcaffinity solar_clusterd dlopen_no_deepbind \
		   onload_remote_monitor
ifneq ($(ONLOAD_ONLY),1)
SUBDIRS		+= cplane unifdef misc onload_mibdump
endif

endif

ifndef PREBUILD_ZF
ifeq (${PLATFORM},gnu_x86_64)
ifneq ($(ONLOAD_ONLY),1)
ifneq ($(NO_ZF),1)
SUBDIRS         += zf
endif
endif
endif
endif

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)
