ifeq ($(GNU),1)
SUBDIRS		:= ciul \
                   nic \
                   ip \
                   citools \
                   driver \
                   ef_vi \
                   onload \
                   cplane \
		   rtt \
                   syscalls

OTHER_SUBDIRS	:= tweaks

ifeq ($(ONLOAD_ONLY),1)
SUBDIRS		:= ef_vi \
                   onload \
                   rtt
endif

ifneq ($(NO_ZF),1)
ifeq (${PLATFORM},gnu_x86_64)
ifeq ($(shell $(TOP)/$(CURRENT)/zf_apps/zf_supported.sh),1)
SUBDIRS         += zf_apps
OTHER_SUBDIRS   += zf_internal
endif
ifndef PREBUILD_ZF
ifneq ($(ONLOAD_ONLY),1)
SUBDIRS         += zf_unit packetdrill
endif
endif
endif
endif
endif

DRIVER_SUBDIRS	:= driver

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
SUBDIRS       	:= solaris nic ip
DRIVER_SUBDIRS	:=
OTHER_SUBDIRS	:=
endif

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

