ifeq ($(GNU),1)
SUBDIRS		:= ciul \
                   nic \
                   ip \
                   citools \
                   driver \
                   ef_vi

OTHER_SUBDIRS	:= tweaks \
                   syscalls

ifdef BROKEN
OTHER_SUBDIRS	+= cplane
endif

ifeq ($(ONLOAD_ONLY),1)
SUBDIRS		:= ef_vi
endif
endif

DRIVER_SUBDIRS	:= driver

ifeq ($(WINDOWS),1)
SUBDIRS       	:= nic ip driver
DRIVER_SUBDIRS	:=
OTHER_SUBDIRS	:= tweaks
endif

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

