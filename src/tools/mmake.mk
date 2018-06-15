ifeq ($(LINUX),1)
SUBDIRS		:= ip sfcaffinity solar_clusterd dlopen_no_deepbind
OTHER_SUBDIRS	:= firmware
ifneq ($(ONLOAD_ONLY),1)
SUBDIRS		+= cplane ftl unifdef misc onload_mibdump
endif

ifeq ($(BUILDORM),1)
SUBDIRS		+= jansson-2.7 onload_remote_monitor
else
$(warning WARNING: onload_remote_monitor will not be available as dependencies are not met)
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
