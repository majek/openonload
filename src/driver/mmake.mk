SUBDIRS		:= ul

# For linux_net/util
ifeq ($(LINUX),1)
SUBDIRS         += linux_net
endif

MMAKE_NO_DEPS	:= 1

ifeq ($(LINUX),1)

# DRIVER_SUBDIRS must be ordered according to inter-driver dependencies
DRIVER_SUBDIRS	:= linux_net linux_affinity linux_resource \
		linux_char linux_onload linux

ifneq ($(wildcard $(linux_aoe) ),"")
DRIVER_SUBDIRS += linux_aoe
endif

ifeq ($(BUILD_AFONLOAD),1)
DRIVER_SUBDIRS  += openonload
endif
#DRIVER_SUBDIRS	+=  linux_iscsi

ifeq ($(BUILD_XEN),1)
DRIVER_SUBDIRS += linux_xen
endif

endif # ifeq ($(LINUX),1)

ifeq ($(WINDOWS),1)
DRIVER_SUBDIRS	:= win
endif

ifeq ($(GLD),1)
SUBDIRS		:= gld
endif

ifeq ($(DARWIN),1)
DRIVER_SUBDIRS	:= macosx
endif

ifeq ($(DOS), 1)
SUBDIRS = dos
endif

all: passthruparams := "CI_FROM_DRIVER=1"
all:
	+@(target=all ; $(MakeSubdirs))

clean:
	@$(MakeClean)

