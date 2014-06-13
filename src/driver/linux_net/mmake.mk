##############################################################################
#
# Support for building the net driver as part of the L5 build system. See 
# the Makefile for building it standalone.
#

CONFIG_FILES := config.h autocompat.h
MMAKE_GEN_SRCS := %.mod.c $(CONFIG_FILES)


ifdef DRIVER

export CONFIG_SFC := m
export CONFIG_SFC_DEBUGFS := y
export CONFIG_SFC_HWMON := y
export CONFIG_SFC_MCDI_MON := y
export CONFIG_SFC_SFE4001 := y
export CONFIG_SFC_I2C := y
export CONFIG_SFC_MTD := y
export CONFIG_SFC_SRIOV := y
export CONFIG_SFC_PTP := y
export CONFIG_SFC_AOE := y
export CONFIG_SFC_PPS := y

ifdef GCOV
IMPORT        := ../linux/gcov.c ../linux/gcov.h
endif

TARGETS := sfc.o
ifdef GCOV
TARGETS += sfc_gcov.o
endif

ifdef NOWERROR
EXTRA_MAKEFLAGS += NOWERROR=1
endif
ifdef MMAKE_LIBERAL
EXTRA_MAKEFLAGS += NOWERROR=1
endif

ifdef EFX_NOT_EXPORTED
EXTRA_MAKEFLAGS += EFX_NOT_EXPORTED=1
endif

KVERPARTS = $(subst -, ,$(subst ., ,$(KVER)))
ifeq ($(word 1,$(KVERPARTS)),2)
ifneq ($(word 2,$(KVERPARTS)),6)
$(error Kernel version $(KVER) is not supported\; minimum version is 2.6.9)
endif
ifneq ($(filter 0 1 2 3 4 5 6 7 8,$(word 3,$(KVERPARTS))),)
$(error Kernel version $(KVER) is not supported\; minimum version is 2.6.9)
endif
ifneq ($(filter 9 10 11 12 13 14 15,$(word 3,$(KVERPARTS))),)
$(warning Kernel <=2.6.15 does not support PTP)
override CONFIG_SFC_PTP :=
override CONFIG_SFC_PPS :=
endif
endif

SFC_MODULES := $(subst .o,.ko, $(TARGETS))

ifneq ($(CC),)
EXTRA_MAKEFLAGS += CC=$(CC)
endif

ifdef BUILD_INKERNEL_TESTS
DRIVER_SUBDIRS := unittest_filters
endif

ifneq ($(findstring $(shell uname -p),x86_64 i686),)
DRIVER_SUBDIRS += unittest
endif

all:	kbuild Module.symvers
	+@$(MakeSubdirs)

unexport NDEBUG

kbuild:
	@if ! [ -h $(CURDIR)/Kbuild ]; then				\
		echo "  UPD     Kbuild";				\
		ln -sf $(SRCPATH)/driver/linux_net/Makefile $(CURDIR)/Kbuild; \
	fi
	@if ! [ -h $(CURDIR)/mtd ]; then				\
		echo "  UPD     mtd";					\
		ln -sf $(SRCPATH)/driver/linux_net/mtd $(CURDIR)/mtd;	\
	fi
	@if ! [ -h $(CURDIR)/trace ]; then				\
		echo "  UPD     trace";					\
		ln -sf $(SRCPATH)/driver/linux_net/trace $(CURDIR)/trace; \
	fi
	$(MMAKE_KBUILD_PRE_COMMAND)
	$(MAKE) $(EXTRA_MAKEFLAGS) $(MMAKE_KBUILD_ARGS) M=$(CURDIR) NDEBUG=$(NDEBUG) MMAKE_IN_KBUILD=1
	$(MMAKE_KBUILD_POST_COMMAND)
	cp -f $(SFC_MODULES) $(DESTPATH)/driver/linux

Module.symvers: kbuild
	@if ! test -f Module.symvers; then \
		if test -f Modules.symvers; then \
			cp Modules.symvers Module.symvers; \
		else \
			touch Module.symvers; \
		fi \
	fi

clean:
	@$(MakeClean)
	rm -rf *.ko Module.symvers Modules.symvers .tmp_versions .*.cmd $(CONFIG_FILES)

else # DRIVER

# This is the util directory being built

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

ifdef BUILD_INKERNEL_TESTS
SUBDIRS := unittest_filters
endif

ifeq ($(LINUX),1)
SUBDIRS += util
endif

endif # DRIVER

.PHONY : $(DRIVER_SUBDIRS)
