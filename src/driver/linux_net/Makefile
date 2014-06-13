ifndef EFX_UPSTREAM

# The EFX_UPSTREAM variable is never defined.  Sections of the Makefile
# that are only needed for an out-of-tree build are guarded by
# "ifndef EFX_UPSTREAM" and removed using sed when it is exported to a
# kernel tree.

# The KERNELRELEASE variable is defined by kbuild.  Some parts of the
# Makefile should only be included when this is the top-level Makefile
# and not when it is included by kbuild; these are guarded by
# "ifndef KERNELRELEASE".

# Configuration
ifndef KERNELRELEASE
export CONFIG_SFC := m
export CONFIG_SFC_DEBUGFS := y
export CONFIG_SFC_HWMON := y
export CONFIG_SFC_MCDI_MON := y
export CONFIG_SFC_SFE4001 := y
export CONFIG_SFC_I2C := y
export CONFIG_SFC_MTD := y
export CONFIG_SFC_TUNE := m
export CONFIG_SFC_SRIOV := y
export CONFIG_SFC_PTP := y
export CONFIG_SFC_AOE := y
export CONFIG_SFC_PPS := y
export CONFIG_SFC_TRACING :=
endif

ifdef KSRCDIR
$(error KSRCDIR has been replaced with KPATH)
endif

ifdef KERNELRELEASE

# Check config dependencies under Kbuild.  We should only do this if
# .config has actually been included (it isn't when cleaning), so test
# for a config symbol that should always be defined.
ifdef CONFIG_NET
ifndef CONFIG_MTD
ifdef CONFIG_SFC_MTD
override CONFIG_SFC_MTD :=
endif
endif
ifdef CONFIG_SFC_I2C
ifndef CONFIG_I2C
$(warning Kernel does not support I2C)
override CONFIG_SFC_I2C :=
endif
ifndef CONFIG_I2C_ALGOBIT
$(warning Kernel does not support I2C_ALGOBIT)
override CONFIG_SFC_I2C :=
endif
endif # CONFIG_SFC_I2C
ifdef CONFIG_SFC_SFE4001
ifndef CONFIG_SFC_I2C
$(warning => SFE4001 board will not be supported)
override CONFIG_SFC_SFE4001 :=
endif
endif # CONFIG_SFC_SFE4001
ifdef CONFIG_SFC_HWMON
ifndef CONFIG_HWMON
$(warning Kernel does not support HWMON)
override CONFIG_SFC_HWMON :=
override CONFIG_SFC_MCDI_MON :=
endif
ifndef CONFIG_HWMON_VID
$(warning Kernel does not support HWMON_VID)
override CONFIG_SFC_HWMON :=
endif
ifndef CONFIG_SFC_I2C
override CONFIG_SFC_HWMON :=
endif
ifndef CONFIG_SFC_HWMON
$(warning => Temperature and voltage monitoring for SFC4000 boards will be disabled)
endif
ifndef CONFIG_SFC_MCDI_MON
$(warning => Temperature and voltage reporting for SFC9000-family boards will be disabled)
endif
endif # CONFIG_SFC_HWMON
ifdef CONFIG_SFC_SRIOV
ifndef CONFIG_PCI_IOV
$(warning Kernel does not support PCI_IOV)
override CONFIG_SFC_SRIOV :=
$(warning => SR-IOV functionality will be disabled)
endif
endif
ifdef CONFIG_SFC_TRACING
ifndef CONFIG_EVENT_TRACING
$(error Kernel does not support EVENT_TRACING)
endif
endif
endif # CONFIG_NET

else # !KERNELRELEASE ###### The following is for the standalone Makefile case

ifneq ($(MAKECMDGOALS),export-srpm)
# Get kernel version and source directory.  Either may be specified and
# we work out the other automatically.  If neither is specified then we
# assume the current kernel version.
ifdef KPATH
ifndef KVER
KVER := $(shell sed -r 's/^\#define UTS_RELEASE "(.*)"/\1/; t; d' $(KPATH)/include/generated/utsrelease.h $(KPATH)/include/linux/utsrelease.h $(KPATH)/include/linux/version.h 2>/dev/null)
ifeq ($(KVER),)
$(error Failed to find kernel version for $(KPATH))
endif
endif
else # !KPATH
ifndef KVER
KVER := $(shell uname -r)
endif
KPATH := /lib/modules/$(KVER)/build
endif # KPATH

KVERPARTS = $(subst -, ,$(subst ., ,$(KVER)))
ifeq ($(word 1,$(KVERPARTS)),2)
ifneq ($(word 2,$(KVERPARTS)),6)
$(error Kernel version $(KVER) is not supported; minimum version is 2.6.16)
endif
ifneq ($(filter 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15,$(word 3,$(KVERPARTS))),)
$(error Kernel version $(KVER) is not supported; minimum version is 2.6.16)
endif
endif

endif # export-srpm

endif # !KERNELRELEASE

endif # !EFX_UPSTREAM

sfc-y			+= efx.o nic.o farch.o falcon.o siena.o ef10.o \
			   tx.o rx.o selftest.o \
			   driverlink.o ethtool.o qt202x_phy.o mdio_10g.o \
			   tenxpress.o txc43128_phy.o falcon_boards.o mcdi.o \
			   mcdi_port.o mcdi_mon.o ptp.o
sfc-$(CONFIG_SFC_MTD)	+= mtd.o
sfc-$(CONFIG_SFC_SRIOV)	+= siena_sriov.o
ifndef EFX_NO_KCOMPAT
ifneq ($(MAKECMDGOALS),export)
sfc-y			+= ioctl.o kernel_compat.o
endif
endif # !EFX_NO_KCOMPAT
ifndef EFX_UPSTREAM
ifeq ($(filter export export-xen,$(MAKECMDGOALS)),)
sfc-y			+= linux_mdio.o
sfc-$(CONFIG_SFC_AOE)	+= aoe.o
sfc-$(CONFIG_SFC_DEBUGFS) += debugfs.o
sfc-$(CONFIG_SFC_HWMON)	+= lm87.o lm90.o
ifneq ($(CONFIG_SFC_PTP),y)
sfc-y			:= $(filter-out ptp.o,$(sfc-y))
endif
endif
endif # !EFX_UPSTREAM

obj-$(CONFIG_SFC)	+= sfc.o

ifndef EFX_UPSTREAM

sfc_tune-y		+= tweak.o idle.o
obj-$(CONFIG_SFC_TUNE)	+= sfc_tune.o

# Compiler flags
EXTRA_CFLAGS += -I$(src) -Wall -Wno-unused-label -Wno-deprecated-declarations -DEFX_NOT_UPSTREAM=1 -DEFX_USE_KCOMPAT=1 -DWITH_MCDI_V2
ifdef KMP_RELEASE
EXTRA_CFLAGS += -DKMP_RELEASE
endif


ifndef EFX_DISABLE_GRO
EXTRA_CFLAGS += -DEFX_USE_GRO
endif
ifndef EFX_DISABLE_SFC_LRO
EXTRA_CFLAGS += -DEFX_USE_SFC_LRO
endif


# Debugging-enabled builds
ifndef NDEBUG
EXTRA_CFLAGS += -DDEBUG -g
endif

all_sfc_ko = $(subst .o,.ko,$(obj-m))

ifdef KERNELRELEASE

# Define filechk if necessary
ifndef filechk
define filechk
	$(Q)set -e;				\
	$(if Q,echo '  CHK     $@';)		\
	mkdir -p $(dir $@);			\
	$(filechk_$(1)) < $< > $@.tmp;		\
	if [ -r $@ ] && cmp -s $@ $@.tmp; then	\
		rm -f $@.tmp;			\
	else					\
		$(if Q,echo '  UPD     $@';)	\
		mv -f $@.tmp $@;		\
	fi
endef
endif

# autocompat.h depends on the kernel compiled against.
# However, there is nothing stopping the user compiling on multiple
# machines in the same directory. The .kpath target provides a simple
# dependency check for this.
#
# Module(s).symvers also depends on the kernel compiled against, but
# can simply be deleted here.  However mmake does some more complicated
# management of Module.symvers and does not allow changing the kernel
# path, so don't touch it when invoked from an mmake tree.
$(obj)/.kpath: FORCE
	@if ! [ -f $@ ] || [ $$(cat $@) != $(objtree) ]; then		\
		echo $(objtree) >$@;					\
		$(if $(MMAKE_IN_KBUILD),,rm -f $(obj)/*.symvers;)	\
	fi

define filechk_autocompat.h
	$(src)/kernel_compat.sh -k $(CURDIR) $(if $(filter 1,$(V)),-v,-q)
endef

$(obj)/autocompat.h: $(obj)/.kpath $(src)/kernel_compat.sh
	+$(call filechk,autocompat.h)
	@touch $@

define filechk_config.h
	printf "$(foreach name,SFC_DEBUGFS SFC_HWMON SFC_MCDI_MON SFC_SFE4001 SFC_I2C SFC_MTD SFC_SRIOV SFC_PTP SFC_PRIVATE_MDIO SFC_AOE SFC_PPS SFC_TRACING,#undef CONFIG_$(name)\n$(if $(filter y,$(CONFIG_$(name))),#define CONFIG_$(name) 1\n))"
endef

$(obj)/config.h: $(src)/Makefile FORCE
	$(call filechk,config.h)

$(addprefix $(obj)/,$(sfc-y) $(sfc_tune-y)): \
	$(obj)/.kpath $(obj)/autocompat.h $(obj)/config.h

# Select the right warnings - complicated by working out which options work
ifndef try-run
try-run = $(shell set -e;		\
	TMP="$(obj)/.$$$$.tmp";		\
	TMPO="$(obj)/.$$$$.o";		\
	if ($(1)) >/dev/null 2>&1;	\
	then echo "$(2)";		\
	else echo "$(3)";		\
	fi;				\
	rm -f "$$TMP" "$$TMPO")
endif
ifndef cc-disable-warning
cc-disable-warning = $(call try-run,\
	$(CC) $(KBUILD_CPPFLAGS) $(KBUILD_CFLAGS) -W$(strip $(1)) -c -xc /dev/null -o "$$TMP",-Wno-$(strip $(1)))
endif
override EXTRA_CFLAGS += $(call cc-disable-warning, unused-but-set-variable) \
			 $(call cc-disable-warning, format-zero-length)

else # !KERNELRELEASE

# Some distribution packages of 2.6.16 fail to define KERNELRELEASE
# when compiling out-of-tree modules.
ifneq ($(filter 2.6.16-% 2.6.16.%,$(KVER)),)
EXTRA_MAKEFLAGS := KERNELRELEASE=$(KVER)
endif
ifneq ($(CC),)
EXTRA_MAKEFLAGS += CC=$(CC)
endif
ifdef KMP_RELEASE
EXTRA_MAKEFLAGS += KMP_RELEASE=1
endif

ifeq ($(INSTALL_MOD_DIR),)
INSTALL_MOD_DIR := updates
endif

default : all

all : modules
ifneq ($(findstring $(shell uname -p),x86_64 i686),)
	! [ -d unittest ] || $(MAKE) -C unittest
endif
ifdef BUILD_INKERNEL_TESTS
	! [ -d unittest_filters ] || $(MAKE) -C unittest_filters
endif

modules :
	$(MAKE) -C $(KPATH) $(EXTRA_MAKEFLAGS) M=$$(pwd)
# strip objects
ifndef DEBUG
	@strip --strip-debug $(all_sfc_ko)
endif

modules_install :
  # See bug 35865 for discussion on updates vs. extra location
	echo INSTALL_MOD_PATH=$(INSTALL_MOD_PATH)
	echo INSTALL_MOD_DIR=$(INSTALL_MOD_DIR)
	mkdir -p $(INSTALL_MOD_PATH)/lib/modules/$(KVER)/$(INSTALL_MOD_DIR)
	$(MAKE) -C $(KPATH) $(EXTRA_MAKEFLAGS) M=$$(pwd) INSTALL_MOD_DIR=$(INSTALL_MOD_DIR) modules_install

clean : clean_modules clean_tests

clean_tests:
	! [ -d unittest ] || $(MAKE) -C unittest clean
	! [ -d unittest_filters ] || $(MAKE) -C unittest_filters clean

clean_modules :
	rm -f *.o *.s *.ko *.mod.c *.symvers config.h autocompat.h .kpath
	$(MAKE) -C $(KPATH) $(EXTRA_MAKEFLAGS) M=$$(pwd) clean

.PHONY : all modules modules_install clean clean_modules FORCE


# Export into kernel tree
export:
	./export.sh $(KPATH) $(sfc-y:%.o=%.c) trace/events/sfc.h

# Export into a Xen kernel tree
export-xen:
	./export.sh -k -kk $(KPATH) $(sfc-y:%.o=%.c) trace/events/sfc.h

# Export for SRPM
export-srpm:
	mkdir -p $(KPATH)/mtd
	./export.sh -o $(KPATH) $(sfc-y:%.o=%.c)  $(sfc_tune-y:%.o=%.c) mtd/mtd-abi.h trace/events/sfc.h kernel_compat.sh

.PHONY : intranet doc clean_doc util clean_util export export-xen export-srpm

endif # !KERELRELEASE
endif # !EFX_UPSTREAM
