############################
# 
# Solarflare AOE Linux kernel drivers 
#
############################

ifndef KERNELRELEASE
export CONFIG_SFC_AOE := y
endif

# This is only used if make is invoked in the src directory

sfc_aoe-$(CONFIG_SFC_AOE)	:= aoe_init.o \
				   aoe_compat.o \
				   aoe_entry.o \
				   aoe_buffer.o \
				   aoe_queue.o \
				   aoe_map.o \
				   aoe_netdev.o \
				   aoe_sysfs.o \
				   aoe_ioctl.o \
				   aoe_stats.o \
				   aoe_dev.o \
				   driverlink.o \
				   mcdi.o \
				   inband.o

sfc_aoe_sim-$(CONFIG_SFC_AOE)	:= aoe_init.o \
				   aoe_compat.o \
				   aoe_sim.o \
				   aoe_dev.o \
				   aoe_buffer.o \
				   aoe_sysfs.o

# Build host
CPPFLAGS += -DCI_BUILD_HOST=$(HOSTNAME)

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

ifndef AOESIM
obj-m := sfc_aoe.o
else
obj-m := sfc_aoe_sim.o
endif

KVERPARTS = $(subst -, ,$(subst ., ,$(KVER)))
ifeq ($(word 1,$(KVERPARTS)),2)
ifneq ($(word 2,$(KVERPARTS)),6)
$(warning Kernel version $(KVER) is not supported\; minimum version is 2.6.16)
override sfc_aoe-y :=
override obj-m :=
endif
ifneq ($(filter 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15,$(word 3,$(KVERPARTS))),)
$(warning Kernel version $(KVER) is not supported\; minimum version is 2.6.16)
override sfc_aoe-y :=
override obj-m :=
endif
endif



# autocompat.h depends on the kernel compiled against.
# However, there is nothing stopping the user compiling on multiple
# machines in the same directory. The .kpath target provides a simple
# dependency check for this.

ifdef KERNELRELEASE

# Define filechk if necessary
ifndef filechk
define filechk
	$(Q)set -e;                             \
	$(if Q,echo '  CHK     $@';)            \
	mkdir -p $(dir $@);                     \
	$(filechk_$(1)) < $< > $@.tmp;          \
	if [ -r $@ ] && cmp -s $@ $@.tmp; then  \
		rm -f $@.tmp;                   \
	else                                    \
		$(if Q,echo '  UPD     $@';)    \
		mv -f $@.tmp $@;                \
	fi
endef
endif

$(obj)/.kpath: FORCE
	@if ! [ -f $@ ] || [ $$(cat $@) != $(objtree) ]; then   \
		echo $(objtree) >$@;                            \
	fi

define filechk_autocompat.h
	$(src)/kernel_compat_aoe.sh -k $(CURDIR) $(if $(filter 1,$(V)),-v,-q)
endef

$(obj)/autocompat.h: $(obj)/.kpath $(src)/kernel_compat_aoe.sh $(src)/../linux_net/kernel_compat.sh
	+$(call filechk,autocompat.h)
	@touch $@

define filechk_config.h
	printf "$(foreach name,SFC_AOE,#undef CONFIG_$(name)\n$(if $(filter y,$(CONFIG_$(name))),#define CONFIG_$(name) 1\n))"
endef

$(obj)/config.h: $(src)/Makefile FORCE
	$(call filechk,config.h)

$(addprefix $(obj)/,$(sfc_aoe-y)): \
	$(obj)/.kpath $(obj)/autocompat.h $(obj)/config.h

INCLUDES += -I$(src) -I$(src)/../../../../src/include -I$(src)/../../include -I$(src)/../linux_net

EXTRA_CFLAGS += $(INCLUDES) -Wall -Wno-unused-label -Wno-deprecated-declarations \
        -DEFX_NOT_UPSTREAM=1 \
        -DEFX_USE_KCOMPAT=1 \
        -DMAP_DEBUG

else

######################################################
# linux kbuild support
#

.PHONY : modules

all: modules

modules:
	$(MAKE) -C $(KPATH) $(EXTRA_MAKEFLAGS) M=$$(pwd)

clean:
	@$(MakeClean)
	rm -rf *.ko Module.symvers .tmp_versions .*.cmd *.mod.c *.o autocompat.h config.h

endif
