############################
# 
# EtherFabric linux kernel drivers 
#
#	onload_ip
#
############################

EFAB_SRCS	:= workqueue.c

ONLOAD_SRCS	:= driver.c linux_cplane.c \
		tcp_sendpage.c driverlink_ip.c linux_stats.c pinbuf.c \
		linux_trampoline.c shmbuf.c iscsi_support.c compat.c \
		ossock_calls.c linux_efabcfg.c linux_sock_ops.c mmap.c \
		bonding.c epoll_device.c terminate.c sigaction_calls.c \
		onloadfs.c

EFTHRM_SRCS	:= cplane.c cplane_prot.c eplock_resource_manager.c \
		tcp_helper_endpoint.c tcp_helper_resource.c \
		tcp_helper_ioctl.c tcp_helper_mmap.c tcp_helper_sleep.c \
		tcp_filters.c oof_filters.c oof_onload.c \
		driverlink_filter.c ip_prot_rx.c ip_protocols.c \
		efabcfg.c onload_nic.c id_pool.c dump_to_user.c iobufset.c

EFTHRM_HDRS	:= oo_hw_filter.h oof_impl.h tcp_filters_internal.h

ifeq ($(LINUX),1)
EFTHRM_SRCS	+= tcp_helper_linux.c
endif

# Build host
CPPFLAGS += -DCI_BUILD_HOST=$(HOSTNAME)

IMPORT		:= $(EFAB_SRCS:%=../efab/%) \
		$(EFTHRM_SRCS:%=../../lib/efthrm/%) \
		$(EFTHRM_HDRS:%=../../lib/efthrm/%)

IP_TARGET      := onload.o
IP_TARGET_SRCS := $(EFAB_SRCS) $(ONLOAD_SRCS) $(EFTHRM_SRCS)

TARGETS		:= $(IP_TARGET)

# Need to import this here, because IMPORT is processed before we know 
# (easily) which architecture we are actually building for.
IMPORT         	   += linux_trampoline_asm_x86.S 

x86_TARGET_SRCS    := x86_linux_trampoline.o linux_trampoline_asm_x86.o

i386_TARGET_SRCS    := $(x86_TARGET_SRCS)

x86_64_TARGET_SRCS := $(x86_TARGET_SRCS)

ia64_TARGET_SRCS := $(x86_TARGET_SRCS)

powerpc_TARGET_SRCS    := ppc64_linux_trampoline_asm.o \
			ppc64_linux_trampoline.o ppc64_linux_trampoline_internal.o


######################################################
# linux kbuild support
#


all: $(BUILDPATH)/driver/linux_onload/Module.symvers
	$(MMAKE_KBUILD_PRE_COMMAND)
	$(MAKE) $(MMAKE_KBUILD_ARGS) M=$(CURDIR) \
		DO_EFAB_IP=1
	$(MMAKE_KBUILD_POST_COMMAND)
	cp -f onload.ko $(DESTPATH)/driver/linux

$(BUILDPATH)/driver/linux_onload/Module.symvers: \
	$(BUILDPATH)/driver/linux_char/Module.symvers
	cp $< $@

clean:
	@$(MakeClean)
	rm -rf *.ko Module.symvers .tmp_versions .*.cmd


ifdef MMAKE_IN_KBUILD

obj-m := $(IP_TARGET)

ifeq ($(ARCH),powerpc)
# RHEL5/PPC requires you to pass this, because by default its userspace
# is 32-bit, but its kernel was built with a 64-bit compiler!
EXTRA_CFLAGS+= -m64
endif

ifeq ($(strip $(CI_PREBUILT_IPDRV)),)
onload-objs  := $(IP_TARGET_SRCS:%.c=%.o) $($(ARCH)_TARGET_SRCS:%.c=%.o)
onload-objs  += $(BUILD)/lib/transport/ip/lib.a	\
		$(BUILD)/lib/citools/lib.a	\
		$(BUILD)/lib/efabcfg/lib.a \
		$(BUILD)/lib/ciul/lib.a

else # CI_PREBUILT_IPDRV

onload-objs := onload.copy.o

$(BUILDPATH)/driver/linux_onload/onload.copy.o: $(CI_PREBUILT_IPDRV)
	@echo +++ Using prebuilt IP driver: $(CI_PREBUILT_IPDRV)
	cp $(CI_PREBUILT_IPDRV) $(BUILDPATH)/driver/linux_onload/onload.copy.o

endif # CI_PREBUILT_IPDRV

endif # MMAKE_IN_KBUILD
