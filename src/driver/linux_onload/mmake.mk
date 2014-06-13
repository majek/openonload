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


# Build host
CPPFLAGS += -DCI_BUILD_HOST=$(HOSTNAME)

IMPORT		:= $(EFAB_SRCS:%=../efab/%) ../linux/linux_trampoline_asm.S \
		$(CHAR_SRCS:%=../linux/%)

IP_TARGET      := onload.o
IP_TARGET_SRCS := $(EFAB_SRCS) $(ONLOAD_SRCS) $(CHAR_SRCS)
IP_TARGET_SRCS += linux_trampoline_asm.o

TARGETS		:= $(IP_TARGET)

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

ifeq ($(strip $(CI_PREBUILT_IPDRV)),)
onload-objs  := $(IP_TARGET_SRCS:%.c=%.o)
onload-objs  += $(BUILD)/lib/efthrm/lib.a	\
		$(BUILD)/lib/transport/ip/lib.a	\
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
