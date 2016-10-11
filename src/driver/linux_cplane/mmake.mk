############################
# 
# EtherFabric linux kernel drivers 
#
#	onload_ip
#
############################


CPLANE_SRCS	:= driver.c bonding.c teaming.c char.c

# Build host
CPPFLAGS += -DCI_BUILD_HOST=$(HOSTNAME)

TARGETS		:= onload_cplane.o
TARGET_SRCS	:= $(CPLANE_SRCS)


cplane_api_version.h: $(CPLANE_HEADERS) $(TOPPATH)/mk/site/ocplane.mk
	$(CPLANE_GENERATE_API_VERSION)

######################################################
# linux kbuild support
#


all: cplane_api_version.h
	$(MMAKE_KBUILD_PRE_COMMAND)
	$(MAKE) $(MMAKE_KBUILD_ARGS) M=$(CURDIR)
	$(MMAKE_KBUILD_POST_COMMAND)
	cp -f onload_cplane.ko $(DESTPATH)/driver/linux

ifneq ($(USE_EXTRA_SYM),ok)
$(BUILDPATH)/driver/linux_cplane/Module.symvers: \
	$(BUILDPATH)/driver/linux_char/Module.symvers
	cp $< $@

all: $(BUILDPATH)/driver/linux_cplane/Module.symvers
endif

clean:
	@$(MakeClean)
	rm -rf *.ko Module.symvers .tmp_versions .*.cmd cplane_api_version.h


ifdef MMAKE_IN_KBUILD

obj-m := $(TARGETS)

onload_cplane-objs  := $(TARGET_SRCS:%.c=%.o)
onload_cplane-objs  += $(BUILD)/lib/cplane/lib.a
onload_cplane-objs  += $(BUILD)/lib/citools/lib.a

endif # MMAKE_IN_KBUILD
