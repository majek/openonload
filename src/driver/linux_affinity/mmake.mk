SFCAFF_SRCS	:= sfcaffinity.c

SFCAFF_TARGET	:= sfc_affinity.o
SFCAFF_TARGET_SRCS := $(SFCAFF_SRCS)

TARGETS		:= $(SFCAFF_TARGET)

IMPORT		:= ../linux_net/driverlink_api.h


######################################################
# linux kbuild support
#

$(BUILDPATH)/driver/linux_affinity/autocompat.h: kernel_compat.sh
	./kernel_compat.sh -k $(KPATH) $(if $(filter 1,$(V)),-v,-q) >$@

all: $(BUILDPATH)/driver/linux_affinity/Module.symvers $(BUILDPATH)/driver/linux_affinity/autocompat.h
	$(MMAKE_KBUILD_PRE_COMMAND)
	$(MAKE) $(MMAKE_KBUILD_ARGS) M=$(CURDIR)
	$(MMAKE_KBUILD_POST_COMMAND)
	cp -f sfc_affinity.ko $(DESTPATH)/driver/linux
ifndef CI_FROM_DRIVER
	$(warning "Due to build order sfc.ko may be out-of-date. Please build in driver/linux_net")
endif

$(BUILDPATH)/driver/linux_affinity/Module.symvers: \
		$(BUILDPATH)/driver/linux_net/Module.symvers
	cp $< $@

clean:
	@$(MakeClean)
	rm -rf *.ko Module.symvers .tmp_versions .*.cmd


ifdef MMAKE_IN_KBUILD
dummy := $(shell echo>&2 "MMAKE_IN_KBUILD")

obj-m := $(SFCAFF_TARGET) 

sfc_affinity-objs := $(SFCAFF_TARGET_SRCS:%.c=%.o)

endif # MMAKE_IN_KBUILD
