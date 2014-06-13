############################
# 
# EtherFabric linux kernel drivers 
#
#	sfc_resource
#
############################

RESOURCE_SRCS	:= resource_driver.c \
	iopage.c driverlink_new.c kernel_proc.c vf_driver.c filter.c

EFHW_SRCS	:= nic.c eventq.c falcon.c

EFRM_SRCS	:=			\
		assert_valid.c		\
		buffer_table.c		\
		efrm_vi_set.c		\
		efrm_pd.c		\
		iobufset_resource.c	\
		resource_manager.c	\
		resources.c		\
		vi_resource_alloc.c	\
		vi_resource_event.c	\
		vi_resource_flush.c	\
		vi_resource_manager.c	\
		vi_resource_info.c	\
		vi_allocator.c		\
		vf_resource.c		\
		buddy.c			\
		kfifo.c			\
		driver_object.c

EFRM_HDRS	:= efrm_internal.h efrm_vi.h efrm_vi_set.h efrm_vf.h \
		efrm_iobufset.h efrm_pd.h


IMPORT		:= $(EFHW_SRCS:%=../../lib/efhw/%) \
		   $(EFRM_SRCS:%=../../lib/efrm/%) \
		   $(EFRM_HDRS:%=../../lib/efrm/%)

RESOURCE_TARGET	:= sfc_resource.o
RESOURCE_TARGET_SRCS := $(RESOURCE_SRCS) $(EFHW_SRCS) $(EFRM_SRCS)

TARGETS		:= $(RESOURCE_TARGET)




######################################################
# linux kbuild support
#


all: $(BUILDPATH)/driver/linux_resource/Module.symvers
	$(MMAKE_KBUILD_PRE_COMMAND)
	$(MAKE) $(MMAKE_KBUILD_ARGS) M=$(CURDIR)
	$(MMAKE_KBUILD_POST_COMMAND)
	cp -f sfc_resource.ko $(DESTPATH)/driver/linux
ifndef CI_FROM_DRIVER
	$(warning "Due to build order sfc.ko may be out-of-date. Please build in driver/linux_net")
endif

$(BUILDPATH)/driver/linux_resource/Module.symvers: \
		$(BUILDPATH)/driver/linux_net/Module.symvers \
		$(BUILDPATH)/driver/linux_affinity/Module.symvers
	cat $^ >$@

clean:
	@$(MakeClean)
	rm -rf *.ko Module.symvers .tmp_versions .*.cmd


ifdef MMAKE_IN_KBUILD

obj-m := $(RESOURCE_TARGET) 

sfc_resource-objs := $(RESOURCE_TARGET_SRCS:%.c=%.o)

endif # MMAKE_IN_KBUILD
