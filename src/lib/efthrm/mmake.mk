
TARGET		:= $(EFTHRM_LIB)
MMAKE_TYPE	:= LIB

LIB_SRCS	:= cplane.c \
		   cplane_prot.c \
		   eplock_resource_manager.c \
		   tcp_helper_endpoint.c \
		   tcp_helper_resource.c \
		   tcp_helper_cluster.c \
		   tcp_helper_ioctl.c \
		   tcp_helper_mmap.c \
		   tcp_helper_sleep.c \
		   tcp_filters.c \
		   oof_filters.c \
		   oof_onload.c \
		   driverlink_filter.c \
		   ip_prot_rx.c \
		   ip_protocols.c \
		   efabcfg.c \
		   onload_nic.c \
		   id_pool.c \
		   dump_to_user.c \
		   iobufset.c

ifeq ($(LINUX),1)
LIB_SRCS	+= tcp_helper_linux.c
endif

ifndef MMAKE_NO_RULES

MMAKE_OBJ_PREFIX := ef_thrm_
LIB_OBJS	 := $(LIB_SRCS:%.c=$(MMAKE_OBJ_PREFIX)%.o)

all: $(TARGET)

lib: $(TARGET)

clean:
	@$(MakeClean)

$(TARGET): $(LIB_OBJS) $(LIB_OBJS1)
	$(MMakeLinkStaticLib)
endif


######################################################
# linux kbuild support
#
ifdef MMAKE_USE_KBUILD
all:
	 $(MAKE) $(MMAKE_KBUILD_ARGS) SUBDIRS=$(BUILDPATH)/lib/efthrm _module_$(BUILDPATH)/lib/efthrm 
clean:
	@$(MakeClean)
	rm -f lib.a
endif

ifdef MMAKE_IN_KBUILD
LIB_OBJS := $(LIB_SRCS:%.c=%.o)
lib-y    := $(LIB_OBJS)
endif
