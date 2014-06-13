SUBDIRS         := ftl

TARGET		:= $(EFABCFG_LIB)

LIB_SRCS	:= lib_efabcfg.c pattern.c

LIB_OBJS	 := $(LIB_SRCS:%.c=$(MMAKE_OBJ_PREFIX)%.o)

ifndef MMAKE_NO_RULES

all: $(TARGET)
	+@$(MakeSubdirs)

lib: $(TARGET)

clean:
	@$(MakeClean)

$(TARGET): $(LIB_OBJS)
	$(MMakeLinkStaticLib)

endif

######################################################
# linux kbuild support
#
ifdef MMAKE_USE_KBUILD
all:
	$(MAKE) $(MMAKE_KBUILD_ARGS) SUBDIRS=$(BUILDPATH)/lib/efabcfg _module_$(BUILDPATH)/lib/efabcfg
clean:
	@$(MakeClean)
	rm -f lib.a
endif

ifdef MMAKE_IN_KBUILD
LIB_OBJS := $(LIB_SRCS:%.c=%.o)
lib-y    := $(LIB_OBJS)
endif

