MMAKE_IN_KBUILD	:= 1

# A makefile called Kbuild should override the mmake-generated Makefile,
# but Linux <2.6.10 does not look for that.
ifneq ($(wildcard $(obj)/Kbuild),)
include $(obj)/Kbuild
else

include $(TOPPATH)/mk/platform/$(PLATFORM).mk

EXTRA_CPPFLAGS += -I$(TOPPATH)/src/include -I$(BUILDPATH)/include \
		-I$(BUILDPATH) -I$(TOPPATH)/$(CURRENT) -D__ci_driver__
ifdef NDEBUG
EXTRA_CPPFLAGS += -DNDEBUG
endif
ifndef MMAKE_LIBERAL
EXTRA_CFLAGS += -Werror
endif # MMAKE_LIBERAL

ifndef NDEBUG
EXTRA_CFLAGS += -g
endif

EXTRA_CFLAGS += $(MMAKE_CFLAGS) $(EXTRA_CPPFLAGS)
EXTRA_AFLAGS += $(EXTRA_CPPFLAGS)

endif # Kbuild exists
