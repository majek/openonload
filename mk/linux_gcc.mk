
######################################################################
# Where to find commands.
#
ifndef CC
CC		:= $(CCPREFIX)gcc$(CCSUFFIX)
endif
ifndef CXX
CXX		:= $(CCPREFIX)g++$(CCSUFFIX)
endif
ifndef CLINK
CLINK		:= $(CC)
endif
ifndef CXXLINK
CXXLINK		:= $(CXX)
endif
ifndef AR
AR		:= ar
endif
ifndef NICE
NICE		:= nice
endif
ifndef STRIP
STRIP		:= strip
endif

CC		:= $(NICE) $(CC)
CXX		:= $(NICE) $(CXX)
CLINK		:= $(NICE) $(CLINK)
CXXLINK		:= $(NICE) $(CXXLINK)
AR		:= $(NICE) $(AR)

######################################################################
# File name conversion function.
#
TOOSNAMES=$(1)


######################################################################
# Compiler options.
#
ifdef MMAKE_LIBERAL
warnerror	:=
else
warnerror	:= -Werror
endif

cwarnings	:= $(warnerror) -Wall
# These are definitely good.
cwarnings	+= -Wundef -Wpointer-arith -Wstrict-prototypes -Wnested-externs
# gcc seems to get this utterly wrong.
#cwarnings	+= -Wbad-function-cast
# These are arguably a bit fussy.
#cwarnings	+= -Wmissing-prototypes
# These require recent gcc version:
#cwarnings	+= -Wdeclaration-after-statement -Wunreachable-code \
#		-Wdisabled-optimization

ifdef W_NO_UNUSED_RESULT
cwarnings += -Wno-unused-result
endif

cxxwarnings	:= $(warnerror) -Wall -Wundef -Wpointer-arith

MMAKE_CFLAGS	+= $(MMAKE_CARCH) $(cwarnings)
MMAKE_CXXFLAGS	+= $(MMAKE_CARCH) $(cxxwarnings)
MMAKE_CPPFLAGS	:=

MMAKE_CFLAGS_DLL := -fPIC
MMAKE_CFLAGS_LIB := -fPIC

ifdef GCOV
  # gcov should be run with optimisations disabled.
  PROFILE_ONLOAD := 1
endif

ifndef CFLAGS
  ifneq (${PROFILE_ONLOAD},1)
    ifeq ($(findstring /opt/at6.0,$(CC)),)
      CFLAGS	:= -O2
    else
      CFLAGS 	:= -O3
    endif
  endif
  ifndef NO_DEBUG_INFO
    CFLAGS	+= -g
  endif
endif

ifndef CXXFLAGS
  ifneq (${PROFILE_ONLOAD},1)
    CXXFLAGS	:= -O2
  endif
  ifndef NO_DEBUG_INFO
    CXXFLAGS	+= -g
  endif
endif

ifdef NDEBUG
MMAKE_CFLAGS	+= -fomit-frame-pointer
MMAKE_CPPFLAGS	+= -DNDEBUG
endif

ifdef STRIP_LIBS
mmake_strip	= $(STRIP) --strip-unneeded $@
endif

ifdef PCAP_SUPPORT
MMAKE_CPPFLAGS	+= -DPCAP_SUPPORT
endif

ifdef OFE_TREE
  MMAKE_INCLUDE	+= -I$(OFE_TREE)/include
  MMAKE_CPPFLAGS	+= -DONLOAD_OFE -DOFE_ONLOAD
endif

ifdef GCOV
  MMAKE_CFLAGS        += -fprofile-arcs -ftest-coverage
  MMAKE_DIR_LINKFLAGS += -fprofile-arcs
endif

######################################################################
# How to compile, link etc.
#
define MMakeCompileC
$(CC) $(mmake_c_compile) $$cflags $$cppflags -c $< -o $@
endef


define MMakeCompileCXX
$(CXX) $(mmake_cxx_compile) $$cxxflags $$cppflags -c $< -o $@
endef


define MMakeCompileASM
$(CC) $(mmake_c_compile) $$cflags $$cppflags -c $< -o $@
endef


define MMakeLinkStaticLib
$(RM) $@ ; $(AR) -cr $@ $^
endef

define MMakeLinkRelocatable
set -x; \
$(CLINK) $(MMAKE_CARCH) $(CFLAGS) $(MMAKE_DIR_LINKFLAGS) \
	-fPIC -nostdlib $(MMAKE_RELOCATABLE_LIB) -r $(filter %.o,$^) $$libs -o $@;
endef

define MMakeLinkPreloadLib
set -x; \
$(CLINK) $(MMAKE_CARCH) $(CFLAGS) $(MMAKE_DIR_LINKFLAGS) -nostartfiles \
	-shared -fPIC $(filter %.o,$^) $$libs -lm -lpthread -lrt -ldl -o $@; \
$(mmake_strip) \
$(call DO_COPY_TARGET,$@)
endef


define MMakeLinkDynamicLib
set -x; \
$(CLINK) $(MMAKE_CARCH) $(CFLAGS) $(MMAKE_DIR_LINKFLAGS) \
	-shared -fPIC -Wl,-soname,$$soname $(filter %.o,$^) $$libs -o $@; \
$(mmake_strip) \
$(call DO_COPY_TARGET,$@)
endef


define MMakeLinkCApp
set -x; \
$(CLINK) $(MMAKE_CARCH) $(CFLAGS) -Wl,-E $(MMAKE_DIR_LINKFLAGS) $(filter %.o,$^) \
	$$libs -lm -lpthread -lrt -o $@; \
$(call DO_COPY_TARGET,$@)
endef


define MMakeLinkCxxApp
set -x; \
$(CXXLINK) $(MMAKE_CARCH) $(CFLAGS) -Wl,-E $(MMAKE_DIR_LINKFLAGS) \
	$(filter %.o,$^) $$libs -lm -lpthread -lrt -o $@; \
$(call DO_COPY_TARGET,$@)
endef


######################################################################
# How to name and find libraries.
#
ifeq ($(NDEBUG),1)
MMakeGeneratePrebuiltPath = $(TOP)/prebuilt/$(shell mmaketool --userbuild)/$(lib_where)
else
MMakeGeneratePrebuiltPath = $(TOP)/prebuilt/$(shell mmaketool --userbuild)/$(lib_where)/debug
endif

MMakeGenerateLibTarget = lib$(lib_name)$(lib_ver).a
MMakeGenerateLibDepend = $(BUILD)/$(lib_where)/$(MMakeGenerateLibTarget)
MMakeGenerateLibLink   = $(BUILD)/$(lib_where)/lib$(lib_name)$(lib_ver).a
MMakeGeneratePrebuiltLibDepend = $(MMakeGeneratePrebuiltPath)/$(MMakeGenerateLibTarget)
MMakeGeneratePrebuiltLibLink   = $(MMakeGeneratePrebuiltPath)/lib$(lib_name)$(lib_ver).a


MMakeGenerateDllRealname = lib$(lib_name).so.$(lib_maj).$(lib_min).$(lib_mic)
MMakeGenerateDllSoname = lib$(lib_name).so.$(lib_maj)
MMakeGenerateDllLinkname = lib$(lib_name).so
MMakeGenerateDllDepend = $(BUILD)/$(lib_where)/$(MMakeGenerateDllTarget)
MMakeGenerateDllLink   = -L$(BUILD)/$(lib_where) -l$(lib_name) -Wl,-rpath $(shell echo "$(BUILDPATH)" | sed 's+/mnt/./home+/home+')/$(lib_where)
MMakeGeneratePrebuiltDllDepend = $(MMakeGeneratePrebuiltPath)/$(MMakeGenerateDllTarget)
MMakeGeneratePrebuiltDllLink   = -L$(MMakeGeneratePrebuiltPath) -l$(lib_name)


######################################################################
# Misc stuff.
#
AppPattern := %
LINUX	:= 1
UNIX	:= 1
