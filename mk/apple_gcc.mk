
######################################################################
# Where to find commands.
#
ifndef CC
CC		:= gcc
endif
ifndef CXX
CXX		:= g++
endif

ifndef CLINK
CLINK		:= $(CC)
endif
ifndef CXXLINK
CXXLINK		:= $(CXX)
endif

ifndef LIBTOOL
LIBTOOL		:= libtool
endif
ifndef STRIP
STRIP		:= strip
endif
ifndef OTOOL
OTOOL		:= otool
endif
ifndef LIPO
LIPO		:= lipo
endif
ifndef INSTALL
INSTALL		:= install
endif
ifndef KEXTUTIL
KEXTUTIL	:= kextutil
endif
ifndef DSYMUTIL
DSYMUTIL	:= dsymutil
endif
ifndef PLUTIL
PLUTIL		:= plutil
endif


######################################################################
# File name conversion function.
#
TOOSNAMES=$(1)


######################################################################
# Compiler options.
#
CFLAGS		:=
LDFLAGS		:=

MMAKE_CFLAGS	:= -Wall

ifdef NDEBUG
MMAKE_CPPFLAGS	+= -DNDEBUG
MMAKE_CFLAGS	+= -Wno-unused
endif

MMAKE_CPPFLAGS	:=
MMAKE_LDFLAGS	:= 

ifndef MMAKE_ARCHS
MMAKE_ARCHS	:= -arch i386 -arch x86_64
endif

######################################################################
# How to compile, link etc.
#
define MMakeCompileC
set -x; \
$(CC) $(MMAKE_ARCHS) $(mmake_c_compile) $$cflags $$cppflags -c $< -o $@
endef

define MMakeCompileCXX
set -x; \
$(CXX) $(MMAKE_ARCHS) $(mmake_cxx_compile) $$cflags $$cppflags -c $< -o $@
endef

define MMakeCompileASM
$(CC) $(mmake_c_compile) -c $< -o $@
endef

define MMakeLinkDriver
set -x; \
$(CXXLINK) $(MMAKE_ARCHS) $(MMAKE_LDFLAGS) $(filter %.o,$^) \
	$(MMAKE_LIBS) -o $@; \
$(call DO_COPY_TARGET,$@)
endef

# Common user build libraries
STDLIBS	:=

define MMakeLinkCApp
set -x; \
$(CLINK) $(MMAKE_ARCHS) $(MMAKE_LDFLAGS) $(filter %.o,$^) \
	$$libs $(STDLIBS) -o $@; \
$(call DO_COPY_TARGET,$@)
endef

define MMakeLinkCXXApp
set -x; \
$(CXXLINK) $(MMAKE_ARCHS) $(MMAKE_LDFLAGS) $(filter %.o,$^) \
	$$libs $(STDLIBS) -o $@; \
$(call DO_COPY_TARGET,$@)
endef

define DarwinGenerateSymbols
set -x; \
$(DSYMUTIL) -o $@ $^
endef


define MMakeLinkStaticLib
set -x; \
$(LIBTOOL) -static -o $@ $^ \
$(call DO_COPY_TARGET,$@)
endef

define MMakeLinkDynamicLib
set -x; \
$(LIBTOOL) -dynamic -o $@ $^ \
$(call DO_COPY_TARGET,$@)
endef

#define MMakeLinkDynamicLibSwallow
#exit 1
#endef

######################################################################
# How to name and find libraries.
#
MMakeGenerateLibTarget = lib$(lib_name)$(lib_ver).a
MMakeGenerateLibDepend = $(BUILD)/$(lib_where)/$(MMakeGenerateLibTarget)
MMakeGenerateLibLink   = $(BUILD)/$(lib_where)/lib$(lib_name)$(lib_ver).a

bp := $(shell echo "$(BUILDPATH)" | sed 's+/mnt/./home+/home+')
MMakeGenerateDllTarget = lib$(lib_name)$(lib_ver).so
MMakeGenerateDllDepend = $(BUILD)/$(lib_where)/$(MMakeGenerateDllTarget)
MMakeGenerateDllLink   = -L$(BUILD)/$(lib_where) -l$(lib_name)$(lib_ver)
MMakeGenerateDllLink  += -Wl,-rpath $(bp)/$(lib_where)

######################################################################
# Misc stuff.
#
AppPattern	:= %
DARWIN		:= 1
UNIX		:= 1
