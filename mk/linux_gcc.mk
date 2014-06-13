
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

cxxwarnings	:= $(warnerror) -Wall -Wundef -Wpointer-arith

MMAKE_CFLAGS	+= $(MMAKE_CARCH) $(cwarnings)
MMAKE_CXXFLAGS	+= $(MMAKE_CARCH) $(cxxwarnings)
MMAKE_CPPFLAGS	:=

MMAKE_CFLAGS_DLL := -fPIC
MMAKE_CFLAGS_LIB := -fPIC

ifndef CFLAGS
CFLAGS		:= -O2
ifndef NO_DEBUG_INFO
CFLAGS		+= -g
endif
endif

ifndef CXXFLAGS
CXXFLAGS	:= -O2
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
MMakeGenerateLibTarget = lib$(lib_name)$(lib_ver).a
MMakeGenerateLibDepend = $(BUILD)/$(lib_where)/$(MMakeGenerateLibTarget)
MMakeGenerateLibLink   = $(BUILD)/$(lib_where)/lib$(lib_name)$(lib_ver).a

MMakeGenerateDllRealname = lib$(lib_name).so.$(lib_maj).$(lib_min).$(lib_mic)
MMakeGenerateDllSoname = lib$(lib_name).so.$(lib_maj)
MMakeGenerateDllLinkname = lib$(lib_name).so
MMakeGenerateDllDepend = $(BUILD)/$(lib_where)/$(MMakeGenerateDllTarget)
MMakeGenerateDllLink   = -L$(BUILD)/$(lib_where) -l$(lib_name) -Wl,-rpath $(shell echo "$(BUILDPATH)" | sed 's+/mnt/./home+/home+')/$(lib_where)


######################################################################
# Misc stuff.
#
AppPattern := %
LINUX	:= 1
UNIX	:= 1
