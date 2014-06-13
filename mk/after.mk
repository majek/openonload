######################################################################
# Sanity checks (correct build path and platform?)
#
ifndef MAKE_SANITY_DONE # only do sanity checks on first make, not recursive makes
MAKE_SANITY_DONE:=1
platform := $(shell cat $(BUILD)/mmake_platform)
ifneq ($(platform),$(PLATFORM))
$(shell echo >&2 "Platform inconsistency. Run mmakebuildtree again.")
$(error Platform inconsistency. Run mmakebuildtree again.)
endif
ifneq ($(WINDOWS),1)
ifneq ($(DOS),1)
buildpath := $(shell mmaketool --buildpath)
ifeq ($(buildpath),)
$(shell echo >&2 "Please ensure mmaketool is the path.")
$(error Please ensure mmaketool is the path.)
endif
ifneq ($(buildpath),$(BUILDPATH))
$(shell echo >&2 "Build path inconsistency. Run mmakebuildtree again.")
$(error Build path inconsistency. Run mmakebuildtree again.)
endif
endif

ifneq ($(BUILDENV),)
buildenv := $(shell mmaketool --distribution)-$(shell uname -m)

ifneq ($(buildenv),$(BUILDENV))
$(shell echo >&2 "********** Warning: building on different host environment. **********")
$(shell echo >&2 "**********          wanted='$(BUILDENV)' got='$(buildenv)'")
ifdef DRIVER
$(error Build host inconsistency for driver build.)
endif
endif
endif
endif

# NDEBUG must be undefined, or defined as 1.
ifdef NDEBUG
ifneq ($(NDEBUG),1)
$(error NDEBUG must be undefined, or defined as 1.)
endif
endif

endif

######################################################################
# Get lists of source files.

MMAKE_ORIG_SRCS := \
    $(filter-out $(addprefix $(TOP)/$(CURRENT)/,$(MMAKE_GEN_SRCS)), \
    $(wildcard $(TOP)/$(CURRENT)/*.S) \
    $(wildcard $(TOP)/$(CURRENT)/*.inc) \
    $(wildcard $(TOP)/$(CURRENT)/*.inf) \
    $(wildcard $(TOP)/$(CURRENT)/*.inx) \
    $(wildcard $(TOP)/$(CURRENT)/*.rc) \
    $(wildcard $(TOP)/$(CURRENT)/*.def) \
    $(wildcard $(TOP)/$(CURRENT)/*.c) \
    $(wildcard $(TOP)/$(CURRENT)/*.cc) \
    $(wildcard $(TOP)/$(CURRENT)/*.h) \
    $(wildcard $(TOP)/$(CURRENT)/*.mof) \
    $(wildcard $(TOP)/$(CURRENT)/*.manifest) \
    $(wildcard $(TOP)/$(CURRENT)/*.mc) \
    $(wildcard $(TOP)/$(CURRENT)/*.ico) \
    $(wildcard $(TOP)/$(CURRENT)/*.cs) \
    $(wildcard $(TOP)/$(CURRENT)/*.resx) \
    $(wildcard $(TOP)/$(CURRENT)/*.sln) \
    $(wildcard $(TOP)/$(CURRENT)/*.csproj) \
    $(wildcard $(TOP)/$(CURRENT)/*.settings) \
    $(wildcard $(TOP)/$(CURRENT)/*.config) \
    $(wildcard $(TOP)/$(CURRENT)/*.datasource) \
    $(wildcard $(TOP)/$(CURRENT)/*.user) \
    $(wildcard $(TOP)/$(CURRENT)/*.bmp) \
    $(wildcard $(TOP)/$(CURRENT)/*.asm) \
    $(wildcard $(TOP)/$(CURRENT)/*.ldpre) \
    $(wildcard $(TOP)/$(CURRENT)/*.plist) \
    $(addprefix $(TOP)/$(CURRENT)/,$(IMPORT)))

MMAKE_C_SRCS := $(notdir $(filter %.c, ${MMAKE_ORIG_SRCS}))
MMAKE_CXX_SRCS := $(notdir $(filter %.cc, ${MMAKE_ORIG_SRCS}))
MMAKE_LDPRE_SRCS := $(notdir $(filter %.ldpre, ${MMAKE_ORIG_SRCS}))
MMAKE_S_SRCS := $(notdir $(filter %.S, ${MMAKE_ORIG_SRCS}))

# list of files that should always be copied
MMAKE_COPY_SRCS := \
    $(wildcard $(TOP)/$(CURRENT)/*.sh)

######################################################################
# Set up stuff for VPATH

IMPORT :=$(sort $(IMPORT))

ifndef VPATH_ENABLED
$(error VPATH_ENABLED not set, please remove your existing build tree and rerun mmakebuildtree)
endif

ifeq ($(VPATH_ENABLED),1)

ifeq ($(WINDOWS)$(DESTFLAG),10)
VPATH := $(VPATH) $(TOP)/$(CURRENT) $(foreach param,$(addprefix $(TOP)/$(CURRENT)/,$(sort $(dir $(IMPORT)))),$(shell cd -P $(param) && pwd))
# note the shell cd & pwd step, reduces any "x/.." elements in the path; this is needed to fix a weird cygwin makedepend problem
else
VPATH := $(VPATH) $(TOP)/$(CURRENT) $(addprefix $(TOP)/$(CURRENT)/,$(sort $(dir $(IMPORT))))
endif

VPATH_INCLUDES := $(addprefix -I,$(VPATH))
MMAKE_INCLUDE		:= $(MMAKE_INCLUDE) $(VPATH_INCLUDES)

endif # ifeq ($(VPATH_ENABLED),1)

######################################################################
# Do file copying

ifndef MMAKEBUILDTREE

ifeq ($(DO_COPY_TARGET),)
COPY_SRC_TARGET=
else
COPY_SRC_TARGET= \
	@for SRC in ${MMAKE_COPY_SRCS} _o ; do \
	    if [ "$$SRC" != "_o" ]; then \
	        $(call DO_COPY_TARGET,$$SRC) \
	    fi ; \
	done

endif

ifeq ($(VPATH_ENABLED),1)

copy.done: ${MMAKE_COPY_SRCS} $(TOP)/$(CURRENT)/mmake.mk $(TOP)/mk/after.mk
	@for SRC in ${MMAKE_COPY_SRCS} _o ; do \
	    if [ "$$SRC" != "_o" ]; then \
		DST=`basename "$$SRC"` ; \
	        if /usr/bin/env test \( \! -f "$$DST" \) -o \( "$$DST" -ot "$$SRC" \) ; then \
                    cp -f "$$SRC" "$$DST" ; \
	            chmod -w "$$DST" ; \
	      	fi ; \
	    fi ; \
	done
	@${COPY_SRC_TARGET}
	@touch "$@"

else  # ifeq ($(VPATH_ENABLED),1) ... else

copy.done: ${MMAKE_COPY_SRCS} ${MMAKE_ORIG_SRCS} $(TOP)/$(CURRENT)/mmake.mk $(TOP)/mk/after.mk
	@for SRC in ${MMAKE_ORIG_SRCS} ${MMAKE_COPY_SRCS}; do \
	    DST=`basename "$$SRC"` ; \
	    if [ \( \! -f "$$DST" \) -o \( "$$DST" -ot "$$SRC" \) ] ; then \
	        cp -f "$$SRC" "$$DST" ; \
	        chmod -w "$$DST" ; \
	    fi ; \
	done
	@${COPY_SRC_TARGET}
	@touch "$@"

endif  # ifeq ($(VPATH_ENABLED),1

# The contents of the file don't matter, but this forces its
# dependencies to be rebuilt.  DON'T UPDATE THE TIMESTAMP ON THE FILE
# UNLESS NECESSARY BECAUSE THAT WOULD CAUSE THE MAKEFILE TO BE REREAD.
# Don't use "echo -n" because Solaris doesn't support that.
copy.depends: copy.done
	@[ -f "$@" ] || echo >$@
sinclude copy.depends

endif # ifndef MMAKEBUILDTREE

######################################################################
# How to compile C and C++ sources.
#
$(MMAKE_OBJ_PREFIX)%.o: %.c
	$(MMakeCompileC)

$(MMAKE_OBJ_PREFIX)%.o: %.cc
	$(MMakeCompileCXX)

$(MMAKE_OBJ_PREFIX)%.o: %.cpp
	$(MMakeCompileCXX)

$(MMAKE_OBJ_PREFIX)%.o: %.cxx
	$(MMakeCompileCXX)

$(MMAKE_OBJ_PREFIX)%.o: %.S
	$(MMakeCompileASM)

ifeq ($(DRIVER),1)
MMAKE_TYPE	:= $(MMAKE_TYPE)_DRIVER
endif

ifeq ($(INSTALLER),1)
MMAKE_TYPE	:= $(MMAKE_TYPE)_INSTALLER
endif

mmake_c_compile = $(MMAKE_INCLUDE)
mmake_c_compile += $(MMAKE_DIR_CPPFLAGS) $(CPPFLAGS) $(MMAKE_CPPFLAGS)
mmake_c_compile += $(MMAKE_CFLAGS_$(MMAKE_TYPE)) $(MMAKE_DIR_CFLAGS)
mmake_c_compile += $(MMAKE_CFLAGS) $(CFLAGS)

mmake_masm_compile = $(MMAKE_INCLUDE)

mmake_cxx_compile = $(MMAKE_INCLUDE)
mmake_cxx_compile += $(MMAKE_DIR_CPPFLAGS) $(CPPFLAGS) $(MMAKE_CPPFLAGS)
mmake_cxx_compile += $(MMAKE_CXXFLAGS_$(MMAKE_TYPE)) $(MMAKE_DIR_CXXFLAGS)
mmake_cxx_compile += $(MMAKE_CXXFLAGS) $(CXXFLAGS)

ifeq ($(DRIVER),1)
SUBDIRS := $(DRIVER_SUBDIRS)
OTHER_SUBDIRS := $(OTHER_DRIVER_SUBDIRS)
endif

ifeq ($(INSTALLER),1)
SUBDIRS := $(INSTALLER_SUBDIRS)
OTHER_SUBDIRS := $(OTHER_INSTALLER_SUBDIRS)
endif


######################################################################
# Default rule for single-source apps.
#
$(AppPattern): %.o $(MMAKE_LIB_DEPS)
	@(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp))


######################################################################
# Generate dependencies automagically :-)
#
ifndef MMAKE_NO_DEPS

ifneq ($(MAKECMDGOALS),clean) # don't make dependencies for clean
ifneq ($(MAKECMDGOALS),clean_desttree) # don't make dependencies for clean

ifdef USE_MAKEDEPEND

MMAKE_DEPS_CXX_OPT:=$(mmake_cxx_compile)
MMAKE_DEPS_C_OPT:=$(mmake_c_compile)

ifeq ($(WINDOWS),1)

makedepend.d: $(MMAKE_C_SRCS) $(MMAKE_CXX_SRCS)
	@echo Generating dependencies
	@cscript /nologo $(TOP)/scripts/win/win_makedepend.vbs -X$(MMAKE_OBJ_PREFIX) $(MMAKE_DEPS_C_OPT)  $(filter %.cc,$^) $(filter %.c,$^) >$@_tmp
	@mv $@_tmp $@ #we move so that if above step fails we don't leave a partly generated .d file around

else
MMAKE_DEPS_C_OPT:=-nostdinc -Y. 

makedepend.d: $(MMAKE_C_SRCS) $(MMAKE_CXX_SRCS)
	@echo Generating dependencies
	@makedepend -f-  -- $(MMAKE_DEPS_C_OPT) -- $(filter %.cc,$^) $(filter %.c,$^)  2>/dev/null |    \
	 sed 's/^.*[/]\([^/]*\)\.o[ :]*/$(MMAKE_OBJ_PREFIX)\1.o $@ : /g' >$@

endif




ifneq ($(strip $(MMAKE_C_SRCS)$(MMAKE_CXX_SRCS)),)
sinclude makedepend.d
endif

else  # ifdef USE_MAKEDEPEND

ifndef MMAKE_USE_KBUILD
%.d: %.c
	@set -e; gcc $(mmake_c_compile) -M $< 2>/dev/null |    \
	 sed 's/\($*\)\.o[ :]*/$(MMAKE_OBJ_PREFIX)\1.o $@ : /g' >$@
	@[ -s $@ ] || rm -f $@

%.d: %.cc
	@set -e; g++ $(mmake_cxx_compile) -M $< 2>/dev/null |  \
	 sed 's/\($*\)\.o[ :]*/$(MMAKE_OBJ_PREFIX)\1.o $@ : /g' >$@
	@[ -s $@ ] || rm -f $@

ifneq ($(MMAKE_C_SRCS),)
sinclude $(subst .c,.d,$(MMAKE_C_SRCS))
endif

ifneq ($(MMAKE_CXX_SRCS),)
sinclude $(subst .cc,.d,$(MMAKE_CXX_SRCS))
endif

ifneq ($(MMAKE_DBI_SRCS),)
sinclude $(subst .dbi,.d,$(MMAKE_DBI_SRCS))
endif


endif  # ifdef MMAKE_USE_KBUILD

endif  # ifdef USE_MAKEDEPEND

endif  # ifneq ($(MAKECMDGOALS),clean)
endif  # ifneq ($(MAKECMDGOALS),clean_desttree)
endif  # ifndef MMAKE_NO_DEPS


######################################################################
# Some targets.
#
.PHONY: lndir
lndir:
	lndir "$(TOP)/$(CURRENT)"

.PHONY: force
force: clean
	$(MAKE) all

.PRECIOUS: $(MMAKE_PRECIOUS)

.PHONY: relink
relink:
	rm -f $(TARGET) $(TARGETS); $(MAKE) $(TARGET) $(TARGETS)


######################################################################
# Misc stuff to help various scripts.
#

# For mmakebuildtree
.PHONY: buildtree
buildtree:
	@mmakebuildtree_gen
	@cd "$(TOP)/$(CURRENT)" && for dir in $(SUBDIRS) $(OTHER_SUBDIRS) ""; do if [ -d "$$dir" ]; then echo "$$dir"; fi; done

.PHONY: echo_subdirs
echo_subdirs:
	@cd "$(TOP)/$(CURRENT)" && for dir in $(SUBDIRS) $(OTHER_SUBDIRS) ""; do if [ -d "$$dir" ]; then echo "$$dir"; fi; done

# For mmakerelease
.PHONY: echo_targets
echo_targets:
	@echo $(TARGETS) $(TARGET)

.PHONY: world
world: all

