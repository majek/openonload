######################################################################
# Make the key variables globally visible.
#
export TOP
export TOPPATH
export BUILD
export BUILDFLAG
export DESTFLAG
export BUILDPATH
export DESTPATH
export CURRENT
export THISDIR
export PLATFORM
export VPATH
export VPATH_ENABLED
export SUBDIRS
export IMPORT
export BUILD_TREE_COPY
export DRIVER
export DRIVER_TYPE
export DRIVER_SIZE
export ISDOING_DESTCLEAN
export MAKE_SANITY_DONE
export MAKEWORLD
export INSTALLER
export OFE_TREE

# Ensure these environment variables are not inherited.
cflags :=
cppflags :=
cxxflags :=
export cflags
export cppflags
export cxxflags


######################################################################
# temporary set up for migration of old build trees
ifndef DESTFLAG
#$(warning you are advised to rerun top level mmakebuildtree)
DESTFLAG=1
BUILDFLAG=1
DESTPATH=$(BUILDPATH)
endif


######################################################################
# Cancel some built-in rules.
#
%.o: %.c
%.o: %.cc
%:   %.c
%:   %.cc
%:   %.o


######################################################################
# Include directories.
#
MMAKE_INCLUDE_DIR	:= $(TOP)/src/include
MMAKE_INCLUDE		:= -I. -I$(BUILD)/include -I$(MMAKE_INCLUDE_DIR)



######################################################################
# Some useful commands.
#
SUBDIRS	:=
DRIVER_SUBDIRS :=
INSTALLER_SUBDIRS :=

define MakeAllSubdirs
([ "$$subdirs" = "" ] && subdirs='$(SUBDIRS) $(OTHER_SUBDIRS)'; \
 [ "$$target" = "" ]  && target='$@'; \
 for d in $$subdirs ; do \
   [ ! -d "$$d" ] || $(MAKE) -C "$$d" $(passthruparams) "$$target" || exit ; done \
)
endef

ifeq ($(MAKECMDGOALS),world)

MAKEWORLD:=1

endif

ifeq ($(MAKEWORLD),1)

MakeSubdirs=$(MakeAllSubdirs)

else 

define MakeSubdirs
([ "$$subdirs" = "" ] && subdirs='$(SUBDIRS)'; \
 [ "$$target" = "" ]  && target='$@'; \
 for d in $$subdirs ; do \
   [ ! -d "$$d" ] || $(MAKE) -C "$$d" $(passthruparams) "$$target" || exit ; done \
)
endef

endif


define MakeClean
rm -f *.a *.so *.o *.ko *.d *.lib *.dll *.exp *.pdb $(TARGET) $(TARGETS); $(MakeAllSubdirs)
endef


######################################################################
# Misc.
#

# Other makefiles may define rules before we get to the makefile in the
# directory, but we don't want them to be the default!
default_all:	all

.PHONY: all clean lib default buildtree

# Do not delete intermediates (needed for dependancy checks).
.SECONDARY:

nullstring:=
space=$(nullstring) #<-do not edit this line

######################################################################
# DO_COPY_TARGET
#
# Set up do copy target; this is used when local build option is used
# if local build option is NOT used then this function becomes a noop

DO_COPY_TARGET=

ifeq ($(BUILDFLAG)$(DESTFLAG),10)
DO_COPY_TARGET=cp $(1) $(DESTPATH)/$(THISDIR);
endif

_BUILDFLAG:=$(BUILDFLAG)

######################################################################
# BUILD TREE local build sanity check
ifeq ($(REMOTEBUILDFLAG),1)
buildhost=$(shell uname -n)
endif

ifeq ($(BUILDFLAG)$(DESTFLAG),01)

buildhost=$(shell uname -n)
ifneq ($(BUILDHOST),$(buildhost))
$(error "Cannot do a local build for host $(BUILDHOST). You are on $(buildhost)" )
endif

endif

######################################################################
# Function to convert cygwin to dos name
ifdef MMAKE_USE_CYGPATH
TODOSNAME=$(if $(filter-out .,$(1)),$(shell cygpath -w $(1)),$(1))
else
TODOSNAMEs2=$(subst /, ,$(patsubst /cygdrive/%,%,$(1)))
TODOSNAMEs1=$(subst $(space),\\,$(firstword $(call TODOSNAMEs2,$(1))): $(wordlist 2,$(words $(call TODOSNAMEs2,$(1))),$(call TODOSNAMEs2,$(1))))
TODOSNAME=$(if $(findstring cygdrive,$(subst /, ,$(1))),$(call TODOSNAMEs1,$(1)),$(1))
endif

TOOSNAMES=$(foreach var,$(1),$(call TODOSNAME,$(var)))

######################################################################
# Function to convert Dosname to cygwin name

FROMDOSNAMESs2=$(subst *,\ ,$(subst $(space),/,$(patsubst %:,/cygdrive %,$(subst \, ,$(1)))))
FROMDOSNAMESs1=$(subst ;, ,$(subst $(space),*,$(1)))

# arg 1=list of dos absolute paths,
# arg 2=optional prefix to place on each path
#example "\$(call FROMDOSNAMES,$(INCLUDE),-I)"
FROMDOSNAMES=$(foreach v,$(call FROMDOSNAMESs1,$(1)),$(2)$(call FROMDOSNAMESs2,$(v)))

######################################################################
# Function to convert Dospath to cygwin path

FROMDOSPATHs2=$(subst *, ,$(subst $(space),/,$(patsubst %:,/cygdrive %,$(subst \, ,$(1)))))
FROMDOSPATHs1=$(subst ;, ,$(subst $(space),*,$(1)))

# arg 1=list of dos absolute paths,
# arg 2=optional prefix to place on each path
#example "\$(call FROMDOSPATH,$(INCLUDE),-I)"
FROMDOSPATH=$(foreach v,$(call FROMDOSPATHs1,$(1)),$(2)$(call FROMDOSPATHs2,$(v)))

