# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

####################################################################################
####################################################################################
# Now we figure out whether we invoke make now or switch to the build tree (in the case of local builds)

INCLUDE_REST_OF_MAKE:=0

ifneq ($(MMAKEBUILDTREE),1) # then we are compiling

#############################################################################
# NON Remote Builds

ifeq ($(BUILDFLAG),0)  # then we have been invoked from the dest tree

ifeq ($(MAKECMDGOALS),clean_desttree) # if make goal is special goal "clean_desttree", then do make clean in this context

.PHONY: clean_desttree

clean_desttree: clean

INCLUDE_REST_OF_MAKE:=1

else
ifeq ($(ISDOING_DESTCLEAN),1) 
INCLUDE_REST_OF_MAKE:=1

else # ISDOING_DESTCLEAN!=0
     # if make goal is special goal NOT "clean_desttree" (usual case), 
     # then redirect make operations to build tree


ifneq ($(MAKECMDGOALS),)
.PHONY: $(MAKECMDGOALS) _domake_cmd

_domake_cmd:
	$(MAKE) -C $(BUILDPATH)/$(THISDIR)  $(MAKECMDGOALS)

$(MAKECMDGOALS): _domake_cmd
	@true

endif #MAKECMDGOALS cmp clean_desttree

all: 
	$(MAKE) -C $(BUILDPATH)/$(THISDIR)


endif #MAKECMDGOALS not NULL
endif #ISDOING_DESTCLEAN

else # then we have been invoked from the build tree

INCLUDE_REST_OF_MAKE:=1

####################################################################################
# If we are "make clean" then invoke make clean in dest tree
# we invoke it using a special target clean_desttree and pass in a variable
# this stops it jumping back into the build tree clean (i.e. a make clean in the
# dest tree normally jumps us into make clean in the build tree)
ifeq ($(MAKECMDGOALS),clean)
ifeq ($(DESTFLAG),0)


ifneq ($(ISDOING_DESTCLEAN),1) # we need a flag to do this only ONCE
ISDOING_DESTCLEAN:=1
dummy:=$(shell $(MAKE) -C $(DESTPATH)/$(THISDIR) clean_desttree ISDOING_DESTCLEAN=$(ISDOING_DESTCLEAN))
endif
endif
endif

endif

else # then we are creating the tree

INCLUDE_REST_OF_MAKE:=1

endif

####################################################################################
####################################################################################

ifeq ($(INCLUDE_REST_OF_MAKE),1)
include $(TOP)/$(CURRENT)/mmake.mk
include $(TOP)/mk/after.mk
endif
