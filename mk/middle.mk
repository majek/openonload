
####################################################################################
####################################################################################
# Now we figure out whether we invoke make now or switch to the build tree (in the case of local builds)

INCLUDE_REST_OF_MAKE:=0

ifneq ($(MMAKEBUILDTREE),1) # then we are compiling

#############################################################################
# Remote Builds
ifeq ($(REMOTEBUILDFLAG),1)

ifeq ($(BUILDHOST),$(buildhost))

INCLUDE_REST_OF_MAKE:=1

else

ifeq ($(MAKECMDGOALS),clean_desttree) # if make goal is special goal "clean_desttree", then do make clean in this context

.PHONY: clean_desttree

clean_desttree: clean

INCLUDE_REST_OF_MAKE:=1

else
ifeq ($(ISDOING_DESTCLEAN),1) 
INCLUDE_REST_OF_MAKE:=1
else

.PHONY: _do_sync
.PHONY: _domake_cmd
.PHONY: _do_syncback
.PHONY: _domake_cmd_no_sync

######################################################################
# make command-line argument to provide remote rsync machine with its
# own version of the destination path
ifeq ($(DESTFLAG),1)
SET_RDESTPATH=DESTPATH=/rsync$(DESTPATH)
else
SET_RDESTPATH=
endif

##########################################################################
#keep this list upto date, as it really improves performance of rsync
TOHOST_EXCLUDES= --exclude "CVS/" \
                 --exclude ".hg/" \
                 --exclude "scripts/py/"  \
                 --exclude "scripts/benchmark/" \
                 --exclude "scripts/cluster-scripts/" \
                 --exclude "scripts/efabdailytest/" \
                 --exclude "scripts/iscsi/" \
                 --exclude "scripts/runapp.d/" \
                 --exclude "scripts/rpmbuild/" \
                 --exclude "scripts/reboot/" \
                 --exclude "scripts/launchers/" \
                 --exclude "scripts/profiling/" \
                 --exclude "scripts/ANVL/" \
                 --exclude "scripts/rpm/" \
		 --exclude "src/tools/discover/" \
		 --exclude "src/tools/tinderbox2/" \
                 --exclude ".*" \
                 --exclude "*.ncb"

ifeq ($(MAKE_NO_SYNC_TO_HOST),1)

_do_sync:
	@echo SKILLPING RSync to $(BUILDHOST)

else


ERROR_SYNC_BACK_CMD:=|| (echo RSync logs from $(BUILDHOST) && RSYNC_PROXY= rsync  --include "*.log" --include "*.err" --include "*.wrn" --include "*.xml" --exclude "*" $(BUILDHOST)::rbuild$(BUILDPATH)/$(THISDIR)/* . && false)

_do_sync:
	@echo RSync to $(BUILDHOST)...
	@echo ...src
	@RSYNC_PROXY= rsync -L -R -t -r -p --delete --exclude ".#*" $(TOHOST_EXCLUDES) $(TOPPATH)/src $(TOPPATH)/mk $(TOPPATH)/scripts $(BUILDHOST)::rbuild
	@echo ...build
	@RSYNC_PROXY= rsync -t -r -C --exclude "*.exe" --exclude "*.pdb" --exclude "*.dll" --exclude "*.so"  --exclude "*.sys" $(BUILDPATH) $(BUILDHOST)::rbuild$(TOPPATH)/build
ifneq ($(MMAKE_DISTFILES)$(MMAKE_FIRMWARE),)
	@echo ...distfiles and firmware
	@RSYNC_PROXY= rsync -L -R -t -r -p --delete --exclude ".hg/" `cd $(MMAKE_DISTFILES); pwd` `cd $(MMAKE_FIRMWARE); pwd` $(BUILDHOST)::rbuild
endif
	@echo ...DONE

endif

_do_syncback: _domake_cmd
	@echo RSync from $(BUILDHOST)...
	@RSYNC_PROXY= rsync -t -r --exclude "*.o" --exclude "*.h" --exclude "*.c" --exclude "*.cpp" --exclude "*.d" $(BUILDHOST)::rbuild$(BUILDPATH)/$(THISDIR)/* .
	@echo ...DONE

_domake_cmd: _do_sync
	@chmod 600 $(TOPPATH)/mk/site/rsync.key
	@ssh -i $(TOPPATH)/mk/site/rsync.key rsync@$(BUILDHOST) bash -l -c "'$(MAKE) -C /rsync$(BUILDPATH)/$(THISDIR) $(SET_RDESTPATH) $(MAKECMDGOALS)'" $(ERROR_SYNC_BACK_CMD)

_domake_cmd_no_sync: 
	@chmod 600 $(TOPPATH)/mk/site/rsync.key
	@ssh -i $(TOPPATH)/mk/site/rsync.key rsync@$(BUILDHOST) bash -l -c "'$(MAKE) -C /rsync$(BUILDPATH)/$(THISDIR) $(SET_RDESTPATH) $(MAKECMDGOALS)'"

ifeq ($(MAKECMDGOALS),clean)

ISDOING_DESTCLEAN=1

clean: _domake_cmd_no_sync
	$(MAKE)  clean_desttree ISDOING_DESTCLEAN=$(ISDOING_DESTCLEAN)

else
ifneq ($(MAKECMDGOALS),)
.PHONY: $(MAKECMDGOALS) _domake_cmd


$(MAKECMDGOALS): _do_syncback
	@true

endif
endif


all: _do_syncback
	@true


endif #ISDOING_DESTCLEAN
endif

endif

else
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
