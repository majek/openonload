##############################################################################
#
# Support for building the aoe driver as part of the L5 build system. See 
# the Makefile for building it standalone.
#

# The Kbuild link should override the mmake-generated Makefile, but
# Linux <2.6.10 does not look for that.  Do nothing if included by
# Kbuild.
ifndef MMAKE_IN_KBUILD

CONFIG_FILES := config.h autocompat.h

export CONFIG_SFC_AOE := y

ifdef NOWERROR
EXTRA_MAKEFLAGS += NOWERROR=1
endif
ifdef MMAKE_LIBERAL
EXTRA_MAKEFLAGS += NOWERROR=1
endif

ifdef EFX_NOT_EXPORTED
EXTRA_MAKEFLAGS += EFX_NOT_EXPORTED=1
endif

ifneq ($(CC),)
EXTRA_MAKEFLAGS += CC=$(CC)
endif

unexport NDEBUG

all: $(BUILDPATH)/driver/linux_aoe/Module.symvers kbuild

$(BUILDPATH)/driver/linux_aoe/Module.symvers: $(BUILDPATH)/driver/linux_net/Module.symvers
	cp $< $@
	@ if test -f $(BUILDPATH)/driver/linux_net/Modules.symvers; then \
		cp $(BUILDPATH)/driver/linux_net/Modules.symvers $(BUILDPATH)/driver/linux_aoe/Modules.symvers; \
	fi

kbuild:
	@if ! [ -h $(CURDIR)/Kbuild ]; then				\
		echo "  UPD     Kbuild";				\
		ln -sf $(SRCPATH)/driver/linux_aoe/Makefile $(CURDIR)/Kbuild; \
	fi
	$(MMAKE_KBUILD_PRE_COMMAND)
	$(MAKE) $(EXTRA_MAKEFLAGS) $(MMAKE_KBUILD_ARGS) M=$(CURDIR) NDEBUG=$(NDEBUG)
	$(MMAKE_KBUILD_POST_COMMAND)
	@if [ -e $(CURDIR)/sfc_aoe.ko ]; then \
		cp -f sfc_aoe.ko $(DESTPATH)/driver/linux; \
	fi
	@if [ -e $(CURDIR)/sfc_aoe_sim.ko ]; then \
		cp -f sfc_aoe_sim.ko $(DESTPATH)/driver/linux; \
	fi

clean:
	@$(MakeClean)
	rm -rf *.ko Module.symvers Modules.symvers *.mod.c .tmp_versions .*.cmd $(CONFIG_FILES)

else

.PHONY : $(DRIVER_SUBDIRS)

endif # !MMAKE_IN_KBUILD
