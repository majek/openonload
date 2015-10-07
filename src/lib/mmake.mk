
SUBDIRS		:= citools ciapp efhwdef

ifeq ($(LINUX),1)
DRIVER_SUBDIRS	:= citools ciul transport efabcfg
OTHER_SUBDIRS	:= spektor
SUBDIRS		+= sfcaffinity sfgpxe onload_ext fsbc
endif

ifeq ($(SOLARIS),1)
SUBDIRS		:= sfgpxe
# libcitools; particularly sysdep.h does not have sparcv9 support at present
ifneq ($(ISA),sparcv9)
SUBDIRS		+= citools ciapp efhwdef
endif
endif

ifeq ($(GNU),1)
SUBDIRS		+= ciul efabcfg transport tools 
endif


all:
	+@(export MMAKE_NO_CSTYLE=1; $(MakeSubdirs))

clean:
	@$(MakeClean)

