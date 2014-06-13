
SUBDIRS		:= citools ciapp efhwdef

ifeq ($(DRIVER_TYPE),ndis)
SUBDIRS         += transport
DRIVER_SUBDIRS	:= citools ciul efthrm transport sfgpxe
endif

ifeq ($(DRIVER_TYPE),iscsi)
DRIVER_SUBDIRS	:= citools iscsi sfgpxe
endif

ifeq ($(DRIVER_TYPE),wlh)
DRIVER_SUBDIRS	:= 3rdparty win sfgpxe
endif

ifeq ($(DRIVER_TYPE),wlh_chimney)
DRIVER_SUBDIRS	:= 3rdparty win sfgpxe
endif

ifeq ($(DRIVER_TYPE),win7)
DRIVER_SUBDIRS	:= 3rdparty win sfgpxe
endif

ifeq ($(DRIVER_TYPE),win7_chimney)
DRIVER_SUBDIRS	:= 3rdparty win sfgpxe
endif

ifeq ($(DRIVER_TYPE),wnet)
DRIVER_SUBDIRS	:= 3rdparty win sfgpxe
endif

ifeq ($(DRIVER_TYPE),wxp)
DRIVER_SUBDIRS	:= 3rdparty win sfgpxe
endif

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

ifeq ($(WINDOWS),1)
#Might need this to be more general in future, but atm Windows only
SUBDIRS		:= citools ciapp efhwdef
OTHER_SUBDIRS   := 3rdparty win
endif


all:
	+@(export MMAKE_NO_CSTYLE=1; $(MakeSubdirs))

clean:
	@$(MakeClean)

