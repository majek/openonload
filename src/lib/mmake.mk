
SUBDIRS		:= citools ciapp efhwdef

ifeq ($(LINUX),1)
DRIVER_SUBDIRS	:= citools ciul cplane transport
OTHER_SUBDIRS	:= spektor
SUBDIRS		+= sfcaffinity onload_ext fsbc
endif

ifeq ($(GNU),1)
# N.B.: The order matters here.
SUBDIRS		+= ciul
SUBDIRS		+= cplane transport tools
ifndef PREBUILD_ZF
ifeq (${PLATFORM},gnu_x86_64)
ifneq ($(ONLOAD_ONLY),1)
ifneq ($(NO_ZF),1)
SUBDIRS         += zf
endif
endif
endif
endif
endif


all:
	+@(export MMAKE_NO_CSTYLE=1; $(MakeSubdirs))

clean:
	@$(MakeClean)

