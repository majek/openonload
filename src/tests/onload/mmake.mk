SUBDIRS	:= wire_order tproxy_preload woda_preload hwtimestamping oof \
           sync_preload


ifeq ($(BUILDORM),1)
SUBDIRS += onload_remote_monitor
endif

OTHER_SUBDIRS	:= titchy_proxy thttp cplane_unit cplane_sysunit

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

