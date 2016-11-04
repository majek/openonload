SUBDIRS	:= wire_order tproxy_preload woda_preload hwtimestamping


ifeq ($(BUILDORM),1)
SUBDIRS += onload_remote_monitor
endif

OTHER_SUBDIRS	:= titchy_proxy thttp

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

