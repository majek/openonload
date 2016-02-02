SUBDIRS	:= wire_order tproxy_preload woda_preload
OTHER_SUBDIRS	:= titchy_proxy thttp hwtimestamping

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

