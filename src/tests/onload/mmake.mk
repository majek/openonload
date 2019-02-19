SUBDIRS	:= wire_order tproxy_preload woda_preload hwtimestamping oof \
           sync_preload l3xudp_preload onload_remote_monitor

OTHER_SUBDIRS	:= titchy_proxy thttp cplane_unit cplane_sysunit

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

