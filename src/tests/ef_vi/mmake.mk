
EFSEND_APPS := efsend efsend_pio efsend_timestamping efsend_pio_warm
TEST_APPS	:= efforward efrss efsink \
		   efsink_packed efforward_packed eflatency stats \
		   efjumborx $(EFSEND_APPS)
ifeq (${PLATFORM},gnu_x86_64)
TEST_APPS	+= efdelegated_server efdelegated_client
endif

TARGETS		:= $(TEST_APPS:%=$(AppPattern))


MMAKE_LIBS	:= $(LINK_CIUL_LIB)
MMAKE_LIB_DEPS	:= $(CIUL_LIB_DEPEND)


all: $(TARGETS)

clean:
	@$(MakeClean)


eflatency: eflatency.o utils.o

$(EFSEND_APPS): utils.o efsend_common.o

efsink: efsink.o utils.o

efjumborx: efjumborx.o utils.o

efsink_packed: efsink_packed.o utils.o

efforward_packed: efforward_packed.o utils.o

efpingpong: MMAKE_LIBS     += $(LINK_CITOOLS_LIB)
efpingpong: MMAKE_LIB_DEPS += $(CITOOLS_LIB_DEPEND)

efdelegated_server: efdelegated_server.o utils.o
efdelegated_server: MMAKE_LIBS     += $(LINK_ONLOAD_EXT_LIB)
efdelegated_server: MMAKE_LIB_DEPS += $(ONLOAD_EXT_LIB_DEPEND)
efdelegated_client: efdelegated_client.o utils.o
efdelegated_client: MMAKE_LIBS     += $(LINK_ONLOAD_EXT_LIB)
efdelegated_client: MMAKE_LIB_DEPS += $(ONLOAD_EXT_LIB_DEPEND)

$(EFSEND_APPS): MMAKE_LIBS += $(LINK_CITOOLS_LIB)
$(EFSEND_APPS): MMAKE_LIB_DEPS += $(CITOOLS_LIB_DEPEND)

eflatency: MMAKE_LIBS     += $(LINK_CITOOLS_LIB)
eflatency: MMAKE_LIB_DEPS += $(CITOOLS_LIB_DEPEND)

stats: stats.py
	cp $< $@
