
TEST_APPS	:= efpingpong efforward efrss efsink efpio eftap \
		   efsink_packed efforward_packed \
		   efdelegated_client efdelegated_server

TARGETS		:= $(TEST_APPS:%=$(AppPattern))


MMAKE_LIBS	:= $(LINK_CIUL_LIB)
MMAKE_LIB_DEPS	:= $(CIUL_LIB_DEPEND)


all: $(TARGETS)

clean:
	@$(MakeClean)


efsink: efsink.o utils.o

efsink_packed: efsink_packed.o utils.o

efforward_packed: efforward_packed.o utils.o

efpingpong: MMAKE_LIBS     += $(LINK_CITOOLS_LIB)
efpingpong: MMAKE_LIB_DEPS += $(CITOOLS_LIB_DEPEND)

efdelegated_server: MMAKE_LIBS     += $(LINK_ONLOAD_EXT_LIB)
efdelegated_server: MMAKE_LIB_DEPS += $(ONLOAD_EXT_LIB_DEPEND)

efpio: MMAKE_LIBS     += $(LINK_CITOOLS_LIB)
efpio: MMAKE_LIB_DEPS += $(CITOOLS_LIB_DEPEND)

eftap: MMAKE_LIBS     += $(LINK_CITOOLS_LIB)
eftap: MMAKE_LIB_DEPS += $(CITOOLS_LIB_DEPEND)
