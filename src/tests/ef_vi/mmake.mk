
TEST_APPS	:= efpingpong efforward efrss efsink efpio eftap

TARGETS		:= $(TEST_APPS:%=$(AppPattern))


MMAKE_LIBS	:= $(LINK_CIUL_LIB)
MMAKE_LIB_DEPS	:= $(CIUL_LIB_DEPEND)


all: $(TARGETS)

clean:
	@$(MakeClean)


efforward: efforward.o efvi_sfw.o

efrss: efrss.o efvi_sfw.o

efsink: efsink.o efvi_sfw.o

efpingpong: MMAKE_LIBS     += $(LINK_CITOOLS_LIB)
efpingpong: MMAKE_LIB_DEPS += $(CITOOLS_LIB_DEPEND)

efpio: MMAKE_LIBS     += $(LINK_CITOOLS_LIB)
efpio: MMAKE_LIB_DEPS += $(CITOOLS_LIB_DEPEND)

eftap: MMAKE_LIBS     += $(LINK_CITOOLS_LIB)
eftap: MMAKE_LIB_DEPS += $(CITOOLS_LIB_DEPEND)
