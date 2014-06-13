APPS	:= sfcaffinity_tool

TARGETS	:= $(APPS:%=$(AppPattern))


MMAKE_LIBS	:= $(LINK_CIAPP_LIB) $(LINK_CITOOLS_LIB)
MMAKE_LIB_DEPS	:= $(CIAPP_LIB_DEPEND) $(CITOOLS_LIB_DEPEND)


all: $(TARGETS)

clean:
	@$(MakeClean)
