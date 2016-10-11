
TEST_APPS	:= rtt
TARGETS		:= $(TEST_APPS:%=$(AppPattern))


all: $(TARGETS)

clean:
	@$(MakeClean)


MMAKE_LIBS	:= $(LINK_CIUL_LIB) $(LINK_CIAPP_LIB) $(LINK_CITOOLS_LIB)
MMAKE_LIB_DEPS	:= $(CIUL_LIB_DEPEND) $(CIAPP_LIB_DEPEND) $(CITOOLS_LIB_DEPEND)


rtt: rtt.o rtt_socket.o rtt_efvi.o
