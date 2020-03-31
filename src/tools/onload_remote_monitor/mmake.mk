# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

APPS := orm_json

SRCS := orm_json ../ip/bpf_stub

OBJS := $(patsubst %,%.o,$(SRCS))

MMAKE_LIB_DEPS	:= $(CIIP_LIB_DEPEND) $(CIAPP_LIB_DEPEND) \
		   $(CITOOLS_LIB_DEPEND) $(CIUL_LIB_DEPEND) \
		   $(CPLANE_LIB_DEPEND)

ifeq  ($(shell CC="${CC}" CFLAGS="${CFLAGS} ${MMAKE_CFLAGS}" check_library_presence pcap.h pcap 2>/dev/null),1)
MMAKE_LIBS_LIBPCAP=-lpcap
CFLAGS += -DCI_HAVE_PCAP=1
else
CFLAGS += -DCI_HAVE_PCAP=0
endif

MMAKE_LIBS	:= $(LINK_CIIP_LIB) $(LINK_CIAPP_LIB) $(MMAKE_LIBS_LIBPCAP) \
		   $(LINK_CITOOLS_LIB) $(LINK_CIUL_LIB) \
		   -lpthread $(LINK_CPLANE_LIB)
MMAKE_INCLUDE	+= -I$(TOP)/src/tools/ip

LIBS      += $(MMAKE_LIBS)
INCS      += $(MMAKE_INCLUDE)
DEPS      += $(OBJS) $(MMAKE_LIB_DEPS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCS) -c $< -o $@

all: $(APPS)

orm_json: $(DEPS)
	(libs="$(LIBS)"; $(MMakeLinkCApp))

clean:
	@$(MakeClean)
	rm -f *.o $(APPS)
