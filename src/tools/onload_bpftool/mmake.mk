# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
APPS := onload_bpftool

TARGETS	:= $(APPS:%=$(AppPattern))

BPFTOOL_OBJS := bpftool.o

MMAKE_INCLUDE := $(MMAKE_INCLUDE) \
                 -I$(TOP)/src/lib/bpf/bpfimpl/kernel/bpf_include/uapi \
                 -I$(TOP)/src/lib/bpf/bpfimpl/kernel_replace/stub_include

onload_bpftool := $(patsubst %,$(AppPattern),onload_bpftool)

MMAKE_LIBS	:= $(LINK_BPFINTF_LIB) $(LINK_BPFIMPL_LIB) \
               $(LINK_KCOMPAT_LIB) $(LINK_CITOOLS_LIB)
MMAKE_LIB_DEPS	:= $(BPFINTF_LIB_DEPEND) $(BPFIMPL_LIB_DEPEND) \
                   $(KCOMPAT_LIB_DEPEND) $(CITOOLS_LIB_DEPEND)

ifeq ($(HAVE_LIBELF),1)
MMAKE_LIBS += -lelf
endif

$(onload_bpftool): $(BPFTOOL_OBJS) $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp))

all: $(TARGETS)
clean:
	rm -f *.o $(TARGETS)
