APPS	:= onload_stackdump \
           onload_tcpdump.bin \
           onload_fuser

ifdef OFE_TREE
APPS	+= onload_fe
endif

ifneq ($(ONLOAD_ONLY),1)

ifeq ($(WINDOWS),1)
APPS	+= locktest           
endif

ifeq ($(GNU),1)
APPS	+= iifdump \
           routedump \
           pio_buddy_test \
           locktest
endif

endif  # ONLOAD_ONLY


TARGETS	:= $(APPS:%=$(AppPattern))

onload_stackdump:= $(patsubst %,$(AppPattern),onload_stackdump)
onload_tcpdump.bin := $(patsubst %,$(AppPattern),onload_tcpdump.bin)
onload_fuser	:= $(patsubst %,$(AppPattern),onload_fuser)
pio_buddy_test	:= $(patsubst %,$(AppPattern),pio_buddy_test)
ifdef OFE_TREE
onload_fe	:= $(patsubst %,$(AppPattern),onload_fe)
endif

MMAKE_LIBS	:= $(LINK_CIIP_LIB) $(LINK_CIAPP_LIB) \
		   $(LINK_CIUL_LIB) $(LINK_CITOOLS_LIB)
MMAKE_LIB_DEPS	:= $(CIIP_LIB_DEPEND) $(CIAPP_LIB_DEPEND) \
		   $(CIUL_LIB_DEPEND) $(CITOOLS_LIB_DEPEND)

MMAKE_STACKDUMP_LIBS := $(LINK_ONLOAD_EXT_LIB)
MMAKE_STACKDUMP_DEPS := $(ONLOAD_EXT_LIB_DEPEND)

# we include readline only in the Level 5 library and only if the environment
# variable USEREADLINE is set to 1 (this way, by default, builds on machines
# which do not incorporate these libraries will still work)
ifneq ($(strip $(USEREADLINE)),)
MMAKE_L5_CPPFLAGS := -DUSE_READLINE
MMAKE_L5_FTL_LIBS := $(LINK_L5_FTL_LIB) -lcurses -lhistory -lreadline
MMAKE_L5_FTL_LIB_DEPS += $(L5_FTL_LIB_DEPEND)
endif

ifeq  ($(shell CC="${CC}" CFLAGS="${CFLAGS} ${MMAKE_CFLAGS}" check_library_presence pcap.h pcap 2>/dev/null),1)
MMAKE_LIBS_LIBPCAP=-lpcap
endif

all: $(TARGETS)

$(onload_stackdump): stackdump.o libstack.o $(MMAKE_LIB_DEPS) $(MMAKE_STACKDUMP_DEPS)
	(libs="$(MMAKE_LIBS) $(MMAKE_STACKDUMP_LIBS)"; $(MMakeLinkCApp))

$(onload_tcpdump.bin): tcpdump_bin.o libstack.o $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS) $(MMAKE_LIBS_LIBPCAP)"; $(MMakeLinkCApp))

$(onload_fuser): fuser.o $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp))

$(pio_buddy_test): pio_buddy_test.o libstack.o $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp))

ifdef OFE_TREE
$(onload_fe): ofe.o libstack.o  $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp))
endif

# These rules may generate a version that uses gnu readline.  We must not
# distribute this because readline is licensed under GPL.
%5.o: %.c ../../tests/cplane/cplane.c
        (cppflags="$(MMAKE_L5_CPPFLAGS)"; $(MMakeCompileC))

clean:
	@$(MakeClean)

ifeq ($(WINDOWS),1)
onload_stackdump.exe : stackdump.res
locktest.exe : locktest.res

## TODO - Wildcard out resource compilation into a generic rule.
stackdump.res : stackdump.rc
	rc /i $(TOP)/src/include /fo $@ /r $?

istack.res : istack.rc
	rc /i $(TOP)/src/include /fo $@ /r $?

locktest.res : locktest.rc
	rc /i $(TOP)/src/include /fo $@ /r $?

endif
