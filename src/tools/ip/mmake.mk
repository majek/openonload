APPS	:= onload_stackdump \
           onload_tcpdump.bin \
           onload_fuser


ifneq ($(ONLOAD_ONLY),1)

ifeq ($(WINDOWS),1)
APPS	+= istack \
           locktest           
endif

ifeq ($(GNU),1)
APPS	+= istack \
           iifdump \
           routedump \
           locktest
endif

ifeq ($(LINUX),1)
APPS	+= istack5
endif

endif  # ONLOAD_ONLY


TARGETS	:= $(APPS:%=$(AppPattern))

onload_stackdump:= $(patsubst %,$(AppPattern),onload_stackdump)
istack		:= $(patsubst %,$(AppPattern),istack)
istack5		:= $(patsubst %,$(AppPattern),istack5)
onload_tcpdump.bin := $(patsubst %,$(AppPattern),onload_tcpdump.bin)
onload_fuser	:= $(patsubst %,$(AppPattern),onload_fuser)

MMAKE_LIBS	:= $(LINK_CIIP_LIB) $(LINK_CIAPP_LIB) \
		   $(LINK_CIUL_LIB) $(LINK_CITOOLS_LIB)
MMAKE_LIB_DEPS	:= $(CIIP_LIB_DEPEND) $(CIAPP_LIB_DEPEND) \
		   $(CIUL_LIB_DEPEND) $(CITOOLS_LIB_DEPEND)

MMAKE_FTL_LIBS  := $(LINK_FTL_LIB)
MMAKE_FTL_LIB_DEPS := $(FTL_LIB_DEPEND)

# By default the Level 5 version of istack is identical to the distributed one
MMAKE_L5_FTL_LIBS     := $(LINK_L5_FTL_LIB)
MMAKE_L5_CPPFLAGS     :=
MMAKE_L5_FTL_LIB_DEPS := $(MMAKE_FTL_LIB_DEPS)

# we include readline only in the Level 5 library and only if the environment
# variable USEREADLINE is set to 1 (this way, by default, builds on machines
# which do not incorporate these libraries will still work)
ifneq ($(strip $(USEREADLINE)),)
MMAKE_L5_CPPFLAGS := -DUSE_READLINE
MMAKE_L5_FTL_LIBS := $(LINK_L5_FTL_LIB) -lcurses -lhistory -lreadline
MMAKE_L5_FTL_LIB_DEPS += $(L5_FTL_LIB_DEPEND)
endif

ifeq  ($(shell CC="${CC}" CFLAGS="${CFLAGS} ${MMAKE_CFLAGS}" check_library_presence pcap.h pcap),1)
MMAKE_LIBS_LIBPCAP=-lpcap
endif

all: $(TARGETS)

$(onload_stackdump): stackdump.o libstack.o $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp))

$(istack): istack.o libstack.o $(MMAKE_LIB_DEPS) $(MMAKE_FTL_LIB_DEPS)
	(libs="$(MMAKE_LIBS) $(MMAKE_FTL_LIBS)"; $(MMakeLinkCApp))

$(istack5): istack.o libstack.o $(MMAKE_LIB_DEPS) $(MMAKE_L5_FTL_LIB_DEPS)
	(libs="$(MMAKE_LIBS) $(MMAKE_L5_FTL_LIBS)"; $(MMakeLinkCApp))

$(onload_tcpdump.bin): tcpdump_bin.o libstack.o $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS) $(MMAKE_LIBS_LIBPCAP)"; $(MMakeLinkCApp))

$(onload_fuser): fuser.o $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp))

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
