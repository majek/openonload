VPATH_ENABLED:=1

CUSTOMER_EVENT_LOG_FILES:= $(TOP)/$(CURRENT)/ci/tools/customer_event_log_msgs.mcc \
                           $(TOP)/$(CURRENT)/ci/tools/customer_event_log_gendefs.h

ifneq ($(MMAKEBUILDTREE),1)
ifeq ($(WINDOWS),1)

EXTRA_CLEANS:=*.def *.rc *.mc *.mc_utf8


#CPREPROC_CMD:=cpp -P -I$(TOP)/$(CURRENT) 
CPREPROC_CMD:=cl /EP '-I$(shell cygpath -w $(TOP)/$(CURRENT))'


customer_event_log_msgs.h: $(CUSTOMER_EVENT_LOG_FILES)
	@echo make event log headers
	@$(CPREPROC_CMD) -DMCC_MC_FILE '$(shell cygpath -w $(filter %.mcc,$^))' | dos2unix | grep ".\+"  | sed 's/[ ]*!NL/\n/g' > customer_event_log_msgs.mc_utf8
	$(MMAKE_DISTFILES)/mk_win/utf8tounicode customer_event_log_msgs.mc_utf8 customer_event_log_msgs.mc
	$(MC) -u -U customer_event_log_msgs.mc
	-@rm customer_event_log_msgs.mc_utf8 customer_event_log_msgs.mc

customer_event_log_msgs.i: $(CUSTOMER_EVENT_LOG_FILES)
	@$(CPREPROC_CMD) -DMCC_FORMAT_CAT_FILE1 -DWINDOWS=$(WINDOWS) -DDRIVER=$(DRIVER) '$(shell cygpath -w $(filter %.mcc,$^))'  | dos2unix | grep ".\+"  | sed 's/[ ]*!NL/\n/g' | sed 's/[ ]*!HS/#/g' > customer_event_log_msgs.i
	@$(CPREPROC_CMD) -DMCC_FORMAT_CAT_FILE2 -DWINDOWS=$(WINDOWS) -DDRIVER=$(DRIVER) '$(shell cygpath -w $(filter %.mcc,$^))'  | dos2unix | grep ".\+"  | sed 's/[ ]*!NL/\n/g' | sed 's/[ ]*!HS/#/g' >> customer_event_log_msgs.i


else

sed_backslash:=\

define sed_nl_pattern
sed -f $(TOP)/scripts/sh/customer_event_log_nl.sed
endef


WINDOWS:=0
customer_event_log_msgs.h: $(CUSTOMER_EVENT_LOG_FILES)
	cpp -P -I$(TOP)/$(CURRENT) -DMCC_H_FILE $(filter %.mcc,$^)  | grep -v '^$$'  | $(sed_nl_pattern) | sed 's/[ ]*!HS/#/g' > customer_event_log_msgs.h


customer_event_log_msgs.i: $(CUSTOMER_EVENT_LOG_FILES)
	cpp -P -I$(TOP)/$(CURRENT) -DMCC_FORMAT_CAT_FILE1 -DWINDOWS=$(WINDOWS) -DDRIVER=$(DRIVER) $(filter %.mcc,$^)  | grep -v '^$$'  | $(sed_nl_pattern) | sed 's/[ ]*!HS/#/g' > customer_event_log_msgs.i_tmp
	cpp -P -I$(TOP)/$(CURRENT) -DMCC_FORMAT_CAT_FILE1_STAGE2 -DWINDOWS=$(WINDOWS) -DDRIVER=$(DRIVER) customer_event_log_msgs.i_tmp  | grep -v '^$$'  | $(sed_nl_pattern) | sed 's/[ ]*!HS/#/g' | sed 's/[ ]*!CC[ ]*//g' > customer_event_log_msgs.i
	cpp -P -I$(TOP)/$(CURRENT) -DMCC_FORMAT_CAT_FILE2 -DWINDOWS=$(WINDOWS) -DDRIVER=$(DRIVER) $(filter %.mcc,$^)  | grep -v '^$$'  | $(sed_nl_pattern) | sed 's/[ ]*!HS/#/g' >> customer_event_log_msgs.i


endif
endif

ifneq ($(DRIVER),1)
DRIVER=0

ifeq ($(WINDOWS),0)
libc_compat.h: $(TOP)/scripts/libc_compat.sh
	CC="${CC}" CFLAGS="${CFLAGS} ${MMAKE_CFLAGS}" $(TOP)/scripts/libc_compat.sh libc_compat.h
all: libc_compat.h
endif
endif


#

all: customer_event_log_msgs.h customer_event_log_msgs.i

_subdirs: all


clean:
	-@rm *.h  *.i $(EXTRA_CLEANS) 2>/dev/null

