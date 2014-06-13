
TARGET		:= $(FTL_LIB) $(L5_FTL_LIB)

LIB_SRCS	:= libftl.c

LIB_OBJS	 := $(LIB_SRCS:%.c=$(MMAKE_OBJ_PREFIX)%.o)
L5_LIB_OBJS	 := $(LIB_SRCS:%.c=$(MMAKE_OBJ_PREFIX)%5.o)


# we include readline only in the Level 5 library and only if the environment
# variable USEREADLINE is set to 1 (this way, by default, builds on machines
# which do not incorporate these libraries will still work)
ifeq ($(LINUX),1)
ifneq ($(strip $(USEREADLINE)),)
MMAKE_LIBS      += -lcurses -lhistory -lreadline 
L5_CPPFLAGS     += -DUSE_READLINE
endif
endif
# unfortunately we can't use MMAKE_LIBS in any of our make rules to create a
# library - so we need to do the above in any *.mk file that requires this
# library

ifndef MMAKE_NO_RULES

all: $(TARGET)

lib: $(TARGET)

clean:
	@$(MakeClean)

$(FTL_LIB): $(LIB_OBJS)
	$(MMakeLinkStaticLib)

# These rules may generate a version that uses gnu readline.  We must not 
# distribute this because readline is licensed under GPL.
LIB_OBJS	 := $(L5_LIB_OBJS)

$(L5_LIB_OBJS): $(LIB_SRCS)
	(cppflags="$(L5_CPPFLAGS)"; $(MMakeCompileC))

$(L5_FTL_LIB):  $(L5_LIB_OBJS)
	$(MMakeLinkStaticLib)


endif
