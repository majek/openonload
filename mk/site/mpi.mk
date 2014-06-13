
ifeq ($(WINDOWS),1)

######################################################################
### Includes Command Line Transform
TODOSNAME=$(if $(filter-out .,$(1)),$(shell cygpath -w $(1)),$(1))
COMMANDLINETRANSFORMs1=$(if $(filter -I%,$(1)),'/I$(call TODOSNAME,$(patsubst -I%,%,$(1)))',$(1))
COMMANDLINETRANSFORM=$(foreach var,$(1),$(call COMMANDLINETRANSFORMs1,$(var)))


CFLAGS  +=$(call COMMANDLINETRANSFORM,$(INCLUDES))
LIBS    := $(foreach var,$(LIBS),'$(call TODOSNAME,$(basename $(var)).lib)')

%: %.c
	$(CC)  /nologo $(CFLAGS) $(CPPFLAGS) $^ $(LIBS) $(BASELIBS)

else

CC	:= mpicc
CFLAGS	:= -Wall -g $(INCLUDES)
CXX	:= mpiCC
CXXFLAGS:= $(CFLAGS)
LIBS    := $(addprefix -L,$(dir $(LIBS))) $(addprefix -l,$(notdir $(basename $(LIBS))))

%: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ $(LIBS) -o $@

endif
