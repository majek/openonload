
CC	:= mpicc
CFLAGS	:= -Wall -g $(INCLUDES)
CXX	:= mpiCC
CXXFLAGS:= $(CFLAGS)
LIBS    := $(addprefix -L,$(dir $(LIBS))) $(addprefix -l,$(notdir $(basename $(LIBS))))

%: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ $(LIBS) -o $@

