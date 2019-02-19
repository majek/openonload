
APPS := orm_json

SRCS := orm_json

OBJS := $(patsubst %,%.o,$(SRCS))

MMAKE_LIB_DEPS	:= $(CIIP_LIB_DEPEND) $(CIAPP_LIB_DEPEND) \
		   $(CIUL_LIB_DEPEND) $(CITOOLS_LIB_DEPEND) \
		   $(CPLANE_LIB_DEPEND)

MMAKE_LIBS	:= $(LINK_CIIP_LIB) $(LINK_CIAPP_LIB) \
		   $(LINK_CIUL_LIB) $(LINK_CITOOLS_LIB) \
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
