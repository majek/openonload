
APPS := orm_json

SRCS := orm_json

OBJS := $(patsubst %,%.o,$(SRCS))

JANSSON_LIB	:= ../jansson-2.7/libjansson.a
JANSSON_LIB_DEP	:= $(JANSSON_LIB)

MMAKE_LIB_DEPS	:= $(CIIP_LIB_DEPEND) $(CIAPP_LIB_DEPEND) \
		   $(CIUL_LIB_DEPEND) $(CITOOLS_LIB_DEPEND) \
		   $(JANSSON_LIB_DEP) $(CPLANE_LIB_DEPEND)

MMAKE_LIBS	:= $(LINK_CIIP_LIB) $(LINK_CIAPP_LIB) \
		   $(LINK_CIUL_LIB) $(LINK_CITOOLS_LIB) \
		   -lpthread $(JANSSON_LIB) $(LINK_CPLANE_LIB)
MMAKE_INCLUDE	+= -I$(TOP)/src/tools/jansson-2.7/src

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
