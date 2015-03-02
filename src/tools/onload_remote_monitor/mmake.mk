
APPS := orm_json

SRCS := orm_json

OBJS := $(patsubst %,%.o,$(SRCS))

JANSSON_LIB	:= ../jansson-2.7/libjansson.a
JANSSON_LIB_DEP	:= $(JANSSON_LIB)

MMAKE_LIB_DEPS	:= $(CIIP_LIB_DEPEND) $(CIUL_LIB_DEPEND) $(CITOOLS_LIB_DEPEND) \
		   $(JANSSON_LIB_DEP)

MMAKE_LIBS	:= $(LINK_CIIP_LIB) $(LINK_CIUL_LIB) $(LINK_CITOOLS_LIB) \
		   -lpthread $(JANSSON_LIB)
MMAKE_INCLUDE	+= -I$(TOP)/src/tools/jansson-2.7/src

LIBS      += $(MMAKE_LIBS)
INCS      += $(MMAKE_INCLUDE)
DEPS      += $(OBJS) $(MMAKE_LIB_DEPS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCS) -c $< -o $@


# Current jansson build does not build 32 bits library on 64 bits
# system so we disallow building on 32 bits all together.
buildplatform=$(shell mmaketool --buildplatform)
BUILD_ORM := 0
ifeq ($(buildplatform),gnu_x86_64)
BUILD_ORM := 1
endif
ifeq ($(buildplatform),gnu_ppc64)
BUILD_ORM := 1
endif

ifeq ($(BUILD_ORM),1)
all: $(APPS)
else
all:
endif

orm_json: $(DEPS)
	$(CC) -g -Wl,-E $^ $(LIBS) -o $@

clean:
	@$(MakeClean)
	rm -f *.o $(APPS)
