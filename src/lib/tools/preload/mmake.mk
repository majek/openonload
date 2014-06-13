
TARGETS		:= libefabnetstat_pl.so libaf_onload.so
MMAKE_TYPE	:= DLL

ifneq ($(ONLOAD_ONLY),1)
#
# Only build wrapper lib. if valgrind.h found
#
VALGRIND_INCLUDE := /misc/apps/valgrind/valgrind-3.2.3/include
VALGRIND_H	:= $(VALGRIND_INCLUDE)/valgrind.h
ifeq ($(shell ls $(VALGRIND_H) 2>/dev/null), $(VALGRIND_H))
TARGETS += libvg_IOPort_access.so
MMAKE_INCLUDE += -I $(VALGRIND_INCLUDE)
endif
endif


all: $(TARGETS)

lib: $(TARGETS)

clean:
	@$(MakeClean)


lib%.so: %.o
	@(libs="-ldl"; $(MMakeLinkPreloadLib))

#
# We want this lib to initialize - so get rid of '-nostartfiles'
#
libvg_IOPort_access.so: vg_IOPort_access.o
	@(soname=libvg_IOPort_access.so; $(MMakeLinkDynamicLib))
