
lib_ver   := 1

ifeq ($(DRIVER),1)
lib_name  := citools-drv
else
lib_name  := citools
endif

lib_where := lib/citools
CITOOLS_LIB		:= $(MMakeGenerateLibTarget)
CITOOLS_LIB_DEPEND	:= $(MMakeGenerateLibDepend)
LINK_CITOOLS_LIB	:= $(MMakeGenerateLibLink)
ifeq ($(SOLARIS),1)
# libkstat for libcitool get_cpu_khz
LINK_CITOOLS_LIB	+= -lkstat
endif
