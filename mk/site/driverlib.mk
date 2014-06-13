
lib_ver   := 1
lib_name  := efab
lib_where := driver/ul
EFAB_LIB		:= $(MMakeGenerateLibTarget)
EFAB_LIB_DEPEND		:= $(MMakeGenerateLibDepend)
LINK_EFAB_LIB		:= $(MMakeGenerateLibLink)

ifeq ($(LINUX),1)
LINK_EFAB_LIB		+= -lpci -lz
endif

ifeq ($(FREEBSD),1)
LINK_EFAB_LIB		+= -lpci -L/usr/local/lib -lz
endif
