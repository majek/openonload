lib_ver   := 0
lib_name  := ocplane
lib_where := lib/cplane
CPLANE_LIB	:= $(MMakeGenerateLibTarget)
CPLANE_LIB_DEPEND	:= $(MMakeGenerateLibDepend)
LINK_CPLANE_LIB	:= $(MMakeGenerateLibLink)

# Following list headers is used to check that binary and source parts
# of cplane use the same API.
_CPLANE_HEADERS	:= config_opt.h contig_shmbuf.h debug.h driver_types.h \
	exported.h internal.h internal_types.h ioctl_ops.h linux_sync.h \
	prot.h prot_types.h shared_ops.h shared_types.h verlock.h ioctl.h \
	ul.h ul_syscalls.h

CPLANE_HEADERS	:= $(_CPLANE_HEADERS:%=$(SRCPATH)/include/cplane/%)

define CPLANE_GENERATE_API_VERSION
@echo "  GENERATE $@"
@md5=$$(cat $(CPLANE_HEADERS) | \
    md5sum | sed 's/ .*//'); \
    echo "#define CPLANE_API_VERSION \"$$md5\"" >"$@"
endef

