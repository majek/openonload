SUBDIRS := util

ifeq ($(DRIVER),1)
  ifeq ($(MMAKE_LIBERAL),1)
    NOWERROR := 1
  endif

  include $(TOPPATH)/$(CURRENT)/Makefile

  ../linux/sfc.ko: modules
	cp -f sfc.ko $@

  all: ../linux/sfc.ko
endif
