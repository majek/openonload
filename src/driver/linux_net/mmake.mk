SUBDIRS := util

ifeq ($(DRIVER),1)
  include $(TOPPATH)/$(CURRENT)/Makefile

  ../linux/sfc.ko: modules
	cp -f sfc.ko $@

  all: ../linux/sfc.ko
endif
