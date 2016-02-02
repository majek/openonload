GNU := 1
ifndef MMAKE_CTUNE
 MMAKE_CTUNE := -mtune=native
 ifneq ($(shell grep -i power8 /proc/cpuinfo),)
  MMAKE_CTUNE += -mpower8-fusion -O6
 endif
endif
MMAKE_CARCH := -m64 -mcpu=native $(MMAKE_CTUNE)
include $(TOP)/mk/linux_gcc.mk
