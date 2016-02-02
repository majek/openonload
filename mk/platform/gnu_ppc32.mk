GNU := 1
ifndef MMAKE_CTUNE
 MMAKE_CTUNE := -mtune=native
endif
MMAKE_CARCH := -m32 -mcpu=native $(MMAKE_CTUNE)
include $(TOP)/mk/linux_gcc.mk
