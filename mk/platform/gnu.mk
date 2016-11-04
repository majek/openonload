GNU	    := 1
ifndef MMAKE_CTUNE
MMAKE_CTUNE = "-msse"
# Not all gcc's support -mtune=native, so we do a dummy invocation with that
# argument and only use the argument if the gcc invocation doesn't fail.
# Note that gcc takes empty STDIN, is told it is C (with -x c) and will create an output executable!
# Then use cond && a || b in order to set MMAKE_CTUNE := "-mtune=native" if the test compile worked
MMAKE_CTUNE += $(shell $(CC) -x c -c -march=core2 - -o /dev/null </dev/null >/dev/null 2>&1 && echo "-march=core2" || echo "")
MMAKE_CTUNE += $(shell $(CC) -x c -c -mtune=native - -o /dev/null </dev/null >/dev/null 2>&1 && echo "-mtune=native" || echo "")
endif
MMAKE_CARCH := -m32 $(MMAKE_CTUNE)

MMAKE_RELOCATABLE_LIB := -z combreloc

include $(TOP)/mk/linux_gcc.mk
