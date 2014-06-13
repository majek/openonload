# Set-up build tree configuration
WINDOWS                   := 1
DRIVER                    := 1
DRIVER_TYPE               := wxp
DRIVER_SIZE               := 32

# Ensure MMAKE_TOOLCHAIN, MMAKE_DISTFILES and MMAKE_FIRMWARE are set
export MMAKE_TOOLCHAIN
export MMAKE_DISTFILES
export MMAKE_FIRMWARE
ifndef MMAKE_TOOLCHAIN
MMAKE_TOOLCHAIN           := wlh
endif
ifndef MMAKE_DISTFILES
MMAKE_DISTFILES           := $(TOP)/../distfiles
endif
ifndef MMAKE_FIRMWARE
MMAKE_FIRMWARE            := $(TOP)/../firmware
endif


# Include tool-chain specific setup and configuration section 
include $(TOP)/mk/wdk_$(MMAKE_TOOLCHAIN)_toolchain.mk

# Include common DDK/WDK section
include $(TOP)/mk/wdk_common.mk
