SIENA_MC_PLATFORM_DEFINE := SIENA_MC_PLATFORM_BUXTON=1
NETWORK_PORTS := 2
MC_PLATFORM_DEFS := florence.c
MC_DRIVER_DEFS := max6646.c qt2025c.c null_phy.c
# The QT2025 is booted over MDIO
WITH_MDIO_BOOT := 1
include $(TOP)/mk/platform/sienamc_asic.mk
