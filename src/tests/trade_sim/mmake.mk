# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

TEST_APPS	:= exchange \
		trader_onload_ds_efvi

ifneq ($(NO_ZF),1)
ifeq (${PLATFORM},gnu_x86_64)
ifeq ($(shell $(TOP)/$(CURRENT)/../zf_apps/zf_supported.sh),1)
TEST_APPS	+= trader_tcpdirect_ds_efvi \
                trader_tcpdirect_ds_efvi_ct_rx
endif
endif
endif

TARGETS		:= $(TEST_APPS:%=$(AppPattern))


all: $(TARGETS)

clean:
	@$(MakeClean)


exchange: exchange.o utils.o
exchange: MMAKE_LIBS     += $(LINK_ONLOAD_EXT_LIB)
exchange: MMAKE_LIB_DEPS += $(ONLOAD_EXT_LIB_DEPEND)

trader_onload_ds_efvi: trader_onload_ds_efvi.o utils.o
trader_onload_ds_efvi: \
	MMAKE_LIBS     += $(LINK_ONLOAD_EXT_LIB) $(LINK_CIUL_LIB)
trader_onload_ds_efvi: \
	MMAKE_LIB_DEPS += $(ONLOAD_EXT_LIB_DEPEND) $(CIUL_LIB_DEPEND)

trader_tcpdirect_ds_efvi: trader_tcpdirect_ds_efvi.o utils.o
trader_tcpdirect_ds_efvi: \
	MMAKE_LIBS     += $(LINK_ZF_STATIC_LIB) $(LINK_CIUL_LIB)
trader_tcpdirect_ds_efvi: \
	MMAKE_LIB_DEPS += $(ZF_STATIC_LIB_DEPEND) $(CIUL_LIB_DEPEND)

trader_tcpdirect_ds_efvi_ct_rx: trader_tcpdirect_ds_efvi_ct_rx.o utils.o
trader_tcpdirect_ds_efvi_ct_rx: \
        MMAKE_LIBS     += $(LINK_ZF_STATIC_LIB) $(LINK_CIUL_LIB)
trader_tcpdirect_ds_efvi_ct_rx: \
        MMAKE_LIB_DEPS += $(ZF_STATIC_LIB_DEPEND) $(CIUL_LIB_DEPEND)
