# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
include $(BUILD)/config.mk
ifeq ($(DESTFLAG),1)
include $(DESTPATH)/options_config.mk
else
include $(BUILD)/options_config.mk
endif
include $(TOP)/mk/before.mk
include $(TOP)/mk/platform/$(PLATFORM).mk
ifneq ($(MMAKEBUILDTREE),1)
include $(TOP)/mk/site/citools.mk
include $(TOP)/mk/site/ciapp.mk
include $(TOP)/mk/site/ciul.mk
include $(TOP)/mk/site/ciip.mk
include $(TOP)/mk/site/cplane.mk
include $(TOP)/mk/site/citpcommon.mk
include $(TOP)/mk/site/efrm.mk
include $(TOP)/mk/site/efthrm.mk
include $(TOP)/mk/site/libs.mk
include $(TOP)/mk/site/sfgpxe.mk
include $(TOP)/mk/site/efhw.mk
endif
include $(TOP)/mk/middle.mk
