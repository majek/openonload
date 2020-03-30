# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
lib_ver   := 0
lib_name  := cplane
lib_where := lib/cplane
CPLANE_LIB	:= $(MMakeGenerateLibTarget)
CPLANE_LIB_DEPEND	:= $(MMakeGenerateLibDepend)
LINK_CPLANE_LIB	:= $(MMakeGenerateLibLink)
