# SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
# Implementation of kernel's libbpf API to enable easy test code reuse
lib_ver   := 0
lib_name  := testbpf
lib_where := tests/bpf/bpf_lib
TESTBPF_LIB		:= $(MMakeGenerateLibTarget)
TESTBPF_LIB_DEPEND	:= $(MMakeGenerateLibDepend)
LINK_TESTBPF_LIB	:= $(MMakeGenerateLibLink)
