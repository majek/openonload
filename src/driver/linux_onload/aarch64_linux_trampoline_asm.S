/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <linux/linkage.h>
#include <asm/assembler.h>
#include <ci/internal/trampoline.h>

ENTRY(efab_linux_trampoline_close)
mov x1, sp
b efab_linux_aarch64_trampoline_close
ENDPROC(efab_linux_trampoline_close)
