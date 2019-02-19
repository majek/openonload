#include <linux/linkage.h>
#include <asm/assembler.h>
#include <ci/internal/trampoline.h>

ENTRY(efab_linux_trampoline_close)
mov x1, sp
b efab_linux_aarch64_trampoline_close
ENDPROC(efab_linux_trampoline_close)
