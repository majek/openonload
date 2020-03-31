/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <errno.h>

struct oo_bpf_jitted_prog;

int oo_bpf_jit(struct oo_bpf_jitted_prog* jp, int fd)
{
  return -ENOSYS;
}

void oo_bpf_jit_free(struct oo_bpf_jitted_prog* jp)
{
}
