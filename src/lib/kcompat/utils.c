/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/kcompat.h>

int fls64(u64 x)
{
  u32 h = x >> 32;
  if (h)
    return fls(h) + 32;
  return fls(x);
}

int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
  int i = vsnprintf(buf, size, fmt, args);
  ssize_t ssize = size;

  return (i >= ssize) ? (ssize - 1) : i;
}

void sort(void *base, size_t num, size_t size,
          int (*cmp_func)(const void *, const void *),
          void (*swap_func)(void *, void *, int size))
{
  qsort(base, num, size, cmp_func);
}

u32 prandom_u32_state(struct rnd_state *state)
{
  return random();
}

void prandom_init_once(void* arg)
{
}

unsigned int get_random_int(void)
{
  return random();
}

void sha_init(u32 *buf)
{
}

extern void sha_transform(u32 *digest, const u8 *data, u32 *array)
{
}

