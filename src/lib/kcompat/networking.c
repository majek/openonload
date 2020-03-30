/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/kcompat.h>

u8 skb_metadata_len(const struct sk_buff *skb)
{
  ci_assert(0);
  return 0;
}

unsigned int skb_headlen(const struct sk_buff *skb)
{
  ci_assert(0);
  return 0;
}

void * skb_header_pointer(const struct sk_buff *skb, int offset,
                                        int len, void *buffer)
{
  ci_assert(0);
  return NULL;
}

u8* skb_tail_pointer(const struct sk_buff *skb)
{
  ci_assert(0);
  return NULL;
}

unsigned char *skb_network_header(const struct sk_buff *skb)
{
  ci_assert(0);
  return NULL;
}

unsigned char *skb_mac_header(const struct sk_buff *skb)
{
  ci_assert(0);
  return NULL;
}

struct qdisc_skb_cb *qdisc_skb_cb(const struct sk_buff *skb)
{
  ci_assert(0);
  return (struct qdisc_skb_cb *)skb->cb;
}

void dev_put(struct net_device* dev)
{
  (void)dev;
}

struct user_struct;
int __bpf_prog_charge(struct user_struct *user, u32 pages)
{
  return 0;
}

void __bpf_prog_uncharge(struct user_struct *user, u32 pages)
{
}
