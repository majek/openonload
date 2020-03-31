/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef CI_INTERNAL_XDP_BUFF_H_
#define CI_INTERNAL_XDP_BUFF_H_

/* There is no requirement for this struct to be in any way compatible with
 * the similarly-named one in the kernel tree. They are broadly similar
 * solely to make the code which can talk to either real kernel or our copy
 * slightly neater */

struct oo_xdp_rxq_info {
};

struct oo_xdp_buff {
  void* data;
  void* data_end;
  void* data_meta;
  void* data_hard_start;
  struct oo_xdp_rxq_info* rxq;
};

#endif
