/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include_next <linux/perf_event.h>

extern struct file* onload_perf_event_get(unsigned int fd);
#define perf_event_get onload_perf_event_get

extern int onload_perf_event_read_local(struct perf_event *event, u64 *value,
                                        u64 *enabled, u64 *running);
#define perf_event_read_local onload_perf_event_read_local

