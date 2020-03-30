/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/kcompat.h>
#include <ci/tools.h>

struct seq_file;

int in_atomic(void) {
  return 0;
}

int in_interrupt(void) {
  return 0;
}

/* Used to test for CAP_NET_RAW for MAC filter install */
int ns_capable(struct user_namespace* user_ns, int c) {
  return 1;
}

bool capable(int cap)
{
  return true;
}

/* Used to compare with scalable_filters_gid for MAC filter install */
int ci_getgid(void) {
  return 1;
};

int cond_resched(void)
{
  return 0;
}

bool need_resched(void)
{
  return 0;
}

int signal_pending(struct task_struct *p)
{
  return 0;
}

int kallsyms_show_value(void)
{
  return 1;
}

bool schedule_work(struct work_struct *work)
{
  ci_assert(0);
  return false;
}

