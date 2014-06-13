/*
** Copyright 2005-2013  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This program is free software; you can redistribute it and/or modify it
** under the terms of version 2 of the GNU General Public License as
** published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/

/****************************************************************************
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2007-2010 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

/* This file implements an alternate idle loop to work-around an A1
 * Silicon issue.
 */

#include "config.h"
#include "kernel_compat.h"

#ifdef EFX_HAVE_PM_IDLE

#include <linux/version.h>
#include <linux/module.h>

#include <linux/sched.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <asm/atomic.h>
#include <linux/node.h>

#ifndef EFX_NEED_MUTEX
#include <linux/mutex.h>
#endif

#include "idle.h"
#include "efx.h"

#define IDLE_DEBUG 0

/* Each CPU is put into a group.  In most cases, the group number is
 * equal to the CPU number of one of the CPUs in the group.  The
 * exception is group NR_CPUS which is the default group.  This is
 * protected by efx_idle_startup_mutex. */
DEFINE_PER_CPU(int, idle_cpu_group) = NR_CPUS;

/* For each group, a count of the number of CPUs in the group which
 * are known to be busy.  A busy CPU might be running the busy loop
 * below or general kernel code.  The count is decremented on entry to
 * the old pm_idle handler and incremented on exit.  The aim is to
 * avoid the count going to zero or negative.  This situation can
 * occur temporarily during module unload or CPU hot-plug but
 * normality will be restored when the affected CPUs next exit the
 * idle loop. */
static atomic_t busy_cpu_count[NR_CPUS+1];

/* A workqueue item to be executed to cause the CPU to exit from the
 * idle loop. */
DEFINE_PER_CPU(struct work_struct, efx_idle_cpu_work);

#if IDLE_DEBUG

DEFINE_PER_CPU(int, idle_cpu_state) = -1;
#define idle_set_state(CPU,STATE) \
	per_cpu(idle_cpu_state, (CPU)) = (STATE)

static DEFINE_MUTEX(efx_idle_debug_mutex);
static cpumask_t efx_idle_debug_cpumask;

#else

#define idle_set_state(CPU,STATE) \
	do { } while(0)

#endif

static unsigned int idle_enable = 1;
module_param(idle_enable, uint, 0444);
MODULE_PARM_DESC(idle_enable, "sfc_tune: Idle polling (0=>disabled,"
		 " 1=>auto, 2=>enabled)");

static unsigned int idle_mode = 1;
module_param(idle_mode, uint, 0444);
MODULE_PARM_DESC(idle_mode, "sfc_tune: Entity to keep busy (0=>hyperthreads,"
		 " 1=>cores, 2=>packages, 3=>NUMA nodes)");

/* A mutex to protect most of the module datastructures. */
static DEFINE_MUTEX(efx_idle_startup_mutex);

/* The old pm_idle handler. */
static void (*old_pm_idle)(void) = NULL;

static void efx_pm_idle(void)
{
	atomic_t *busy_cpus_ptr;
	int busy_cpus;
	int cpu = smp_processor_id();

	busy_cpus_ptr = &(busy_cpu_count[per_cpu(idle_cpu_group, cpu)]);

	idle_set_state(cpu, 2);

	local_irq_enable();
	while (!need_resched()) {
		busy_cpus = atomic_read(busy_cpus_ptr);

		/* If other CPUs in this group are busy then let this
		 * CPU go idle.  We mustn't let the number of busy
		 * CPUs drop below 1. */
		if ( busy_cpus > 1 &&
		     old_pm_idle != NULL &&
		     ( atomic_cmpxchg(busy_cpus_ptr, busy_cpus,
				      busy_cpus-1) == busy_cpus ) ) {
			local_irq_disable();
			idle_set_state(cpu, 3);
			/* This check might not be necessary, but it
			 * seems safest to include it because there
			 * might be a kernel version which requires
			 * it. */
			if (need_resched())
				local_irq_enable();
			else
				old_pm_idle();
			/* This CPU is busy again. */
			idle_set_state(cpu, 1);
			atomic_add(1, busy_cpus_ptr);
			return;
		}

		cpu_relax();
	}
	idle_set_state(cpu, 0);
}


void efx_idle_work_func(struct work_struct *work)
{
	/* Do nothing.  Since this function is running in process
	 * context, the idle thread isn't running on this CPU. */
}


#ifdef CONFIG_SMP
static void efx_idle_smp_call(void *info)
{
	schedule_work(&get_cpu_var(efx_idle_cpu_work));
	put_cpu_var(efx_idle_cpu_work);
}
#endif


#ifdef CONFIG_SMP
static void efx_idle_refresh(void)
{
	on_each_cpu(&efx_idle_smp_call, NULL, 1);
}
#else
static void efx_idle_refresh(void)
{
	/* The current thread is executing on the one and only CPU so
	 * the idle thread isn't running. */
}
#endif


#if IDLE_DEBUG

static void show_cpus_in_state_smp_call(void *info)
{
	int cpu = smp_processor_id();
	int state = per_cpu(idle_cpu_state, cpu);
	if (state == (long)info)
		cpu_set(cpu, efx_idle_debug_cpumask);
}

static ssize_t show_cpus_in_state(char *buf, long state)
{
	ssize_t res;

	mutex_lock(&efx_idle_debug_mutex);
	cpus_clear(efx_idle_debug_cpumask);
	on_each_cpu(&show_cpus_in_state_smp_call, (void*)state, 1);
	res = cpumask_scnprintf(buf, PAGE_SIZE-2, efx_idle_debug_cpumask);
	mutex_unlock(&efx_idle_debug_mutex);

	buf[res++] = '\n';
	buf[res] = 0;
	
	return res;
}

static ssize_t show_idle_cpu_set(struct sys_device *dev,
				 char *buf)
{
	return show_cpus_in_state(buf, 3);
}
static SYSDEV_ATTR(idle_cpu_set, 0444, show_idle_cpu_set, NULL);


static ssize_t show_spinning_cpu_set(struct sys_device *dev,
				     char *buf)
{
	return show_cpus_in_state(buf, 2);
}
static SYSDEV_ATTR(spinning_cpu_set, 0444, show_spinning_cpu_set, NULL);


static ssize_t show_idle_cpu_state(struct sys_device *dev,
				   char *buf)
{
	int cpu = dev->id;
	return sprintf(buf, "%u\n", per_cpu(idle_cpu_state, cpu));
}
static SYSDEV_ATTR(idle_cpu_state, 0444, show_idle_cpu_state, NULL);


static ssize_t show_idle_cpu_group(struct sys_device *dev,
				   char *buf)
{
	int cpu = dev->id;
	return sprintf(buf, "%u\n", per_cpu(idle_cpu_group, cpu));
}
static SYSDEV_ATTR(idle_cpu_group, 0444, show_idle_cpu_group, NULL);


static ssize_t show_busy_cpus(struct sys_device *dev,
			      char *buf)
{
	int group = per_cpu(idle_cpu_group, dev->id);
	return sprintf(buf, "%u\n", atomic_read(&(busy_cpu_count[group])));
}
static SYSDEV_ATTR(busy_cpus, 0444, show_busy_cpus, NULL);

#endif


static int efx_idle_cpu_group(int cpu)
{
#ifdef CONFIG_SMP
	const cpumask_t *mask;
	int node;
	int other_cpu;
	int group;

	switch(idle_mode) {
	default:
	case 0:
		/* Keep one hyperthread busy per hyperthread. */
		return cpu;
	case 1:
#if defined(topology_thread_cpumask) && defined(EFX_HAVE_EXPORTED_CPU_SIBLING_MAP)
		/* Keep one hyperthread busy per core. */
		mask = topology_thread_cpumask(cpu);
		break;
#else
		return cpu;
#endif
	case 2:
#ifdef topology_core_cpumask
		/* Keep one hyperthread busy per package. */
		mask = topology_core_cpumask(cpu);
		break;
#else
		return cpu;
#endif
	case 3:
#ifdef EFX_HAVE_CPUMASK_OF_NODE
		/* Keep one hyperthread busy per NUMA node. */
		node = cpu_to_node(cpu);
		mask = cpumask_of_node(node);
		break;
#else
		(void)node;
		return cpu;
#endif
	}

	for_each_cpu(other_cpu, mask) {
		group = per_cpu(idle_cpu_group, other_cpu);
		if (group != NR_CPUS)
			return group;
	}
#endif

	return cpu;
}


static void efx_idle_add_cpu(int cpu)
{
#if IDLE_DEBUG
	struct sys_device *sysdev = get_cpu_sysdev(cpu);
#endif
	int group;

	/* Do nothing if this CPU has already been added. */
	if (per_cpu(idle_cpu_group, cpu) != NR_CPUS)
		return;

	group = efx_idle_cpu_group(cpu);
	per_cpu(idle_cpu_group, cpu) = group;
	atomic_inc(&(busy_cpu_count[group]));

#if IDLE_DEBUG
	printk(KERN_INFO "sfc_idle: Adding CPU %d to group %d\n",
	       cpu, group);

	sysdev_create_file(sysdev, &attr_idle_cpu_set);
	sysdev_create_file(sysdev, &attr_spinning_cpu_set);
	sysdev_create_file(sysdev, &attr_idle_cpu_state);
	sysdev_create_file(sysdev, &attr_idle_cpu_group);
	sysdev_create_file(sysdev, &attr_busy_cpus);
#endif
}

static void efx_idle_del_cpu(int cpu)
{
#if IDLE_DEBUG
	struct sys_device *sysdev = get_cpu_sysdev(cpu);
#endif
	int group;

	if (per_cpu(idle_cpu_group, cpu) == NR_CPUS)
		return;

	group = per_cpu(idle_cpu_group, cpu);
	/* If the CPU was busy, this can cause the count to drop to
	 * zero.  To rectify this, we need to cause one of the other
	 * CPUs in the group to exit the idle loop.  If the CPU was
	 * not busy then this causes the contribution for this CPU to
	 * go to -1 which can cause the overall count to drop to zero
	 * or go negative.  To rectify this situation we need to cause
	 * this CPU to exit the idle loop. */
	atomic_dec(&(busy_cpu_count[group]));
	per_cpu(idle_cpu_group, cpu) = NR_CPUS;

#if IDLE_DEBUG
	printk(KERN_INFO "sfc_idle: Removing CPU %d from group %d\n",
	       cpu, group);

	sysdev_remove_file(sysdev, &attr_idle_cpu_set);
	sysdev_remove_file(sysdev, &attr_spinning_cpu_set);
	sysdev_remove_file(sysdev, &attr_idle_cpu_state);
	sysdev_remove_file(sysdev, &attr_idle_cpu_group);
	sysdev_remove_file(sysdev, &attr_busy_cpus);
#endif
}


static int efx_idle_cpu_notify(struct notifier_block *self,
			       unsigned long action, void *hcpu)
{
	int cpu = (long)hcpu;
	
	switch(action) {
#ifdef CPU_ONLINE_FROZEN
	case CPU_ONLINE_FROZEN:
#endif
	case CPU_ONLINE:
		mutex_lock(&efx_idle_startup_mutex);
		efx_idle_add_cpu(cpu);
		mutex_unlock(&efx_idle_startup_mutex);
		/* The CPU might have already entered the idle loop in
		 * the wrong group.  Make sure it exits the idle loop
		 * so that it picks up the correct group. */
		efx_idle_refresh();
		break;

#ifdef CPU_DEAD_FROZEN
	case CPU_DEAD_FROZEN:
#endif
	case CPU_DEAD:
		mutex_lock(&efx_idle_startup_mutex);
		efx_idle_del_cpu(cpu);
		mutex_unlock(&efx_idle_startup_mutex);
		/* The deleted CPU may have been the only busy CPU in
		 * the group.  Make sure one of the other CPUs in the
		 * group exits the idle loop. */
		efx_idle_refresh();
		break;
	}
	return NOTIFY_OK;
}


static struct notifier_block efx_idle_cpu_nb = {
	.notifier_call = efx_idle_cpu_notify,
};


static void efx_idle_ensure_init(void)
{
	BUG_ON (old_pm_idle != NULL);

	/* Atomically update pm_idle to &efx_pm_idle.  The old value
	 * is stored in old_pm_idle before installing the new
	 * handler. */
	do {
		old_pm_idle = pm_idle;
	} while (cmpxchg(&pm_idle, old_pm_idle, &efx_pm_idle) !=
		 old_pm_idle);
}

void efx_idle_fini(void)
{
	void (*old)(void);
	int cpu;

	unregister_cpu_notifier(&efx_idle_cpu_nb);

	mutex_lock(&efx_idle_startup_mutex);

	if (idle_enable >= 2) {
		/* Atomically uninstall the handler.  If someone has
		 * changed pm_idle in the mean-time, we're a bit
		 * stuck. */
		old = cmpxchg(&pm_idle, &efx_pm_idle, old_pm_idle);
		BUG_ON(old != &efx_pm_idle);
	}

	for_each_online_cpu(cpu)
		efx_idle_del_cpu(cpu);

	mutex_unlock(&efx_idle_startup_mutex);
	
	/* Our handler may still be executing on other CPUs.
	 * Schedule this thread on all CPUs to make sure all
	 * idle threads get interrupted. */
	efx_idle_refresh();

	/* Make sure the work item has finished executing on all CPUs.
	 * This in turn ensures that all idle threads have been
	 * interrupted. */
	flush_scheduled_work();
}


int efx_idle_init(void)
{
	int rc = 0;
	int updated = 0;
	int cpu;

	for_each_possible_cpu(cpu) {
		INIT_WORK(&per_cpu(efx_idle_cpu_work, cpu),
			  efx_idle_work_func);
	}

	/* Start by registering the handler to ensure we don't miss
	 * any updates. */
	register_cpu_notifier(&efx_idle_cpu_nb);

	mutex_lock(&efx_idle_startup_mutex);

	for_each_online_cpu(cpu)
		efx_idle_add_cpu(cpu);

	if (idle_enable >= 2) {
		efx_idle_ensure_init();
		updated = 1;
	}

	mutex_unlock(&efx_idle_startup_mutex);

	if (updated) {
		/* Ensure our idle handler starts to run. */
		efx_idle_refresh();
	}

	return rc;
}

int efx_idle_enhance(void)
{
	int rc = 0;
	int updated = 0;

	BUG_ON(xen_domain());

	mutex_lock(&efx_idle_startup_mutex);
	if (idle_enable == 1) {
		/* Only ever try to start the enhanced idle loop
		 * once. */
		idle_enable = 2;
		efx_idle_ensure_init();
		updated = 1;
	}
	mutex_unlock(&efx_idle_startup_mutex);

	if (updated) {
		/* Ensure our idle handler starts to run. */
		efx_idle_refresh();
	}

	return rc;
}

#endif
