/*
** Copyright 2005-2014  Solarflare Communications Inc.
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

/* TODO:
 *
 * - When reconfigure cpu_to_q map, redirect existing filters...?  (Only
 * those that specified cpu rather than rxq of course).
 */

#include <ci/affinity/ul_drv_intf.h>
#include <ci/affinity/k_drv_intf.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/ctype.h>
#include <ci/efhw/efhw_types.h>
#include <ci/driver/efab/hardware.h>
#include <driver/linux_net/driverlink_api.h>
#include "kernel_compat.h"


#define T(x)  x
#define E(x)  x


MODULE_AUTHOR("Solarflare Communications");
MODULE_LICENSE("GPL");


#ifndef NIPQUAD
# define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]
#endif
#ifndef NIPQUAD_FMT
# define NIPQUAD_FMT "%u.%u.%u.%u"
#endif
#define NIPP_FMT        NIPQUAD_FMT":%d"
#define NIPP(ip,port)   NIPQUAD(ip), ntohs(port)


struct aff_interface {
	bool down;
	struct list_head all_interfaces_link;
	struct list_head filters;
	struct efx_dl_device *dl_device;
	int ifindex;
	int n_rxqs;
	int* cpu_to_q;
	char proc_name[12];
	struct proc_dir_entry *proc_dir;
};


struct aff_fd {
	struct list_head filters;
};


struct aff_filter {
	struct list_head fd_filters_link;
	struct list_head intf_filters_link;
	struct aff_interface *intf;
	int filter_id;
	int rq_rxq, rq_cpu;
	int rxq;
	int protocol;
	unsigned daddr, dport;
	unsigned saddr, sport;
};


static struct efx_dl_driver dl_driver;
static LIST_HEAD(all_interfaces);
static DEFINE_SPINLOCK(lock);
static struct proc_dir_entry *aff_proc_root;


/* simple_strtol() does not strip leading whitespace. */
static long strtol(const char *s, char **p_end, unsigned int base)
{
	while (isspace(*s))
		++s;
	return simple_strtol(s, p_end, base);
}


static int aff_proc_read_int(struct seq_file *seq, void *s)
{
	int *pint = seq->private;
	seq_printf(seq, "%d\n", *pint);
	return 0;
}
static int aff_proc_open_int(struct inode *inode, struct file *file)
{
	return single_open(file, aff_proc_read_int, PDE_DATA(inode));
}
static const struct file_operations aff_proc_fops_int = {
	.owner		= THIS_MODULE,
	.open		= aff_proc_open_int,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};


static int aff_proc_read_cpu2rxq(struct seq_file *seq, void *s)
{
	/* ?? fixme: this really needs to grab [lock] */
	struct aff_interface *intf = seq->private;
	int n_cpus = num_online_cpus();
	int i;
	spin_lock(&lock);
	for (i = 0; i < n_cpus; ++i)
		seq_printf(seq, "%s%d", i == 0 ? "":" ", intf->cpu_to_q[i]);
	spin_unlock(&lock);
	seq_printf(seq, "\n");
	return 0;
}
static int aff_proc_open_cpu2rxq(struct inode *inode, struct file *file)
{
	return single_open(file, aff_proc_read_cpu2rxq, PDE_DATA(inode));
}
static const struct file_operations aff_proc_fops_cpu2rxq = {
	.owner		= THIS_MODULE,
	.open		= aff_proc_open_cpu2rxq,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};


static int aff_proc_read_filters(struct seq_file *seq, void *s)
{
	struct aff_interface *intf = seq->private;
	struct aff_filter *f;
	spin_lock(&lock);
	list_for_each_entry(f, &intf->filters, intf_filters_link) {
		seq_printf(seq, 
			   "%s "NIPP_FMT" "NIPP_FMT" %d %d %d\n",
			   f->protocol == IPPROTO_TCP ? "tcp":"udp",
			   NIPP(f->daddr, f->dport),
			   NIPP(f->saddr, f->sport),
			   f->rq_cpu, f->rq_rxq, f->rxq);
	}
	spin_unlock(&lock);
	return 0;
}
static int aff_proc_open_filters(struct inode *inode, struct file *file)
{
	return single_open(file, aff_proc_read_filters, PDE_DATA(inode));
}
static const struct file_operations aff_proc_fops_filters = {
	.owner		= THIS_MODULE,
	.open		= aff_proc_open_filters,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};


static struct aff_interface *__interface_find(int ifindex)
{
	/* Caller must hold [lock]. */
	struct aff_interface *intf;
	list_for_each_entry(intf, &all_interfaces, all_interfaces_link)
		if (intf->ifindex == ifindex)
			return intf;
	return NULL;
}


static struct aff_interface *interface_find(int ifindex)
{
	/* Caller must hold [lock]. */
	struct aff_interface *intf = __interface_find(ifindex);
	return (intf == NULL || intf->down) ? NULL : intf;
}


static void interface_add_proc(struct aff_interface *intf,
			       const char *name, void *data,
			       const struct file_operations *proc_fops)
{
	proc_create_data(name, 0444, intf->proc_dir, proc_fops, data);
}


static void interface_add_proc_int(struct aff_interface *intf,
				   const char *name, int *data)
{
	interface_add_proc(intf, name, data, &aff_proc_fops_int);
}


static void interface_add_proc_entries(struct aff_interface *intf)
{
	intf->proc_dir = proc_mkdir(intf->proc_name, aff_proc_root);
	if (intf->proc_dir != NULL) {
		interface_add_proc_int(intf, "ifindex", &intf->ifindex);
		interface_add_proc_int(intf, "n_rxqs", &intf->n_rxqs);
		interface_add_proc(intf, "cpu2rxq", intf,
				   &aff_proc_fops_cpu2rxq);
		interface_add_proc(intf, "filters", intf,
				   &aff_proc_fops_filters);
	}
}


static void interface_remove_proc_entries(struct aff_interface *intf)
{
	if (intf->proc_dir != NULL) {
		remove_proc_entry("ifindex", intf->proc_dir);
		remove_proc_entry("n_rxqs", intf->proc_dir);
		remove_proc_entry("cpu2rxq", intf->proc_dir);
		remove_proc_entry("filters", intf->proc_dir);
		intf->proc_dir = NULL;
	}
	remove_proc_entry(intf->proc_name, aff_proc_root);
}


static struct aff_interface *interface_up(int ifindex, int n_rxqs,
					  struct efx_dl_device *dl_dev)
{
	int i, add_proc = 0, n_cpus = num_possible_cpus();
	struct aff_interface *new_intf;
	struct aff_interface *intf;
	int *new_cpu_to_q;

	new_intf = kmalloc(sizeof(*new_intf), GFP_KERNEL);
	new_cpu_to_q = kmalloc(n_cpus * sizeof(int), GFP_KERNEL);

	spin_lock(&lock);
	if ((intf = __interface_find(ifindex)) == NULL) {
		printk(KERN_NOTICE "[sfcaffinity] interface_up: %d NEW\n",
			ifindex);
		intf = new_intf;
		new_intf = NULL;
		intf->ifindex = ifindex;
		sprintf(intf->proc_name, "%d", ifindex);
		INIT_LIST_HEAD(&intf->filters);
		intf->cpu_to_q = NULL;
	} else {
		printk(KERN_NOTICE "[sfcaffinity] interface_up: %d RESURECT\n",
			ifindex);
		if (intf->n_rxqs != n_rxqs) {
			kfree(intf->cpu_to_q);
			intf->cpu_to_q = NULL;
		}
	}
	if (intf->cpu_to_q == NULL) {
		intf->cpu_to_q = new_cpu_to_q;
		new_cpu_to_q = NULL;
		for (i = 0; i < n_cpus; ++i)
			intf->cpu_to_q[i] = -1;
	}
	intf->down = false;
	intf->dl_device = dl_dev;
	intf->n_rxqs = n_rxqs;
	if (__interface_find(ifindex) == NULL) {
		list_add(&intf->all_interfaces_link, &all_interfaces);
		add_proc = 1;
	}
	spin_unlock(&lock);

	/* This must be after dropping spin lock as proc_mkdir() can block */
	if (add_proc)
		interface_add_proc_entries(intf);

	kfree(new_cpu_to_q);
	kfree(new_intf);
	return intf;
}


static void interface_down(int ifindex)
{
	struct aff_interface *intf;
	spin_lock(&lock);
	if ((intf = __interface_find(ifindex)) != NULL) {
		intf->down = true;
		intf->dl_device = NULL;
	}
	spin_unlock(&lock);
}


static void interface_free(struct aff_interface *intf)
{
	/* Caller must hold [lock]. */
	BUG_ON(! list_empty(&intf->filters));
	interface_remove_proc_entries(intf);
	list_del(&intf->all_interfaces_link);
	kfree(intf->cpu_to_q);
	kfree(intf);
}


static int interface_configure(int ifindex, int n_rxqs, const int *cpu_to_q)
{
	int n_cpus = num_possible_cpus();
	struct aff_interface *intf;
	int i, rc;

	rc = -EINVAL;
	for (i = 0; i < n_cpus; ++i)
		if (cpu_to_q[i] < 0 || cpu_to_q[i] >= n_rxqs)
			goto fail1;

	spin_lock(&lock);
	if ((intf = __interface_find(ifindex)) == NULL) {
		printk(KERN_ERR "[sfcaffinity] ERROR: unknown ifindex=%d\n",
		       ifindex);
		goto fail2;
	}
	intf->n_rxqs = n_rxqs;
	memcpy(intf->cpu_to_q, cpu_to_q, n_cpus * sizeof(intf->cpu_to_q[0]));
	spin_unlock(&lock);
	return 0;

fail2:
	spin_unlock(&lock);
fail1:
	return rc;
}


static int filter_eq(struct aff_filter *f, int protocol,
		     unsigned daddr, unsigned dport,
		     unsigned saddr, unsigned sport)
{
	return  f->protocol == protocol &&
		f->daddr == daddr &&
		f->dport == dport &&
		f->saddr == saddr &&
		f->sport == sport;
}


static struct aff_filter *filter_find(struct aff_interface *intf,
				      int protocol,
				      unsigned daddr, unsigned dport,
				      unsigned saddr, unsigned sport)
{
	/* Caller must hold [lock]. */
	struct aff_filter *f;
	list_for_each_entry(f, &intf->filters, intf_filters_link)
		if (filter_eq(f, protocol, daddr, dport, saddr, sport))
			return f;
	return NULL;
}


static void filter_remove(struct aff_filter *f)
{
	/* Caller must hold [lock]. */
	list_del(&f->fd_filters_link);
	list_del(&f->intf_filters_link);
	if (f->intf->dl_device != NULL)
		efx_dl_filter_remove(f->intf->dl_device, f->filter_id);
	kfree(f);
}


enum sfc_aff_err insert_fail_reason(int rc)
{
	switch (rc) {
	case EBUSY:
		return sfc_aff_table_full;
	case EEXIST:
		return sfc_aff_filter_exists;
	case EPERM:
		return sfc_aff_cannot_replace;
	default:
		return sfc_aff_filter_set_fail;
	}
}


static int filter_add(struct aff_fd *aff, int cpu, int rxq, int ifindex,
		      int protocol,
		      unsigned daddr, unsigned dport,
		      unsigned saddr, unsigned sport,
		      enum sfc_aff_err *err_out)
{
	struct efx_filter_spec spec;
	struct aff_interface *intf;
	struct aff_filter *newf;
	struct aff_filter *f;
	int filter_type, rc;

	*err_out = sfc_aff_no_error;
	rc = -EINVAL;

	switch (protocol) {
	case IPPROTO_TCP:
		if (saddr)
			filter_type = EFHW_IP_FILTER_TYPE_TCP_FULL;
		else
			filter_type = EFHW_IP_FILTER_TYPE_TCP_WILDCARD;
		break;
	case IPPROTO_UDP:
		if (saddr)
			filter_type = EFHW_IP_FILTER_TYPE_UDP_FULL;
		else
			filter_type = EFHW_IP_FILTER_TYPE_UDP_WILDCARD;
		break;
	default:
		printk("sfc_affinity: bad protocol=%d\n", protocol);
		*err_out = sfc_aff_bad_protocol;
		goto fail1;
	};

	if ((saddr == 0) != (sport == 0)) {
		printk("sfc_affinity: bad saddr="NIPP_FMT"\n",
		       NIPP(saddr, sport));
		*err_out = sfc_aff_bad_saddr;
		goto fail1;
	}
	if (daddr == 0 || dport == 0) {
		printk("sfc_affinity: bad daddr="NIPP_FMT"\n",
		       NIPP(daddr, dport));
		*err_out = sfc_aff_bad_daddr;
		goto fail1;
	}
	if (cpu < 0) {
		/* Using smp_processor_id() generates false positives
		 * on preemptable kernels because right after doing
		 * this the application thread can move to a different
		 * core.  That is something that the application has
		 * to deal with with with proper affinitisation.  So
		 * we use raw_smp_processor_id() to silence the
		 * warning.
		 */
		cpu = raw_smp_processor_id();
	} else if (cpu >= num_possible_cpus()) {
		printk("sfc_affinity: bad cpu=%d (0-%d)\n", cpu,
		       (int)num_possible_cpus() - 1);
		*err_out = sfc_aff_bad_cpu;
		goto fail1;
	}

	newf = kmalloc(sizeof(*newf), GFP_KERNEL);
	if (newf == NULL) {
		rc = -ENOMEM;
		goto fail1;
	}
	newf->rq_rxq = rxq;
	newf->rq_cpu = cpu;

	spin_lock(&lock);

	rc = -EINVAL;
	intf = interface_find(ifindex);
	if (intf == NULL) {
		printk(KERN_ERR "[sfc_affinity] %s: ERROR: ifindex=%d not "
		       "supported\n", __FUNCTION__, ifindex);
		*err_out = sfc_aff_intf_not_supported;
		goto fail2;
	}
	if (rxq >= intf->n_rxqs) {
		printk(KERN_ERR "[sfc_affinity] %s: ERROR: bad rxq=%d "
		       "(0-%d)\n", __FUNCTION__, rxq, intf->n_rxqs - 1);
		*err_out = sfc_aff_bad_rxq;
		goto fail2;
	} else if (rxq < 0) {
		rxq = intf->cpu_to_q[cpu];
	}
	if (rxq < 0) {
		printk(KERN_ERR "[sfc_affinity] %s: ERROR: ifindex=%d not "
		       "initialised\n", __FUNCTION__, ifindex);
		*err_out = sfc_aff_intf_not_configured;
		goto fail2;
	}

	T(printk(KERN_NOTICE "[sfc_affinity] %s: cpu=%d rxq=%d ifindex=%d "
		 "protocol=%d local="NIPP_FMT" remote="NIPP_FMT"\n",
		 __FUNCTION__, cpu, rxq, ifindex,
		 protocol, NIPP(daddr, dport), NIPP(saddr, sport)));

	f = filter_find(intf, protocol, daddr, dport, saddr, sport);
	if (f != NULL) {
		if (f->rxq == rxq) {
			/* Take ownership of existing filter. */
			list_del(&f->fd_filters_link);
			list_add(&f->fd_filters_link, &aff->filters);
			f->rq_cpu = newf->rq_cpu;
			f->rq_rxq = newf->rq_rxq;
			rc = 0;
			goto fail2;
		} else {
			filter_remove(f);
		}
	}

	newf->rxq = rxq;
	newf->protocol = protocol;
	newf->daddr = daddr;
	newf->dport = dport;
	newf->saddr = saddr;
	newf->sport = sport;
	newf->intf = intf;

	efx_filter_init_rx(&spec, EFX_FILTER_PRI_MANUAL,
			   EFX_FILTER_FLAG_RX_SCATTER, rxq);
	if( saddr != 0 )
		rc = efx_filter_set_ipv4_full(&spec, protocol, daddr, dport,
					      saddr, sport);
	else
		rc = efx_filter_set_ipv4_local(&spec, protocol, daddr, dport);
	if (rc != 0) {  /* Not expected to ever fail. */
		printk("sfc_affinity: ERROR: efx_filter_set failed\n");
		*err_out = sfc_aff_filter_set_fail;
		goto fail2;
	}
	rc = efx_dl_filter_insert(intf->dl_device, &spec, true);
	if (rc < 0) {
		*err_out = insert_fail_reason(rc);
		printk("sfc_affinity: unable to add filter: %d %s\n", rc,
		       sfc_aff_err_msg(*err_out));
		printk("sfc_affinity: ifindex=%d rxq=%d protocol=%d "
		       "local="NIPP_FMT" remote="NIPP_FMT"\n",
		       ifindex, rxq, protocol, NIPP(daddr, dport),
		       NIPP(saddr, sport));
		goto fail2;
	}
	else {
		newf->filter_id = rc;
		list_add(&newf->intf_filters_link, &intf->filters);
		list_add(&newf->fd_filters_link, &aff->filters);
	}

	spin_unlock(&lock);
	return 0;

fail2:
	spin_unlock(&lock);
	kfree(newf);
fail1:
	return rc;
}


static int filter_del(struct aff_fd *aff, int ifindex, int protocol,
		      unsigned daddr, unsigned dport,
		      unsigned saddr, unsigned sport,
		      enum sfc_aff_err *err_out)
{
	struct list_head *l;
	struct aff_filter *f;
	int rc = -EINVAL;
	*err_out = sfc_aff_not_found;

	spin_lock(&lock);
	for (l = aff->filters.next; l != &aff->filters; ) {
		f = list_entry(l, struct aff_filter, fd_filters_link);
		l = l->next;
		if (filter_eq(f, protocol, daddr, dport, saddr, sport))
			if (ifindex < 0 || ifindex == f->intf->ifindex) {
				*err_out = sfc_aff_no_error;
				rc = 0;
				filter_remove(f);
			}
	}
	spin_unlock(&lock);
	return rc;
}


static ssize_t aff_proc_write_new_interface(struct file *file,
					    const char __user *buffer,
					    size_t count, loff_t *ppos)
{
	int max_cpus = num_possible_cpus();
	int i, rc, ifindex, n_rxqs;
	int *cpu_to_q;
	char *buf, *s;

	rc = -E2BIG;
	if (count > max_cpus * 8 + 20)
		goto fail1;
	rc = -ENOMEM;
	cpu_to_q = kmalloc(max_cpus * sizeof(int), GFP_KERNEL);
	if (cpu_to_q == NULL)
		goto fail1;
	buf = kmalloc(count + 1, GFP_KERNEL);
	if (buf == NULL)
		goto fail2;
	rc = -EFAULT;
	if (copy_from_user(buf, buffer, count))
		goto fail3;
	buf[count] = '\0';
	s = buf;
	ifindex = strtol(s, &s, 0);
	n_rxqs = strtol(s, &s, 0);
	for (i = 0; i < max_cpus; ++i)
		cpu_to_q[i] = strtol(s, &s, 0);
	for (; i < max_cpus; ++i)
		cpu_to_q[i] = 0;
	while (isspace(*s))
		++s;
	rc = -EINVAL;
	if (*s)
		goto fail3;
	interface_configure(ifindex, n_rxqs, cpu_to_q);
	rc = count;
fail3:
	kfree(buf);
fail2:
	kfree(cpu_to_q);
fail1:
	return rc;
}
static const struct file_operations aff_proc_fops_new_interface = {
	.owner		= THIS_MODULE,
	.write		= aff_proc_write_new_interface,
};


static int aff_proc_init(void)
{
	struct proc_dir_entry *pde;
	int rc = -ENOMEM;

	aff_proc_root = proc_mkdir("driver/sfc_affinity", NULL);
	if (aff_proc_root == NULL)
		goto fail1;

	pde = proc_create("new_interface", 0644, aff_proc_root,
			&aff_proc_fops_new_interface);
	if (pde == NULL)
		goto fail1;
	return 0;

fail1:
	return rc;
}


static void aff_proc_fini(void)
{
	remove_proc_entry("new_interface", aff_proc_root);
	remove_proc_entry("driver/sfc_affinity", NULL);
}


static int sfc_aff_set(struct aff_fd *aff, void __user *user_aff_set)
{
	struct sfc_aff_set as;
	int rc;
	if (copy_from_user(&as, user_aff_set, sizeof(as)))
		return -EFAULT;
	rc = filter_add(aff, as.cpu, as.rxq, as.ifindex, as.protocol,
			as.daddr, as.dport, as.saddr, as.sport, &as.err_out);
	if (rc < 0)
		if (copy_to_user(user_aff_set, &as, sizeof(as)))
			return -EFAULT;
	return rc;
}


static int sfc_aff_clear(struct aff_fd *aff, void __user *user_aff_clear)
{
	struct sfc_aff_clear ac;
	int rc;
	if (copy_from_user(&ac, user_aff_clear, sizeof(ac)))
		return -EFAULT;
	rc = filter_del(aff, ac.ifindex, ac.protocol,
			ac.daddr, ac.dport, ac.saddr, ac.sport,
			&ac.err_out);
	if (rc < 0)
		if (copy_to_user(user_aff_clear, &ac, sizeof(ac)))
			return -EFAULT;
	return rc;
}


static long fop_ioctl(struct file *filp,
		      unsigned cmd, unsigned long arg) 
{
	struct aff_fd *aff = filp->private_data;

	switch (cmd) {
	case SFC_AFF_SET:
		return sfc_aff_set(aff, (void __user *) arg);
	case SFC_AFF_CLEAR:
		return sfc_aff_clear(aff, (void __user *) arg);
	default:
		printk("sfc_affinity: unknown ioctl (%u, %lx)\n", cmd, arg);
		return -ENOTTY;
	}
}


#ifndef HAVE_UNLOCKED_IOCTL
static int fop_legacy_ioctl(struct inode *inode, struct file *filp,
			    unsigned cmd, unsigned long arg) 
{
	return (int) fop_ioctl(filp, cmd, arg);
}
#endif


static int fop_open(struct inode *inode, struct file *filp)
{
	struct aff_fd *aff;
	aff = kmalloc(sizeof(*aff), GFP_KERNEL);
	if (aff == NULL)
		return -ENOMEM;
	INIT_LIST_HEAD(&aff->filters);
	filp->private_data = aff;
	return 0;
}


static int fop_close(struct inode *inode, struct file *filp) 
{
	struct aff_fd *aff = filp->private_data;
	struct aff_filter *f;
	spin_lock(&lock);
	while (! list_empty(&aff->filters)) {
		f = list_entry(aff->filters.next, struct aff_filter,
			       fd_filters_link);
		filter_remove(f);
	}
	spin_unlock(&lock);
	return 0;
}


struct file_operations fops = {
	.owner = THIS_MODULE,
#ifdef HAVE_UNLOCKED_IOCTL
	.unlocked_ioctl = fop_ioctl,
#else
	.ioctl = fop_legacy_ioctl,
#endif
#ifdef HAVE_COMPAT_IOCTL
	.compat_ioctl = fop_ioctl,
#endif
	.open = fop_open,
	.release = fop_close,
};


static int dl_probe(struct efx_dl_device* dl_dev,
		    const struct net_device* net_dev,
		    const struct efx_dl_device_info* dev_info,
		    const char* silicon_rev)
{
	struct efx_dl_falcon_resources *res;
	int n_rxqs = 0;
	efx_dl_for_each_device_info_matching(dev_info, EFX_DL_FALCON_RESOURCES,
					     struct efx_dl_falcon_resources,
					     hdr, res)
		n_rxqs = res->rxq_min;
	printk(KERN_NOTICE "[sfcaffinity] probe ifindex=%d n_rxqs=%d\n",
	       net_dev->ifindex, n_rxqs);
	if (interface_up(net_dev->ifindex, n_rxqs, dl_dev) == NULL)
		return -1;
	dl_dev->priv = (void*) net_dev;
	return 0;
}


static void dl_remove(struct efx_dl_device* dl_dev)
{
	struct net_device *net_dev = dl_dev->priv;
	printk(KERN_NOTICE "[sfcaffinity] remove ifindex=%d\n",
	       net_dev->ifindex);
	interface_down(net_dev->ifindex);
}


static struct efx_dl_driver dl_driver = {
  .name   = "sfcaffinity",
#if EFX_DRIVERLINK_API_VERSION >= 7
  .priority = EFX_DL_EV_LOW,
#endif
#if EFX_DRIVERLINK_API_VERSION >= 8
  /* This flag is required to for the driver to register with the net
   * driver however this driver will never receive packets so it will
   * not be doing any actual checking. */
  .flags = EFX_DL_DRIVER_CHECKS_FALCON_RX_USR_BUF_SIZE,
#endif
  .probe  = dl_probe,
  .remove = dl_remove,
};


static int dev_major;


static int __init init_sfc_affinity(void)
{
	int rc;

	T(printk("sfc_affinity: starting\n"));

	rc = aff_proc_init();
	if (rc < 0)
		goto fail1;

	rc = efx_dl_register_driver(&dl_driver);
	if (rc < 0)
		goto fail2;

	rc = register_chrdev(0, "sfc_affinity", &fops);
	if (rc < 0) {
		E(printk("sfc_affinity: ERROR: register_chrdev failed (%d)\n",
			 rc));
		goto fail3;
	}
	dev_major = rc;

	return 0;

fail3:
	efx_dl_unregister_driver(&dl_driver);
fail2:
	aff_proc_fini();
fail1:
	return rc;
}


static void cleanup_sfc_affinity(void)
{
	/* TODO shouldn't this take [lock]? */
	T(printk("sfc_affinity: cleaning up\n"));
	unregister_chrdev(dev_major, "sfc_affinity");
	efx_dl_unregister_driver(&dl_driver);
	while (! list_empty(&all_interfaces)) {
		struct aff_interface *intf;
		intf = list_entry(all_interfaces.next, struct aff_interface,
				  all_interfaces_link);
		interface_free(intf);
	}
	aff_proc_fini();
	T(printk("sfc_affinity: unloaded\n"));
}


module_init(init_sfc_affinity);
module_exit(cleanup_sfc_affinity);


int sfc_affinity_cpu_to_channel(int ifindex, int cpu)
{
	struct aff_interface *intf;
	int rc = -1;
	spin_lock(&lock);
	if (cpu >= 0 && cpu < num_possible_cpus() &&
	    (intf = interface_find(ifindex)) != NULL)
		rc = intf->cpu_to_q[cpu];
	spin_unlock(&lock);
	return rc;
}
EXPORT_SYMBOL(sfc_affinity_cpu_to_channel);
