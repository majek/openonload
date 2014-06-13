/*
** Copyright 2005-2012  Solarflare Communications Inc.
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

#ifndef __ONLOAD_NIC_H__
#define __ONLOAD_NIC_H__


struct oo_nic {
  struct efrm_client* efrm_client;
};


extern int oo_n_nics;
extern struct oo_nic oo_nics[];


extern struct oo_nic* oo_nic_add(struct efrm_client*);
extern void oo_nic_remove(struct oo_nic*);

extern struct oo_nic* oo_nic_find_ifindex(int ifindex);

extern int oo_nic_hwport(struct oo_nic*);


#endif  /* __ONLOAD_NIC_H__ */
