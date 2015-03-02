/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
 * Driver for Solarflare network controllers and boards
 * Copyright 2014-2015 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include <net/genetlink.h>
#include <linux/err.h>
#include <linux/netdevice.h>
#include <linux/wait.h>
#include <net/sock.h>
#include "mcdi_proxy.h"
#include "proxy_auth.h"
#include "mcdi_pcol.h"

#ifdef EFX_USE_MCDI_PROXY_AUTH_NL

/* Definition of the EFX_MCDI_PROXY genetlink protocol family. */

static u32 efx_mcdi_proxy_daemon_pid = 0; /* saved pid of daemon which did CONFIGURE */
static wait_queue_head_t efx_mcdi_proxy_ack_waitq;
static bool efq_mcdi_proxy_request_acked = false;

static void efx_mcdi_proxy_async_work(struct work_struct *work);
static DECLARE_WORK(efx_mcdi_proxy_async_work_struct, efx_mcdi_proxy_async_work);
static struct list_head efx_mcdi_proxy_async_list =
	LIST_HEAD_INIT(efx_mcdi_proxy_async_list);
spinlock_t efx_mcdi_proxy_async_lock;

#define EFX_MCDI_PROXY_ACK_TIMEOUT	HZ / 10
#define EFX_MCDI_PROXY_RETRIES	5

/* attributes */
enum {
	EFX_MCDI_PROXY_A_UNSPEC,
	EFX_MCDI_PROXY_A_IFINDEX,
	EFX_MCDI_PROXY_A_MCDI_CMD,
	EFX_MCDI_PROXY_A_MCDI_CMDS,
	EFX_MCDI_PROXY_A_PF_INDEX,
	EFX_MCDI_PROXY_A_VF_INDEX,
	EFX_MCDI_PROXY_A_HANDLE,
	EFX_MCDI_PROXY_A_MCDI_REQ,
	EFX_MCDI_PROXY_A_MCDI_RESP,
	EFX_MCDI_PROXY_A_REQ_SIZE,
	EFX_MCDI_PROXY_A_RESP_SIZE,
	EFX_MCDI_PROXY_A_RC,
	EFX_MCDI_PROXY_A_RID,
	EFX_MCDI_PROXY_A_PRIVILEGES,
	__EFX_MCDI_PROXY_A_MAX
};

/* attribute policy */
static struct nla_policy efx_mcdi_proxy_genl_policy[__EFX_MCDI_PROXY_A_MAX] = {
	[EFX_MCDI_PROXY_A_IFINDEX]	= { .type = NLA_U32 },
	[EFX_MCDI_PROXY_A_MCDI_CMD]	= { .type = NLA_U16 },
	[EFX_MCDI_PROXY_A_MCDI_CMDS]	= { .type = NLA_NESTED },
	[EFX_MCDI_PROXY_A_PF_INDEX]	= { .type = NLA_U16 },
	[EFX_MCDI_PROXY_A_VF_INDEX]	= { .type = NLA_U16 },
	[EFX_MCDI_PROXY_A_HANDLE]	= { .type = NLA_U64 },
	[EFX_MCDI_PROXY_A_MCDI_REQ]	= { .type = NLA_STRING },
	[EFX_MCDI_PROXY_A_MCDI_RESP]	= { .type = NLA_STRING },
	[EFX_MCDI_PROXY_A_REQ_SIZE]	= { .type = NLA_U16 },
	[EFX_MCDI_PROXY_A_RESP_SIZE]	= { .type = NLA_U16 },
	[EFX_MCDI_PROXY_A_RC]		= { .type = NLA_S32 },
	[EFX_MCDI_PROXY_A_RID]		= { .type = NLA_U16 },
	[EFX_MCDI_PROXY_A_PRIVILEGES]	= { .type = NLA_U32 },
};

/* family */
static struct genl_family efx_mcdi_proxy_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "EFX_MCDI_PROXY",
	.version = 1,
	.maxattr = __EFX_MCDI_PROXY_A_MAX - 1,
};

/* commands */
enum {
	EFX_MCDI_PROXY_C_UNSPEC,
	EFX_MCDI_PROXY_C_CONFIGURE_LIST,
	EFX_MCDI_PROXY_C_CONFIGURE_ONE,
	EFX_MCDI_PROXY_C_CONFIGURE_NONE,
	EFX_MCDI_PROXY_C_PROXY_REQUEST,
	EFX_MCDI_PROXY_C_PROXY_ALLOW,
	EFX_MCDI_PROXY_C_PROXY_DENY,
	EFX_MCDI_PROXY_C_PROXY_DONE,
	EFX_MCDI_PROXY_C_PROXY_ACK,
	EFX_MCDI_PROXY_C_PROXY_RC,
	EFX_MCDI_PROXY_C_PROXY_ACTION_REQ,
	EFX_MCDI_PROXY_C_PROXY_ACTION_RESP,
	__EFX_MCDI_PROXY_C_MAX,
};

static int efx_mcdi_proxy_send_request(struct efx_nic *efx, u64 uhandle,
			   u16 pf, u16 vf, u16 rid,
			   const void *request_buffer, size_t request_len);

static void efx_mcdi_proxy_stopped(struct efx_nic *efx);


/* command handlers */
static int efx_mcdi_proxy_missing_handler(struct sk_buff *skb, struct genl_info *info)
{
	printk(KERN_WARNING "Unhandled efx_mcdi_proxy command %d\n",
	       info->nlhdr->nlmsg_type);
	return -ENOSYS;
}

/* For commands which should never be received by the kernel */
static int efx_mcdi_proxy_wrong_way_handler(struct sk_buff *skb, struct genl_info *info)
{
	printk(KERN_WARNING "Unexpected incoming efx_mcdi_proxy command %d\n",
	       info->nlhdr->nlmsg_type);
	return -EINVAL;
}

#define _getattr(_name)	info->attrs[EFX_MCDI_PROXY_A_## _name ]
#define getattr(_name)	(_getattr(_name) == NULL ? NULL : nla_data(_getattr(_name)))

static inline struct net_device *efx_mcdi_proxy_get_dev(struct sk_buff *skb,
						   struct genl_info *info)
{
	u32 *ifindex = getattr(IFINDEX);
	struct net_device *dev;
	struct net *net;

	if (ifindex == NULL)
		return ERR_PTR(-EINVAL);
	if (skb && skb->sk)
		net = sock_net(skb->sk);
	else /* shouldn't happen */
		return ERR_PTR(-EIO);
	dev = dev_get_by_index(net, *ifindex);
	if (!dev)
		return ERR_PTR(-ENODEV);
	return dev;
}

static int efx_mcdi_proxy_do_configure_list(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev = efx_mcdi_proxy_get_dev(skb, info);
	u32 *handled_privileges = getattr(PRIVILEGES);
	u16 *req_size = getattr(REQ_SIZE),
	    *resp_size = getattr(RESP_SIZE),
	    *mcdi_cmd;
	struct nlattr *nla_mcdi;
	struct efx_nic *efx;
	unsigned int nops, op_i = 0;
	unsigned int *ops;
	int rc;
	int i;

	if (IS_ERR(dev))
		return PTR_ERR(dev);
	efx = netdev_priv(dev);
	if (info->attrs[EFX_MCDI_PROXY_A_MCDI_CMDS] == NULL) {
		rc = -EINVAL;
		goto out1;
	}
	if (req_size == NULL || resp_size == NULL) {
		rc = -EINVAL;
		goto out1;
	}

	/* each u16 takes up 8 bytes when encoded */
	nops = nla_len(info->attrs[EFX_MCDI_PROXY_A_MCDI_CMDS]) / 8;
	ops = kmalloc_array(nops, sizeof(*ops), GFP_KERNEL);
	if (ops == NULL) {
		rc = -ENOMEM;
		goto out1;
	}
	nla_for_each_nested(nla_mcdi, info->attrs[EFX_MCDI_PROXY_A_MCDI_CMDS], i) {
		if (nla_type(nla_mcdi) != EFX_MCDI_PROXY_A_MCDI_CMD) {
			rc = -EINVAL;
			goto out2;
		}
		mcdi_cmd = nla_data(nla_mcdi);
		if (WARN_ON(op_i > nops - 1)) { /* our size calculation was bogus! */
			rc = -ENOBUFS;
			goto out2;
		}
		ops[op_i++] = *mcdi_cmd;
	}
	if (WARN_ON(op_i != nops)) { /* our size calculation was bogus! */
		rc = -ENOBUFS;
		goto out2;
	}

	rc = efx_proxy_auth_configure_list(efx, *req_size, *resp_size, ops, nops,
			handled_privileges ? *handled_privileges : 0,
			MC_CMD_PROXY_COMPLETE_IN_TIMEDOUT,
			efx_mcdi_proxy_send_request, efx_mcdi_proxy_stopped);
	if (rc == 0)
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_OLD_GENL_INFO)
		efx_mcdi_proxy_daemon_pid = info->snd_pid;
#else
		efx_mcdi_proxy_daemon_pid = info->snd_portid;
#endif
out2:
	kfree(ops);
out1:
	dev_put(dev);
	return rc;
}

static int efx_mcdi_proxy_do_configure_one(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev = efx_mcdi_proxy_get_dev(skb, info);
	u32 *handled_privileges = getattr(PRIVILEGES);
	u16 *mcdi_cmd = getattr(MCDI_CMD),
	    *req_size = getattr(REQ_SIZE),
	    *resp_size = getattr(RESP_SIZE);
	struct efx_nic *efx;
	int rc;

	if (IS_ERR(dev))
		return PTR_ERR(dev);
	efx = netdev_priv(dev);
	if (mcdi_cmd == NULL || req_size == NULL || resp_size == NULL) {
		rc = -EINVAL;
		goto out;
	}
	rc = efx_proxy_auth_configure_one(efx, *req_size, *resp_size, *mcdi_cmd,
			handled_privileges ? *handled_privileges : 0,
			MC_CMD_PROXY_COMPLETE_IN_TIMEDOUT,
			efx_mcdi_proxy_send_request, efx_mcdi_proxy_stopped);
	if (rc == 0)
#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_OLD_GENL_INFO)
		efx_mcdi_proxy_daemon_pid = info->snd_pid;
#else
		efx_mcdi_proxy_daemon_pid = info->snd_portid;
#endif
out:
	dev_put(dev);
	return rc;
}

static int efx_mcdi_proxy_do_configure_none(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev = efx_mcdi_proxy_get_dev(skb, info);
	struct efx_nic *efx;
	int rc;

	if (IS_ERR(dev))
		return PTR_ERR(dev);
	efx = netdev_priv(dev);
	rc = efx_proxy_auth_stop(efx, false);
	if (rc == 0)
		efx_mcdi_proxy_daemon_pid = 0;
out:
	dev_put(dev);
	return rc;
}

static void efx_mcdi_proxy_stopped(struct efx_nic *efx)
{
	/* Proxying is dead so we send a CONFIGURE_NONE to the daemon */
	struct sk_buff *skb;
	void *msg_head;
	int rc, tries;

	if (!efx_mcdi_proxy_daemon_pid) {
		netif_warn(efx, drv, efx->net_dev,
			   "efx_mcdi_proxy_stopped has no daemon pid\n");
		return;
	}

	for (tries = 0; tries < EFX_MCDI_PROXY_RETRIES; tries++)
	{
		if (tries)
			netif_dbg(efx, drv, efx->net_dev,
				  "efx_mcdi_proxy_stopped retry %d\n", tries);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
		if (skb == NULL)
			return;
		msg_head = genlmsg_put(skb, efx_mcdi_proxy_daemon_pid, 0,
				       &efx_mcdi_proxy_genl_family,
				       NLM_F_REQUEST | NLM_F_ACK,
				       EFX_MCDI_PROXY_C_CONFIGURE_NONE);
		if (msg_head == NULL) {
			rc = -ENOMEM;
			goto fail;
		}
		rc = nla_put_u32(skb, EFX_MCDI_PROXY_A_IFINDEX, efx->net_dev->ifindex);
		if (rc)
			goto fail;

		genlmsg_end(skb, msg_head);
		efq_mcdi_proxy_request_acked = false;
		init_waitqueue_head(&efx_mcdi_proxy_ack_waitq);
		rc = genlmsg_unicast(efx->net_dev->nd_net, skb, efx_mcdi_proxy_daemon_pid);
		if (rc != 0)
			/* genlmsg_unicast frees the skb in the event of failure. */
			return;
		if(wait_event_timeout(efx_mcdi_proxy_ack_waitq, efq_mcdi_proxy_request_acked,
				      EFX_MCDI_PROXY_ACK_TIMEOUT) > 0)
			return;
	}
	return;

fail:
	nlmsg_free(skb);
}

struct efx_mcdi_proxy_async_response {
	struct net *net;
	unsigned long cookie;
	int rc;
	size_t outlen;
	struct list_head list;
	struct efx_dword_t *data;
};

static void efx_mcdi_proxy_async_completer(struct efx_nic *efx,
		      unsigned long cookie, int rc,
		      efx_dword_t *outbuf,
		      size_t outlen_actual)
{
	struct efx_mcdi_proxy_async_response *rsp;

	rsp = kzalloc(sizeof(*rsp) + outlen_actual, GFP_KERNEL);
	if (!rsp)
		return;

	rsp->net = get_net(efx->net_dev->nd_net);
	rsp->cookie = cookie;
	rsp->rc = rc;
	rsp->outlen = outlen_actual;
	rsp->data = (void*)(rsp + 1);
	memcpy(rsp->data, outbuf, outlen_actual);

	spin_lock(&efx_mcdi_proxy_async_lock);
	list_add_tail(&rsp->list, &efx_mcdi_proxy_async_list);
	spin_unlock(&efx_mcdi_proxy_async_lock);

	schedule_work(&efx_mcdi_proxy_async_work_struct);
}

static void efx_mcdi_proxy_async_work(struct work_struct *work)
{
	struct efx_mcdi_proxy_async_response *rsp;
	struct sk_buff *skb;
	void *msg_head;

	do {
		spin_lock(&efx_mcdi_proxy_async_lock);
		rsp = list_first_entry_or_null(&efx_mcdi_proxy_async_list,
				struct efx_mcdi_proxy_async_response, list);
		if (rsp)
			list_del(&rsp->list);
		spin_unlock(&efx_mcdi_proxy_async_lock);

		if (!rsp)
			break;

		/* TODO: should stick a retry loop in. */
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
		if (!skb)
			goto out;
		msg_head = genlmsg_put(skb, efx_mcdi_proxy_daemon_pid,
				rsp->cookie & 0xffffffff,
				&efx_mcdi_proxy_genl_family,
				NLM_F_REQUEST,
				EFX_MCDI_PROXY_C_PROXY_ACTION_RESP);
		if (!msg_head)
			goto fail_free;

		if (nla_put_u64(skb, EFX_MCDI_PROXY_A_HANDLE, rsp->cookie))
			goto fail_free;
		if (nla_put_u32(skb, EFX_MCDI_PROXY_A_RC, rsp->rc))
			goto fail_free;

		if ((rsp->rc == 0) && (rsp->outlen) &&
		    (nla_put(skb, EFX_MCDI_PROXY_A_MCDI_RESP,
			     rsp->outlen, rsp->data)))
			goto fail_free;

		genlmsg_end(skb, msg_head);
		genlmsg_unicast(rsp->net, skb, efx_mcdi_proxy_daemon_pid);
        goto out;
fail_free:
		nlmsg_free(skb);
out:
		put_net(rsp->net);
		kfree(rsp);
		rsp = NULL;
	} while(1);
}

static int efx_mcdi_proxy_do_proxy_action_req(struct sk_buff *skb,
		struct genl_info *info)
{
	struct net_device *dev = efx_mcdi_proxy_get_dev(skb, info);
	struct nlattr *req = getattr(MCDI_REQ);
	u64 *cookie = getattr(HANDLE);
	u16 *mcdi_cmd = getattr(MCDI_CMD);
	u16 *outlen = getattr(RESP_SIZE);

	struct efx_nic *efx;
	int rc;

	if (IS_ERR(dev))
		return -PTR_ERR(dev);
	efx = netdev_priv(dev);

	req = info->attrs[EFX_MCDI_PROXY_A_MCDI_REQ];

	if (mcdi_cmd == NULL || req == NULL ||
	    cookie == NULL || outlen == NULL) {
		rc = -EINVAL;
		goto out1;
	}

	rc = efx_mcdi_rpc_async(efx, *mcdi_cmd,
		   nla_data(req), nla_len(req), *outlen,
		   efx_mcdi_proxy_async_completer, *cookie);

out1:
	dev_put(dev);
	return rc;
}

struct efx_mcdi_proxy_proxy_context {
	struct net *net;
	u32 ifindex;
	u32 seqno;
	u64 handle;
};

static void efx_mcdi_proxy_proxy_callback(int mcdi_rc, void *_ctx)
{
	struct efx_mcdi_proxy_proxy_context *ctx = _ctx;
	struct sk_buff *skb;
	void *msg_head;

	if (!efx_mcdi_proxy_daemon_pid) {
		printk(KERN_WARNING "efx_mcdi_proxy_proxy_callback has no daemon pid\n");
		return;
	}

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL)
		goto out;
	msg_head = genlmsg_put(skb, efx_mcdi_proxy_daemon_pid, ctx->seqno,
			       &efx_mcdi_proxy_genl_family, NLM_F_REQUEST,
			       EFX_MCDI_PROXY_C_PROXY_RC);
	if (msg_head == NULL)
		goto fail;

	if (nla_put_u32(skb, EFX_MCDI_PROXY_A_IFINDEX, ctx->ifindex))
		goto fail;
	if (nla_put_u64(skb, EFX_MCDI_PROXY_A_HANDLE, ctx->handle))
		goto fail;
	if (nla_put_s32(skb, EFX_MCDI_PROXY_A_RC, mcdi_rc))
		goto fail;

	genlmsg_end(skb, msg_head);
	genlmsg_unicast(ctx->net, skb, efx_mcdi_proxy_daemon_pid);
	/* genlmsg_unicast frees skb even in error cases */
	goto out;

fail:
	nlmsg_free(skb);
out:
	put_net(ctx->net);
	return;
}

static int efx_mcdi_proxy_do_proxy_handled(struct sk_buff *skb,
		struct genl_info *info, unsigned int result,
		u32 granted_privileges)
{
	struct net_device *dev = efx_mcdi_proxy_get_dev(skb, info);
	struct efx_mcdi_proxy_proxy_context *ctx;
	u64 *handle = getattr(HANDLE);
	struct efx_nic *efx;
	int rc;

	if (IS_ERR(dev))
		return PTR_ERR(dev);
	efx = netdev_priv(dev);
	if (handle == NULL) {
		rc = -EINVAL;
		goto out;
	}
	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (ctx == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	ctx->ifindex = efx->net_dev->ifindex;
	ctx->handle = *handle;
	ctx->seqno = info->snd_seq;
	ctx->net = get_net(efx->net_dev->nd_net);
	rc = efx_proxy_auth_handle_response(efx->proxy_admin_state, *handle,
					    result, granted_privileges, NULL, 0,
					    efx_mcdi_proxy_proxy_callback, ctx);
	if (rc)
		kfree(ctx);
	else
		rc = -EINPROGRESS;
out:
	dev_put(dev);
	return rc;
}

static int efx_mcdi_proxy_do_proxy_allow(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev = efx_mcdi_proxy_get_dev(skb, info);
	u32 *granted_privileges = getattr(PRIVILEGES);
	int rc;

	if (IS_ERR(dev))
		return PTR_ERR(dev);
	if (granted_privileges == NULL) {
		dev_put(dev);
		return -EINVAL;
	}

	rc = efx_mcdi_proxy_do_proxy_handled(skb, info,
			MC_CMD_PROXY_COMPLETE_IN_AUTHORIZED,
			*granted_privileges);
	dev_put(dev);
	return rc;
}

static int efx_mcdi_proxy_do_proxy_deny(struct sk_buff *skb, struct genl_info *info)
{
	return efx_mcdi_proxy_do_proxy_handled(skb, info,
			MC_CMD_PROXY_COMPLETE_IN_DECLINED, 0);
}

static int efx_mcdi_proxy_do_proxy_done(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev = efx_mcdi_proxy_get_dev(skb, info);
	const struct nlattr *resp = info->attrs[EFX_MCDI_PROXY_A_MCDI_RESP];
	struct efx_mcdi_proxy_proxy_context *ctx;
	u64 *handle = getattr(HANDLE);
	struct efx_nic *efx;
	int rc;

	if (IS_ERR(dev))
		return PTR_ERR(dev);
	efx = netdev_priv(dev);
	if (resp == NULL || handle == NULL) {
		rc = -EINVAL;
		goto out;
	}
	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (ctx == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	ctx->ifindex = efx->net_dev->ifindex;
	ctx->handle = *handle;
	ctx->seqno = info->snd_seq;
	ctx->net = get_net(efx->net_dev->nd_net);
	rc = efx_proxy_auth_handle_response(efx->proxy_admin_state, *handle,
					    MC_CMD_PROXY_COMPLETE_IN_COMPLETE,
					    0, nla_data(resp), nla_len(resp),
					    efx_mcdi_proxy_proxy_callback, ctx);
	if (rc)
		kfree(ctx);
	else
		rc = -EINPROGRESS;
out:
	dev_put(dev);
	return rc;
}

static int efx_mcdi_proxy_do_proxy_ack(struct sk_buff *skb, struct genl_info *info)
{
	efq_mcdi_proxy_request_acked = true;
	wake_up(&efx_mcdi_proxy_ack_waitq);
	return 0;
}

/* operation definition */
#define EFX_MCDI_PROXY_OP(_cmd, _handler) [ EFX_MCDI_PROXY_C_## _cmd ] = { \
	.cmd = EFX_MCDI_PROXY_C_## _cmd,				   \
	.flags = GENL_ADMIN_PERM,					   \
	.policy = efx_mcdi_proxy_genl_policy,				   \
	.doit = efx_mcdi_proxy_## _handler,				   \
	.dumpit = NULL,							   \
	}
static struct genl_ops efx_mcdi_proxy_genl_ops[__EFX_MCDI_PROXY_C_MAX] = {
	EFX_MCDI_PROXY_OP(UNSPEC, missing_handler),
	EFX_MCDI_PROXY_OP(CONFIGURE_LIST, do_configure_list),
	EFX_MCDI_PROXY_OP(CONFIGURE_ONE, do_configure_one),
	EFX_MCDI_PROXY_OP(CONFIGURE_NONE, do_configure_none),
	EFX_MCDI_PROXY_OP(PROXY_REQUEST, wrong_way_handler),
	EFX_MCDI_PROXY_OP(PROXY_ALLOW, do_proxy_allow),
	EFX_MCDI_PROXY_OP(PROXY_DENY, do_proxy_deny),
	EFX_MCDI_PROXY_OP(PROXY_DONE, do_proxy_done),
	EFX_MCDI_PROXY_OP(PROXY_ACK, do_proxy_ack),
	EFX_MCDI_PROXY_OP(PROXY_RC, wrong_way_handler),
	EFX_MCDI_PROXY_OP(PROXY_ACTION_REQ, do_proxy_action_req),
	EFX_MCDI_PROXY_OP(PROXY_ACTION_RESP, wrong_way_handler),
};

static int efx_mcdi_proxy_send_request(struct efx_nic *efx, u64 uhandle,
			   u16 pf, u16 vf, u16 rid,
			   const void *request_buffer, size_t request_len)
{
	struct sk_buff *skb;
	void *msg_head;
	int rc, tries;

	if (!efx_mcdi_proxy_daemon_pid) {
		netif_warn(efx, drv, efx->net_dev,
			   "efx_mcdi_proxy_send_request has no daemon pid\n");
		return -ENOENT;
	}

	for (tries = 0; tries < EFX_MCDI_PROXY_RETRIES; tries++)
	{
		if (tries)
			netif_dbg(efx, drv, efx->net_dev,
				  "efx_mcdi_proxy_send_request retry %d\n", tries);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
		if (skb == NULL)
			return -ENOMEM;
		msg_head = genlmsg_put(skb, efx_mcdi_proxy_daemon_pid, uhandle >> 32,
				       &efx_mcdi_proxy_genl_family,
				       NLM_F_REQUEST | NLM_F_ACK,
				       EFX_MCDI_PROXY_C_PROXY_REQUEST);
		if (msg_head == NULL) {
			rc = -ENOMEM;
			goto fail;
		}
		rc = nla_put_u32(skb, EFX_MCDI_PROXY_A_IFINDEX, efx->net_dev->ifindex);
		if (rc)
			goto fail;
		rc = nla_put_u16(skb, EFX_MCDI_PROXY_A_PF_INDEX, pf);
		if (rc)
			goto fail;
		rc = nla_put_u16(skb, EFX_MCDI_PROXY_A_VF_INDEX, vf);
		if (rc)
			goto fail;
		rc = nla_put_u16(skb, EFX_MCDI_PROXY_A_RID, rid);
		if (rc)
			goto fail;
		rc = nla_put_u64(skb, EFX_MCDI_PROXY_A_HANDLE, uhandle);
		if (rc)
			goto fail;
		rc = nla_put(skb, EFX_MCDI_PROXY_A_MCDI_REQ, request_len, request_buffer);
		if (rc)
			goto fail;

		genlmsg_end(skb, msg_head);
		efq_mcdi_proxy_request_acked = false;
		init_waitqueue_head(&efx_mcdi_proxy_ack_waitq);
		rc = genlmsg_unicast(efx->net_dev->nd_net, skb, efx_mcdi_proxy_daemon_pid);
		if (rc != 0)
			return rc;
		if(wait_event_timeout(efx_mcdi_proxy_ack_waitq, efq_mcdi_proxy_request_acked,
				      EFX_MCDI_PROXY_ACK_TIMEOUT) > 0)
			return 0;
	}
	return -ETIMEDOUT;

fail:
	nlmsg_free(skb);
	return rc;
}

int efx_mcdi_proxy_nl_register(void)
{
	int rc;

#if !defined(EFX_USE_KCOMPAT) || defined(genl_register_family_with_ops) /* It became a macro at the same time the arguments changed */
	rc = genl_register_family_with_ops(&efx_mcdi_proxy_genl_family,
					   efx_mcdi_proxy_genl_ops);
#else
	rc = genl_register_family_with_ops(&efx_mcdi_proxy_genl_family,
					   efx_mcdi_proxy_genl_ops,
					   __EFX_MCDI_PROXY_C_MAX);
#endif
	if (rc)
		printk(KERN_ERR "Failed to register efx_mcdi_proxy genl family rc=%d\n",
		       rc);
	else
		printk(KERN_INFO "Registered efx_mcdi_proxy genl family as %u\n",
		       efx_mcdi_proxy_genl_family.id);

	return rc;
}

int efx_mcdi_proxy_nl_unregister(void)
{
	return genl_unregister_family(&efx_mcdi_proxy_genl_family);
}

#endif /* EFX_USE_MCDI_PROXY_AUTH_NL */

