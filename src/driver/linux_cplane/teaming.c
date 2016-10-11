/*
** Copyright 2005-2016  Solarflare Communications Inc.
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

#include "linux_cplane_internal.h"
#include <net/genetlink.h>
#include <net/sock.h>
#include <linux/moduleparam.h>


#ifdef EFRM_HAVE_TEAMING
#include <uapi/linux/if_team.h>
#include <uapi/linux/if_arp.h>

/********************************************************************/
/* Poll NETLINK (or any other) socket and a callback when woken up. */

typedef void (*ci_sockpoll_callback_t)(void* arg, unsigned long key);

struct ci_sockpoll_socket {
  struct socket* s;
  unsigned long key;
  ci_sockpoll_callback_t callback;
  wait_queue_t wait;
};

static int ci_sockpoll_callback(wait_queue_t *wait, unsigned mode,
                                int sync, void *key_p)
{
  struct ci_sockpoll_socket* sp = container_of(wait, struct ci_sockpoll_socket, wait);
  unsigned long key = key_p ? (unsigned long)key_p : (unsigned long)-1;

  if( (key & sp->key) == 0 )
    return 0;

  sp->callback(sp->wait.private, key);
  return 0;
}

static struct ci_sockpoll_socket *
ci_sockpoll_ctor(struct socket* s, unsigned long key,
                 ci_sockpoll_callback_t callback, void* arg)
{
  struct ci_sockpoll_socket* sp = kmalloc(sizeof(*sp), GFP_KERNEL);

  if( sp == NULL )
    return NULL;

  sp->s = s;
  sp->key = key;
  sp->callback = callback;

  init_waitqueue_func_entry(&sp->wait, ci_sockpoll_callback);
  sp->wait.private = arg;
  add_wait_queue(sk_sleep(sp->s->sk), &sp->wait);
  
  return sp;
}

static void ci_sockpoll_dtor(struct ci_sockpoll_socket* nl)
{
  remove_wait_queue(sk_sleep(nl->s->sk), &nl->wait);
  kfree(nl);
}

static struct socket* ci_sockpoll_socket_get(struct ci_sockpoll_socket* nl)
{
  return nl->s;
}

static int __ci_sockpoll_send(struct socket* s,
                              void* buf, size_t buflen, int flags)
{
  struct msghdr msg;
  struct kvec iov;
  int rc;

  ci_assert_gt(buflen, 0);
  iov.iov_base = (void*)buf;
  iov.iov_len = buflen;
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_controllen = 0;
  msg.msg_flags = flags;

  rc = kernel_sendmsg(s, &msg, &iov, 1, iov.iov_len);
  ci_assert_equal(rc, buflen);
  return rc < 0 ? rc : 0;
}

static int ci_sockpoll_send(struct ci_sockpoll_socket* nl,
                            void* buf, size_t buflen, int flags)
{
  return __ci_sockpoll_send(nl->s, buf, buflen, flags);
}



/********************************************************************/
/*************** Create GENERIC NETLINK request *********************/

#define CI_TEAM_GENL_REQ_BUFSIZE \
  (NLMSG_HDRLEN + GENL_HDRLEN + NLA_ALIGN(GENL_NAMSIZ + 1))

static void *
__ci_genl_request_create(void* buf, size_t buflen, u16 nlmsg_type,
                         u8 genl_cmd, u8 genl_version,
                         u16 nla_type, u16 nla_len)
{
  struct nlmsghdr* nlh;
  struct genlmsghdr* genlhdr;
  struct nlattr* nla;

  ci_assert_ge(buflen, CI_TEAM_GENL_REQ_BUFSIZE);
  memset(buf, 0, buflen);
  nlh = (void *)buf;
  nlh->nlmsg_type = nlmsg_type;
  nlh->nlmsg_flags = NLM_F_REQUEST;
  genlhdr = nlmsg_data(nlh);
  genlhdr->cmd = genl_cmd;
  genlhdr->version = genl_version;
  nla = nlmsg_attrdata(nlh, GENL_HDRLEN);
  nla->nla_type = nla_type;
  nla->nla_len = nla_attr_size(nla_len);
  nlh->nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN + NLA_ALIGN(nla->nla_len);
  ci_assert_le(nlh->nlmsg_len, buflen);

  return nla_data(nla);
}
#define ci_genl_request_create(buf, buflen, nlmsg_type,              \
                               genl_cmd, genl_version,               \
                               nla_type, type_of_nla_data, nla_data) \
  *(type_of_nla_data *)                                              \
    __ci_genl_request_create(buf, buflen, nlmsg_type,                \
                             genl_cmd, genl_version, nla_type,       \
                             sizeof(type_of_nla_data)) = nla_data


static size_t ci_genl_request_len(void* buf)
{
  ci_assert_le(((struct nlmsghdr *)buf)->nlmsg_len,
               CI_TEAM_GENL_REQ_BUFSIZE);
  return ((struct nlmsghdr *)buf)->nlmsg_len;
}



/********************************************************************/
/******************** Kernel module parameters **********************/

static int oo_teaming_dump_period = HZ;
static struct kernel_param_ops ci_team_dump_period_ops;
module_param_cb(oo_teaming_dump_period, &ci_team_dump_period_ops,
                &oo_teaming_dump_period, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oo_teaming_dump_period,
"Period (in jiffies) between requiesting full state of all teaming "
"interfaces.  This is probably not needed at all because all updates "
"in the teaming interfaces are received via netlink.  You can set this "
"to 0 if you are sure that netlink messages are never lost.");

#ifndef NDEBUG
static int oo_teaming_listen_updates = true;
static struct kernel_param_ops ci_team_listen_updates_ops;
module_param_cb(oo_teaming_listen_updates, &ci_team_listen_updates_ops,
                &oo_teaming_listen_updates, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oo_teaming_listen_updates,
"Subscribe to teaming updates via netlink.  You probably want this "
"to be on.");
#else
#define oo_teaming_listen_updates true
#endif

/********************************************************************/
/****************** The teaming object structure ********************/

struct ci_team_control {
  cicp_handle_t* cplane;

  struct work_struct read_work;
  struct delayed_work dump_work;

  int grp_id;
  int family_id;
  struct mutex mutex; /* protects grp_id & family_id */

  struct ci_sockpoll_socket *gnl;
};


/********************************************************************/
/************ TEAM family management: dump & subscribe **************/

static void ci_team_dump_one(struct ci_team_control* c, int ifindex)
{
  char buf[CI_TEAM_GENL_REQ_BUFSIZE];
  int rc;

  /* It is important to keep the messages ordered.
   *
   * If we dump a team option here and it is changed just after the dump,
   * then we must process the dump before the change.  It is possible only
   * if we re-use the same netlink socket.
   *
   * Socket reuse makes things complicated - it is hard to detect when we
   * have received the answer and can remove any unknown slaves, but it is
   * worthwhile.
   */

  /* TEAM_CMD_PORT_LIST_GET */
  CP_DBG_BOND(ci_log("%s: TEAM_CMD_PORT_LIST_GET(%d)", __func__, ifindex));
  /* We've got a teaming iterface - so, family_id is probably
   * registered.  In case of races we'll get NLMSG_ERROR, which is not
   * a big deal. */
  ci_genl_request_create(buf, sizeof(buf),
                         c->family_id, TEAM_CMD_PORT_LIST_GET,
                         TEAM_GENL_VERSION, TEAM_ATTR_TEAM_IFINDEX,
                         u32, ifindex);
  ci_assert_equal(TEAM_GENL_VERSION, 1);

  rc = ci_sockpoll_send(c->gnl, buf, ci_genl_request_len(buf), 0);
  if( rc < 0 ) {
    ci_log("%s: failed to send TEAM_CMD_PORT_LIST_GET(%d) request",
           __func__, ifindex);
  }
  /* When we receive reply to TEAM_CMD_PORT_LIST_GET, we will issue
   * TEAM_CMD_OPTIONS_GET command.  See ci_team_teamnl_ports_parse(). */
}

static bool ci_team_netdev_is_team(struct net_device* dev)
{
  struct ethtool_drvinfo info;

  if( dev->type != ARPHRD_ETHER )
    return false;
  if( dev->ethtool_ops == NULL )
    return false;
  dev->ethtool_ops->get_drvinfo(dev, &info);
  if( strcmp(info.driver, "team") == 0 )
    return true;
  return false;
}

static void ci_team_dump(struct ci_team_control* c)
{
  struct net_device* dev;

  /* Add all known teaming interfaces: */
  rtnl_lock();
  for_each_netdev(&init_net, dev) {
    if( ci_team_netdev_is_team(dev) )
      ci_team_dump_one(c, dev->ifindex);
  }
  rtnl_unlock();

  /* When llap is removed, we also remove all bonding info.
   * Hence, we could add all unknown team interfacess and do not worry
   * about stale interfaces. */
}

static void ci_team_subscribe(struct ci_team_control* c)
{
  int opt = c->grp_id;
  int rc;

  ci_assert(mutex_is_locked(&c->mutex));
  ci_assert(c->grp_id);
  ci_assert(c->family_id);
  rc = kernel_setsockopt(ci_sockpoll_socket_get(c->gnl), SOL_NETLINK,
                         NETLINK_ADD_MEMBERSHIP,
                         (char *)&opt, sizeof(opt));
  if( rc != 0 ) {
    ci_log("Failed to register team family %d netlink group %d",
           c->family_id, c->grp_id);
  }
}
static void ci_team_unsubscribe(struct ci_team_control* c)
{
  int opt = c->grp_id;

  ci_assert(mutex_is_locked(&c->mutex));
  ci_assert(c->grp_id);
  ci_assert(c->family_id);

  kernel_setsockopt(ci_sockpoll_socket_get(c->gnl), SOL_NETLINK,
                    NETLINK_DROP_MEMBERSHIP,
                    (char *)&opt, sizeof(opt));
}

static int ci_team_dump_period_set(const char *val,
                                   const struct kernel_param *kp)
{
  int old_period = oo_teaming_dump_period;
  int rc = param_set_int(val, kp);
  if( rc != 0 )
    return rc;

  if( old_period == 0 && oo_teaming_dump_period != 0 ) {
    struct ci_team_control* c = CI_GLOBAL_CPLANE.team;

    CP_DBG_BOND(ci_log("%s: dump teaming state every %d jiffies.",
                       __func__, oo_teaming_dump_period));
    schedule_delayed_work(&c->dump_work, oo_teaming_dump_period);
  }
  return 0;
}
static struct kernel_param_ops ci_team_dump_period_ops = {
  .get = param_get_int,
  .set = ci_team_dump_period_set,
};

#ifndef NDEBUG
static int ci_team_listen_updates_set(const char *val,
                                      const struct kernel_param *kp)
{
  int old_updates = oo_teaming_listen_updates;
  struct ci_team_control* c = CI_GLOBAL_CPLANE.team;
  int rc = param_set_bool(val, kp);
  if( rc != 0 )
    return rc;

  if( c->grp_id == 0 )
    return 0;
  if( oo_teaming_listen_updates == old_updates )
    return 0;

  mutex_lock(&c->mutex);
  if( c->grp_id != 0 ) {
    if( oo_teaming_listen_updates )
      ci_team_subscribe(c);
    else
      ci_team_unsubscribe(c);
  }
  mutex_unlock(&c->mutex);

  return 0;
}
static struct kernel_param_ops ci_team_listen_updates_ops = {
  .get = param_get_bool,
  .set = ci_team_listen_updates_set,
};
#endif

static void ci_team_new_family(struct ci_team_control* c,
                               int family_id, int grp_id)
{
  if( family_id == c->family_id && grp_id == c->grp_id)
    return;

  mutex_lock(&c->mutex);

  if( c->grp_id != 0 ) {
    CP_DBG_BOND(ci_log("Unregister team family %d with netlink group %d",
                       c->family_id, c->grp_id));
    ci_team_unsubscribe(c);
    c->grp_id = 0;
  }

  if( family_id == 0 ) {
    ci_assert_equal(c->grp_id, 0);
    c->family_id = 0;
    ci_team_dump(c);
  }
  else
    c->family_id = family_id;

  if( grp_id != 0 ) {
    CP_DBG_BOND(ci_log("Register team family %d with netlink group %d",
                       family_id, grp_id));
    c->grp_id = grp_id;

    if( oo_teaming_listen_updates )
      ci_team_subscribe(c);
    mutex_unlock(&c->mutex);

    /* We've joined the grp_id, but it is possible that we've missed some
     * messages.  Even if the teaming driver have beed just loaded, it
     * could create a teaming interface before we get here.  So, we must
     * ask for the current state. */
    ci_team_dump(c);

    if( oo_teaming_dump_period )
      schedule_delayed_work(&c->dump_work, oo_teaming_dump_period);
  }
  else
    mutex_unlock(&c->mutex);
}

static void ci_team_genl_parse(struct ci_team_control* c,
                               const struct nlmsghdr* nlh)
{
  struct genlmsghdr* genlhdr;
  struct nlattr* nla;
  int team_family_id;

  ci_assert_equal(nlh->nlmsg_type, GENL_ID_CTRL);
  genlhdr = nlmsg_data(nlh);

  /* On 3.10, you'll see CTRL_CMD_NEWFAMILY without groups
   * + CTRL_CMD_NEWMCAST_GRP when team module is registered.
   * On 3.16, you'll see CTRL_CMD_NEWFAMILY with groups. */
  if( genlhdr->cmd != CTRL_CMD_NEWFAMILY &&
      genlhdr->cmd != CTRL_CMD_DELFAMILY &&
      genlhdr->cmd != CTRL_CMD_NEWMCAST_GRP &&
      genlhdr->cmd != CTRL_CMD_DELMCAST_GRP)
    return;
  nla = nlmsg_find_attr(nlh, GENL_HDRLEN, CTRL_ATTR_FAMILY_NAME);
  if( nla_strcmp(nla, TEAM_GENL_NAME) != 0 )
    return;
  if( genlhdr->cmd == CTRL_CMD_DELFAMILY ) {
    ci_team_new_family(c, 0, 0);
    return;
  }

  nla = nlmsg_find_attr(nlh, GENL_HDRLEN, CTRL_ATTR_FAMILY_ID);
  if( nla == NULL )
    return;
  ci_assert_equal(nla->nla_len, nla_attr_size(sizeof(u16)));
  team_family_id = nla_get_u16(nla);

  nla = nlmsg_find_attr(nlh, GENL_HDRLEN, CTRL_ATTR_MCAST_GROUPS);
  if( nla == NULL )
    return;

  /* Assume that team has only one mcast group: */
  nla = nla_find_nested(nla_data(nla), CTRL_ATTR_MCAST_GRP_ID);
  if( nla == NULL )
    return;

  ci_assert_equal(nla->nla_len, nla_attr_size(sizeof(u32)));

  if( genlhdr->cmd == CTRL_CMD_DELMCAST_GRP ) {
    ci_assert_equal(nla_get_u32(nla), c->grp_id);
    ci_team_new_family(c, team_family_id, 0);
  }
  else
    ci_team_new_family(c, team_family_id, nla_get_u32(nla));
}


/********************************************************************/
/********************* TEAM NETLINK messages ************************/

/* We are interested in the following options only: */
struct ci_team_option {
  char* name;
  int type;
  int per_port;
};
/* Synchronise this with ci_team_options[] !!! */
enum ci_team_option_type {
  CI_TEAM_OPTION_MODE,
  CI_TEAM_OPTION_ENABLED,
  CI_TEAM_OPTION_ACTIVEPORT,
  CI_TEAM_OPTION_BFP_HASH_FUNC,
  CI_TEAM_OPTION_MAX
};
/* Synchronise this with enum ci_team_option !!! */
static struct ci_team_option ci_team_options[] = {
  {"mode", NLA_STRING, 0},
  {"enabled", NLA_FLAG, 1},

  /* activebackup-specific */
  {"activeport", NLA_U32, 0},

  /* loadbalance-specific */
  {"bpf_hash_func", NLA_BINARY, 0},
};

static void ci_team_set_mode(struct ci_team_control* c,
                             int team_ifindex, int rowid,
                             const char* mode)
{
  int old_mode, new_mode;
  int rc;

  if( strcmp(mode, "activebackup") == 0 )
    new_mode = CICP_BOND_MODE_ACTIVE_BACKUP;
  else if( strcmp(mode, "loadbalance") == 0 )
    new_mode = CICP_BOND_MODE_802_3AD;
  else {
    /* unsupported mode */
    new_mode = CICP_BOND_MODE_BALANCE_XOR;
  }
  CP_DBG_BOND(ci_log("%s(ifindex=%d, %s) new_mode=%d", __func__,
                     team_ifindex, mode, new_mode));

  rc = cicp_bond_get_mode(c->cplane, rowid, team_ifindex, &old_mode);
  if( rc != 0 )
    return;

  if( new_mode != old_mode ) {
    rc = cicp_bond_update_mode(c->cplane, rowid, team_ifindex, new_mode);
    if( rc != 0 )
      return;
  }

  if( new_mode == CICP_BOND_MODE_802_3AD ) {
    /* bpf is not supported.  Using CICP_BOND_XMIT_POLICY_LAYER34. */
    if( new_mode != old_mode ) {
      cicp_bond_set_hash_policy(c->cplane, rowid, new_mode,
                                team_ifindex, CICP_BOND_XMIT_POLICY_LAYER34);
    }

  }
  if( new_mode == CICP_BOND_MODE_BALANCE_XOR ) {
    CP_DBG_BOND(ci_log("Unaccelerated mode %s team %d", mode, team_ifindex));
    cicp_llap_update_active_hwport(c->cplane, team_ifindex,
                                   CI_HWPORT_ID_BAD, rowid, true);
  }
}

static void ci_team_slave_add(struct ci_team_control* c,
                              int team_ifindex, int rowid, int port_ifindex,
                              bool linkup, bool is_dump)
{
  int port_rowid = cicp_bond_find_rowid(c->cplane, port_ifindex);
  int rc;
  cicp_encap_t encap;

  if( port_rowid != CICP_BOND_ROW_NEXT_BAD ) {
    if( is_dump )
      cicp_bond_mark_row(c->cplane, port_rowid, port_ifindex);
    return;
  }

  port_rowid = cicp_bond_add_slave(c->cplane, team_ifindex, port_ifindex);
  if( port_rowid < 0 ) {
    ci_log("%s: failed to add slave %d to team %d: %d", __func__,
           port_ifindex, team_ifindex, port_rowid);
    return;
  }
  if( !linkup )
    return;

  rc = cicp_llap_get_encapsulation(c->cplane, port_ifindex, &encap);
  if( rc != 0 || !(encap.type & CICP_LLAP_TYPE_SFC) ||
      (encap.type & CICP_LLAP_TYPE_VLAN) ) {
    CP_DBG_BOND(ci_log("Non-SFC port %d in team %d, not accelerating", 
                       port_ifindex, team_ifindex));
    cicp_llap_update_active_hwport(c->cplane, team_ifindex,
                                   CI_HWPORT_ID_BAD, rowid, true);
  }
  if( is_dump )
    cicp_bond_mark_row(c->cplane, port_rowid, port_ifindex);
}

static void ci_team_slave_del(struct ci_team_control* c,
                              int team_ifindex, int rowid, int port_ifindex)
{
  int port_rowid = cicp_bond_find_rowid(c->cplane, port_ifindex);

  if( port_rowid == CICP_BOND_ROW_NEXT_BAD )
    return;
  cicp_bond_remove_slave(c->cplane, team_ifindex, port_ifindex);
}

static void ci_team_slave_enable(struct ci_team_control* c,
                                 int team_ifindex, int rowid, int port_ifindex,
                                 int enabled)
{
  int port_rowid = cicp_bond_find_rowid(c->cplane, port_ifindex);
  ci_hwport_id_t curr_hwport, hwport;
  int rc;

  if( port_rowid == CICP_BOND_ROW_NEXT_BAD ) {
    ci_team_slave_add(c, team_ifindex, rowid, port_ifindex, enabled, false);
    port_rowid = cicp_bond_find_rowid(c->cplane, port_ifindex);
  }
  if( port_rowid == CICP_BOND_ROW_NEXT_BAD ) {
    CP_DBG_BOND(ci_log("%s: failed to add slave %d to team %d",
                       __func__, port_ifindex, team_ifindex));
    return;
  }

  cicp_bond_set_active(c->cplane, rowid, team_ifindex,
                       port_rowid, port_ifindex,
                       enabled);

  curr_hwport = cicp_llap_get_hwport(c->cplane, team_ifindex);
  rc = cicp_bond_check_active_slave_hwport(c->cplane, rowid, team_ifindex,
                                           curr_hwport, &hwport);
  if( rc != 0 )
    hwport = CI_HWPORT_ID_BAD;

  if( hwport != curr_hwport ) {
    cicp_llap_update_active_hwport(c->cplane, team_ifindex, hwport, rowid,
                                   hwport == CI_HWPORT_ID_BAD);
  }
}

static void ci_team_teamnl_options_parse(struct ci_team_control* c,
                                         int team_ifindex, int rowid,
                                         const struct nlattr* nla)
{
  const struct nlattr* nla1;
  const struct nlattr* nla2;
  int rc1, rc2;
  int port_ifindex;
  int type;
  bool changed, removed;
  const char *name;
  enum ci_team_option_type option;
  ci_uint32 val32;
  const char *val_str;
  int val_len;

  ci_assert(nla);
  ci_assert_equal(nla_type(nla), TEAM_ATTR_LIST_OPTION);
  nla_for_each_nested(nla1, nla, rc1) {
    ci_assert_equal(nla_type(nla1), TEAM_ATTR_ITEM_OPTION);

    option = CI_TEAM_OPTION_MAX;
    port_ifindex = 0;
    changed = removed = false;
    name = NULL;
    type = 0;
    val_str = NULL;
    val32 = 0;
    val_len = 0;

    nla_for_each_nested(nla2, nla1, rc2) {
      switch( nla_type(nla2) ) {
        case TEAM_ATTR_OPTION_NAME:
          name = nla_data(nla2);
          for( option = 0; option < CI_TEAM_OPTION_MAX; option++ )
            if( nla_strcmp(nla2, ci_team_options[option].name) == 0 )
              break;
          if( option == CI_TEAM_OPTION_MAX )
            goto next_option;
          break;

        case TEAM_ATTR_OPTION_CHANGED:
          ci_assert_equal(nla2->nla_len, nla_attr_size(0));
          changed = true;
          break;

        case TEAM_ATTR_OPTION_REMOVED:
          ci_assert_equal(nla2->nla_len, nla_attr_size(0));
          removed = true;
          break;

        case TEAM_ATTR_OPTION_TYPE:
          ci_assert_equal(nla2->nla_len, nla_attr_size(sizeof(u8)));
          type = nla_get_u8(nla2);
          break;

        case TEAM_ATTR_OPTION_DATA:
          ci_assert(type);
          switch(type) {
            case NLA_U32:
              ci_assert_equal(nla2->nla_len, nla_attr_size(sizeof(u32)));
              val32 = nla_get_u32(nla2);
              break;

            case NLA_FLAG:
              ci_assert_equal(nla2->nla_len, nla_attr_size(0));
              val32 = 1;
              break;

            case NLA_STRING:
              val_str = nla_data(nla2);
              break;

            case NLA_BINARY:
              val_str = nla_data(nla2);
              val_len = nla_len(nla2);
              break;
          }
          break;

        case TEAM_ATTR_OPTION_PORT_IFINDEX:
          ci_assert_equal(nla2->nla_len, nla_attr_size(sizeof(u32)));
          port_ifindex = nla_get_u32(nla2);
          break;

        case TEAM_ATTR_OPTION_ARRAY_INDEX:
          CP_DBG_BOND(ci_log("array"));
          ci_assert(0);
          break;

        default:
          ci_assert(0);
      }
    }
    CP_DBG_BOND(ci_log("Team %d port %d option %s val %d-%p-%s%s%s",
                       team_ifindex, port_ifindex, name,
                       val32, type == NLA_BINARY ? val_str : NULL,
                       type == NLA_STRING ? val_str : NULL,
                       changed ? " changed" : "",
                       removed ? " removed" : ""));
    ci_assert(type);
    ci_assert(name);
    ci_assert_equiv(port_ifindex,  ci_team_options[option].per_port);

   next_option:
    switch( option ) {
      case CI_TEAM_OPTION_MODE:
        ci_assert_equal(type, NLA_STRING);
        ci_assert(val_str);
        ci_team_set_mode(c, team_ifindex, rowid, val_str);
        break;

      case CI_TEAM_OPTION_BFP_HASH_FUNC:
        ci_assert_equal(type, NLA_BINARY);
        ci_assert(val_str);
        if( removed )
          cicp_bond_remove_master(c->cplane, team_ifindex);
        else {
          CP_DBG_BOND(ci_log("Teaming TX hash modes are not supported "
                             "by Onload.  Using l3+l4."));
        }
        break;

      case CI_TEAM_OPTION_ACTIVEPORT:
        ci_assert_equal(type, NLA_U32);
        if( removed )
          cicp_bond_remove_master(c->cplane, team_ifindex);
        else if( val32 != 0 )
          ci_team_slave_enable(c, team_ifindex, rowid, val32, true);
        break;

      case CI_TEAM_OPTION_ENABLED:
        ci_assert_equal(type, NLA_FLAG);
        ci_team_slave_enable(c, team_ifindex, rowid, port_ifindex, val32);
        break;

      default:
        ci_assert_equal(option, CI_TEAM_OPTION_MAX);
    }
  }
}

static void ci_team_teamnl_ports_parse(struct ci_team_control* c,
                                       int team_ifindex, int rowid,
                                       const struct nlattr* nla)
{
  const struct nlattr* nla1;
  const struct nlattr* nla2;
  int rc1, rc2;
  int port_ifindex;
  bool changed, removed, linkup, is_dump;

  ci_assert(nla);
  ci_assert_equal(nla_type(nla), TEAM_ATTR_LIST_PORT);
  is_dump = false;
  nla_for_each_nested(nla1, nla, rc1) {
    ci_assert_equal(nla_type(nla1), TEAM_ATTR_ITEM_PORT);

    port_ifindex = 0;
    changed = removed = false;
    linkup = false;

    nla_for_each_nested(nla2, nla1, rc2) {
      switch( nla_type(nla2) ) {
        case TEAM_ATTR_PORT_IFINDEX:
          ci_assert_equal(nla2->nla_len, nla_attr_size(sizeof(u32)));
          port_ifindex = nla_get_u32(nla2);
          break;

        case TEAM_ATTR_PORT_CHANGED:
          changed = true;
          break;

        case TEAM_ATTR_PORT_REMOVED:
          removed = true;
          break;

        case TEAM_ATTR_PORT_LINKUP:
          linkup = true;
          break;
      }
    }

    if( is_dump ) {
      ci_assert( !changed && !removed );
    }
    else if( !changed && !removed ) {
      is_dump = true;
    }
    CP_DBG_BOND(ci_log("Port %d in team %d %s%s%s%s",
                       port_ifindex, team_ifindex,
                       is_dump ? "DUMP" : "notify",
                       removed ? " removed" : "",
                       changed ? " changed" : "",
                       linkup ? " UP" : " DOWN"));
    ci_assert(port_ifindex);

    if( removed ) {
      ci_team_slave_del(c, team_ifindex, rowid, port_ifindex);
    }
    else {
      ci_team_slave_add(c, team_ifindex, rowid, port_ifindex,
                        linkup, is_dump);
    }
  }

  if( is_dump ) {
    char buf[CI_TEAM_GENL_REQ_BUFSIZE];
    int rc;

    cicp_bond_prune_unmarked_in_bond(c->cplane, team_ifindex);

    CP_DBG_BOND(ci_log("%s: TEAM_CMD_OPTIONS_GET(%d)",
                       __func__, team_ifindex));
    /* c->family_id might be outdated - and we'll get NLMSG_ERROR,
     * so it is not a big deal. */
    ci_genl_request_create(buf, sizeof(buf),
                           c->family_id, TEAM_CMD_OPTIONS_GET,
                           TEAM_GENL_VERSION, TEAM_ATTR_TEAM_IFINDEX,
                           u32, team_ifindex);
    ci_assert_equal(TEAM_GENL_VERSION, 1);

    rc = ci_sockpoll_send(c->gnl, buf, ci_genl_request_len(buf), 0);
    if( rc < 0 ) {
      ci_log("%s: failed to send TEAM_CMD_PORT_LIST_GET(%d) request",
             __func__, team_ifindex);
    }
  }
}

static void ci_team_teamnl_parse(struct ci_team_control* c,
                                 const struct nlmsghdr* nlh)
{
  struct genlmsghdr* genlhdr;
  const struct nlattr* nla;
  int team_ifindex;
  int rowid;
  int rc = nlh->nlmsg_len;

  /* This assert is incorrect: we can parse the message AFTER the family
   * was unregistered (and c->family_id=0).  However, it looks useful. */
  ci_assert_equal(nlh->nlmsg_type, c->family_id);

  genlhdr = nlmsg_data(nlh);

  rc -= NLMSG_HDRLEN + GENL_HDRLEN;
  nla = nlmsg_attrdata(nlh, GENL_HDRLEN);
  ci_assert_equal(nla_type(nla), TEAM_ATTR_TEAM_IFINDEX);
  ci_assert_equal(nla->nla_len, nla_attr_size(sizeof(u32)));
  team_ifindex = nla_get_u32(nla);
  rowid = cicp_bond_find_rowid(c->cplane, team_ifindex);
  if( rowid < 0 ) {
    struct net_device* netdev = dev_get_by_index(&init_net, team_ifindex);
    if( netdev != NULL ) {
      /* We get here before NETDEV_UP, so we should add llap entry first */
      cicpos_llap_import(c->cplane, NULL, team_ifindex, netdev->mtu,
                         netdev->flags & IFF_UP,
                         CICP_LLAP_TYPE_BOND, netdev->name, NULL);
      dev_put(netdev);
      cicp_llap_set_bond(c->cplane, team_ifindex);
      rowid = cicp_bond_find_rowid(c->cplane, team_ifindex);
    }
  }
  if( rowid < 0 ) {
    CP_DBG_BOND(ci_log("Can't find or add a row for team "
                       "ifindex=%d: %d", team_ifindex, rowid));
    return;
  }

  switch( genlhdr->cmd ) {
    case TEAM_CMD_OPTIONS_GET:
      ci_team_teamnl_options_parse(c, team_ifindex, rowid,
                                   nla_next(nla, &rc));

      break;

    case TEAM_CMD_PORT_LIST_GET:
      ci_team_teamnl_ports_parse(c, team_ifindex, rowid,
                                 nla_next(nla, &rc));
      break;

    default:
      ci_assert(0);
  }
}

/********************************************************************/
/************************** Work items ******************************/


static bool ci_team_nl_read(struct ci_team_control* c)
{
  struct socket* s = ci_sockpoll_socket_get(c->gnl);
  struct sk_buff* skb;
  struct nlmsghdr* nlh;
  int rc;

  skb = skb_recv_datagram(s->sk, 0, true, &rc);
  if( skb == NULL )
    return false;

  SKB_LINEAR_ASSERT(skb);
  nlh = (void *)skb->data;
  rc = skb->len;
  ci_assert( NLMSG_OK(nlh, rc) );

  if( nlh->nlmsg_type == GENL_ID_CTRL )
    ci_team_genl_parse(c, nlh);
  else if( nlh->nlmsg_type != NLMSG_ERROR )
    ci_team_teamnl_parse(c, nlh);
  nlh = NLMSG_NEXT(nlh, rc);
  ci_assert(rc == 0 || (NLMSG_OK(nlh, rc) && nlh->nlmsg_type == NLMSG_DONE));

  skb_free_datagram(s->sk, skb);
  return true;
}

void ci_team_nl_callback(void* arg, unsigned long key)
{
  struct ci_team_control* c = arg;

  schedule_work(&c->read_work);
}

static void ci_team_read_work(struct work_struct *work)
{
  struct ci_team_control* c = container_of(work, struct ci_team_control,
                                           read_work);
  while( ci_team_nl_read(c) );
}

static int ci_team_family_get(struct ci_team_control* c)
{
  char buf[CI_TEAM_GENL_REQ_BUFSIZE];

  strcpy(__ci_genl_request_create(buf, sizeof(buf),
                                  GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1,
                                  CTRL_ATTR_FAMILY_NAME,
                                  strlen(TEAM_GENL_NAME) + 1),
         TEAM_GENL_NAME);
  return ci_sockpoll_send(c->gnl, buf, ci_genl_request_len(buf), 0);
}

static void ci_team_dump_work(struct work_struct *work)
{
  struct ci_team_control* c = container_of(work, struct ci_team_control,
                                           dump_work.work);
  int rc;

  /* Refresh the team family id */
  rc = ci_team_family_get(c);
  if( rc < 0 ) {
    ci_log("%s: Failed to refresh \""TEAM_GENL_NAME"\" family id",
           __func__);
    return;
  }
  while( ci_team_nl_read(c) );

  /* Dump all the team interfaces */
  if( c->family_id != 0 )
    ci_team_dump(c);

  /* Respawn this work item */
  if( oo_teaming_dump_period )
    schedule_delayed_work(&c->dump_work, oo_teaming_dump_period);
}

/********************************************************************/
/******************** External API (init/fini) **********************/

int ci_teaming_init(cicp_handle_t* cplane)
{
  struct socket* s;
  char buf[CI_TEAM_GENL_REQ_BUFSIZE];
  struct sk_buff* skb;
  struct nlmsghdr* nlh;
  struct genlmsghdr* genlhdr;
  struct nlattr* nla;
  struct nlattr* nla1;
  int rc = -ENOMEM;
  struct ci_team_control* c = kmalloc(sizeof(*c), GFP_KERNEL);
  int opt = 0;

  if( c == NULL )
    return -ENOMEM;
  c->cplane = cplane;

  mutex_init(&c->mutex);
  c->family_id = 0;
  c->grp_id = 0;

  c->gnl = NULL;
  INIT_WORK(&c->read_work, ci_team_read_work);
  INIT_DELAYED_WORK(&c->dump_work, ci_team_dump_work);

  rc = sock_create_kern(&init_net, PF_NETLINK, SOCK_RAW, NETLINK_GENERIC, &s);
  if( rc != 0 )
    goto fail1;

  /* When we send TEAM_CMD_OPTIONS_GET, genl_family_rcv_msg() calls
   * netlink_capable(), which expects s->file to be installed.
   * Because of this, we should allocate the struct file which is do not
   * really needed. */
  if( sock_alloc_file(s, 0, NULL) == NULL )
    goto fail2;

  /* Get GENL_ID_CTRL/notify multicast group */
  ci_genl_request_create(buf, sizeof(buf),
                         GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1,
                         CTRL_ATTR_FAMILY_ID, u16, GENL_ID_CTRL);
  rc = __ci_sockpoll_send(s, buf, ci_genl_request_len(buf), 0);
  if( rc < 0 ) {
    ci_log("Failed to send NETLINK_GENERIC message: can't find "
           "GENL_ID_CTRL(%d) family", GENL_ID_CTRL);
    goto fail2;
  }

  /* Reply for GENL_ID_CTRL/notify multicast group */
  skb = skb_recv_datagram(s->sk, 0, false, &rc);
  if( skb == NULL ) {
    ci_log("Failed to get GENL_ID_CTRL/notify multicast group");
    goto fail2;
  }
  SKB_LINEAR_ASSERT(skb);

  nlh = (void *)skb->data;
  ci_assert( NLMSG_OK(nlh, skb->len) );
  rc = -EINVAL;
  if( nlh->nlmsg_type != GENL_ID_CTRL )
    goto fail3;
  genlhdr = nlmsg_data(nlh);
  if( genlhdr->cmd != CTRL_CMD_NEWFAMILY )
    goto fail3;
  nla = nlmsg_find_attr(nlh, GENL_HDRLEN, CTRL_ATTR_MCAST_GROUPS);
  if( nla == NULL )
    goto fail2;

  nla_for_each_nested(nla1, nla, rc) {
    struct nlattr* nla2;
    int rc1;
    int group_id = 0;
    int found = false;

    nla_for_each_nested(nla2, nla1, rc1) {
      switch( nla_type(nla2) ) {
        case CTRL_ATTR_MCAST_GRP_ID:
          ci_assert_equal(nla2->nla_len, nla_attr_size(sizeof(u32)));
          group_id = nla_get_u32(nla2);
          break;

        case CTRL_ATTR_MCAST_GRP_NAME:
          if( nla_strcmp(nla2, "notify") == 0 )
            found = true;
          break;

        default:
          /* it should not happen.  We want to be notified if kernel API
           * changes in future. */
          ci_assert(0);
      }
    }
    if( found )  {
      opt = group_id;
      break;
    }
  }
  skb_free_datagram(s->sk, skb);
  rc = -EINVAL;
  if( opt == 0 ) {
    ci_log("No notify multicast group in GENL_ID_CTRL family");
    goto fail2;
  }
  CP_DBG_BOND(ci_log("NETLINK_GENERIC GENL_ID_CTRL/notify "
                     "multicast group is %d", opt));


  /* Set up receive handler */
  c->gnl = ci_sockpoll_ctor(s, POLLIN, ci_team_nl_callback, c);
  if( c->gnl == NULL )
    goto fail2;

  /* Join GENL_ID_CTRL/notify group to receive details of the TEAM family. */
  rc = kernel_setsockopt(s, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                         (char *)&opt, sizeof(opt));
  if( rc != 0 ) {
    ci_log("Failed to NETLINK_ADD_MEMBERSHIP on NETLINK_GENERIC socket");
    goto fail4;
  }

  /* Explictly request TEAM_GENL_NAME family in case it is already
   * registered. */
  rc = ci_team_family_get(c);
  if( rc < 0 ) {
    ci_log("Failed to send NETLINK_GENERIC message: can't find "
           "\""TEAM_GENL_NAME"\" family");
    goto fail4;
  }

  cplane->team = c;
  return 0;

fail4:
  ci_sockpoll_dtor(c->gnl);
  flush_scheduled_work();
  goto fail2;
fail3:
  skb_free_datagram(s->sk, skb);
fail2:
  /* sock_release releases socket with or without file */
  sock_release(s);
fail1:
  kfree(c);
  ci_assert_lt(rc, 0);
  return rc;
}

void ci_teaming_fini(cicp_handle_t* cplane)
{
  struct ci_team_control* c = cplane->team;
  struct socket* s;

  oo_teaming_dump_period = 0;
  cancel_delayed_work_sync(&c->dump_work);
  flush_scheduled_work(); /* Read any OPTIONS_GET */
  flush_scheduled_work(); /* Read any PORT_LIST_GET */

  s = ci_sockpoll_socket_get(c->gnl);
  ci_sockpoll_dtor(c->gnl);
  flush_scheduled_work();
  sock_release(s);

  kfree(c);
}
#endif
