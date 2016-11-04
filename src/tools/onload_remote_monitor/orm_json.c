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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  as
**  \brief  Dump state of all Onload stacks in json format to stdout.
**   \date  2014/12/01
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/* XXX: We are not handling the following types of stats from
 * 'onload_stackdump lots' yet.
 *
 * dump_stats(more_stats_fields, N_MORE_STATS_FIELDS, &more_stats, 0);
 * dump_stats(tcp_stats_fields, N_TCP_STATS_FIELDS, &t_stats, 0);
 * dump_stats(tcp_ext_stats_fields, N_TCP_EXT_STATS_FIELDS, &te_stats, 0);
 * dump_stats(udp_stats_fields, N_UDP_STATS_FIELDS, &u_stats, 0);
 */

#define _GNU_SOURCE

#include <ci/internal/ip.h>
#include <ci/efhw/common.h>
#include <ci/app/testapp.h>
#include <onload/ioctl.h>
#include <onload/driveraccess.h>
#include <onload/debug_intf.h>
#include <onload/version.h>

#include "ftl_defs.h"
#include <jansson.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRY(x)                                                  \
  do {                                                          \
    int __rc = (x);                                             \
    if( __rc < 0 ) {                                            \
      fprintf(stderr, "ERROR: '%s' failed\n", #x);              \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",           \
              __rc, errno, strerror(errno));                    \
      exit(EXIT_FAILURE);                                       \
    }                                                           \
  } while( 0 )


#define TEST(x)                                                 \
  do {                                                          \
    if( ! (x) ) {                                               \
      fprintf(stderr, "ERROR: '%s' failed\n", #x);              \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      exit(EXIT_FAILURE);                                       \
    }                                                           \
  } while( 0 )


/* flags to control which info gets output */
#define ORM_OUTPUT_NONE 0
#define ORM_OUTPUT_STATS 0x1
#define ORM_OUTPUT_STACK 0x10
#define ORM_OUTPUT_OPTS 0x100
#define ORM_OUTPUT_EXTRA 0x1000
#define ORM_OUTPUT_LOTS 0xFFF


/* output formats for the datatypes we support */
#define ci_uint64_fmt   "\"%llu\"" /* use string 
                                      as JSON can't cope with 64-bit int */
#define uint64_t_fmt    "\"%llu\""
#define ci_uint32_fmt   "%u"
#define uint32_t_fmt    "%u"
#define ci_uint16_fmt   "%u"
#define ci_uint8_fmt    "%u"
#define unsigned_fmt    "%u"
#define ci_int64_fmt    "\"%lld\""
#define ci_int32_fmt    "%d"
#define ci_int16_fmt    "%d"
#define ci_int8_fmt     "%d"
#define int_fmt         "%d"
#define ci_iptime_t_fmt "%u"
#define ef_eventq_ptr_fmt "%u"
#define CI_IP_STATS_TYPE_fmt "%u"
#define ci_iptime_callback_param_t_fmt "%u"
#define char_fmt        "%d"
#define ci_iptime_callback_fn_t_fmt "%u"
#define __TIME_TYPE___fmt "%u"
#define uid_t_fmt "%u"
#define ci_verlock_value_t_fmt "%u"
#define ci_ip_addr_t_fmt "%u"
#define ci_mtu_t_fmt "%u"
#define ci_ifid_t_fmt "%d"
#define cicp_encap_t_fmt "%u"
#define ci_hwport_id_t_fmt "%u"
#define ci_pkt_priority_t_fmt "%u"
#define oo_p_fmt "%d"
#define oo_pkt_p_fmt "%d"
#define oo_sp_fmt "\"%p\"" /* pointer - typically 64 bit */
#define oo_waitable_lock_fmt "%u"
#define oo_atomic_t_fmt "%u"



static char* cfg_stackname = NULL;
static ci_cfg_desc cfg_opts[] = {
  { 'h', "help", CI_CFG_USAGE, 0, "this message" },
  { 0, "name",  CI_CFG_STR,  &cfg_stackname, "select a single stack name" }
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))

/**********************************************************/
/* Manage stack mappings */
/**********************************************************/

struct orm_stack {
  ci_netif os_ni;
  int      os_id;
};

static struct orm_stack** orm_stacks = NULL;
static int n_orm_stacks = 0;


static int orm_map_stack(unsigned stack_id)
{
  int rc;
  orm_stacks = realloc(orm_stacks, (n_orm_stacks + 1) * sizeof(*orm_stacks));
  TEST(orm_stacks);
  struct orm_stack* orm_stack = calloc(1, sizeof(*orm_stack));
  TEST(orm_stack);
  orm_stacks[n_orm_stacks++] = orm_stack;
  orm_stack->os_id = stack_id;
  if( (rc = ci_netif_restore_id(&orm_stack->os_ni, stack_id)) != 0 )
    fprintf(stderr, "%s: Fail: ci_netif_restore_id(%d)=%d\n", __func__,
            stack_id, rc);
  return rc;
}


static int orm_map_stacks(void)
{
  int rc, i;
  oo_fd fd;
  if( (rc = oo_fd_open(&fd)) != 0 ) {
    fprintf(stderr, "%s: Fail: oo_fd_open()=%d.  Onload drivers loaded?",
            __func__, rc);
    return rc;
  }

  ci_netif_info_t info;
  memset(&info, 0, sizeof(ci_netif_info_t));
  i = 0;
  while( i >= 0 ) {
    info.ni_index = i;
    info.ni_orphan = 0;
    info.ni_subop = CI_DBG_NETIF_INFO_GET_NEXT_NETIF;
    if( (rc = oo_ioctl(fd, OO_IOC_DBG_GET_STACK_INFO, &info)) != 0 ) {
      fprintf(stderr, "%s: Fail: oo_ioctl(OO_IOC_DBG_GET_STACK_INFO)=%d.",
              __func__, rc);
      goto out;
    }
    if( info.ni_exists ) {
      int stack_id = info.ni_index;
      if( (rc = orm_map_stack(stack_id)) != 0 )
        goto out;
    }
    else if( info.ni_no_perms_exists ) {
      fprintf(stderr, "User %d:%d cannot access full details of stack %d(%s) "
              "owned by %d:%d share_with=%d\n", (int) getuid(), (int) geteuid(),
              info.ni_no_perms_id, info.ni_no_perms_name,
              (int) info.ni_no_perms_uid, (int) info.ni_no_perms_euid,
              info.ni_no_perms_share_with);
    }
    i = info.u.ni_next_ni.index;
  }

 out:
  oo_fd_close(fd);
  return rc;
}


/**********************************************************/
/* dump_buf mgmt */
/**********************************************************/

#define DUMP_BUF_INC 1024

struct dump_buf {
  char* db_buf;
  int   db_len;
  int   db_used;
};

static struct dump_buf db = {
  .db_buf  = NULL,
  .db_len  = 0,
  .db_used = 0,
};


static void __dump_buf_cat(const char* buf, int len)
{
  while( db.db_used + len > db.db_len ) {
    db.db_buf = realloc(db.db_buf, db.db_len + DUMP_BUF_INC);
    TEST(db.db_buf);
    db.db_len += DUMP_BUF_INC;
  }
  memcpy(db.db_buf + db.db_used, buf, len);
  db.db_used += len;
}


static void dump_buf_catv(const char* fmt, va_list va)
{
  int len;
  char* buf;
  TRY(len = vasprintf(&buf, fmt, va));
  __dump_buf_cat(buf, len);
  free(buf);
}


static void dump_buf_cat(const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  dump_buf_catv(fmt, va);
  va_end(va);
}


static void dump_buf_cleanup(void)
{
  /* Remove any extraneous characters at end of string for json
   * format */
  while( db.db_buf[db.db_used - 1] == ',' ||
         db.db_buf[db.db_used - 1] == ' ' ) {
    db.db_buf[db.db_used - 1] = '\0';
    --db.db_used;
  }
}


static const char* dump_buf_get(void)
{
  return db.db_buf;
}


/**********************************************************/
/* Dump ci_netif_opts */
/**********************************************************/

static int orm_oo_opts_dump(ci_netif* ni)
{
  ci_netif_config_opts* opts = &ni->state->opts;
  dump_buf_cat("\"opts\": {");

#ifdef NDEBUG
  dump_buf_cat("\"NDEBUG\": 1, ");
#else
  dump_buf_cat("\"NDEBUG\": 0, ");
#endif


#undef CI_CFG_OPTFILE_VERSION
#undef CI_CFG_OPT
#undef CI_CFG_OPTGROUP

#define CI_CFG_OPTFILE_VERSION(version)
#define CI_CFG_OPTGROUP(group, category, expertise)
#define CI_CFG_OPT(env, name, type, doc, bits, group, default, min, max, presentation) \
  if( strlen(env) != 0 ) {                                              \
    dump_buf_cat("\"%s\": " type##_fmt ", ", env, opts->name);          \
  }

#include <ci/internal/opts_netif_def.h>

  dump_buf_cleanup();
  dump_buf_cat("}");
  return 0;
}

/**********************************************************/
/* Dump ci_netif_stats */
/**********************************************************/

static int orm_oo_stats_dump(ci_netif* ni)
{
  ci_netif_stats* stats = &ni->state->stats;

  dump_buf_cat("\"stats\": {");

#undef  OO_STAT
#define OO_STAT(desc, type, name, kind)                                 \
  dump_buf_cat("\"%s\": " type##_fmt ", ", #name, stats->name);

#include <ci/internal/stats_def.h>

  dump_buf_cleanup();
  dump_buf_cat("}");
  return 0;
}


/*********************************************************/
/* Dump most structs using ftl definitions */
/*********************************************************/

/* manually create as config opts are defined separately
   TODO consider reordering */
static void orm_dump_struct_ci_netif_config_opts(char* label, ci_netif_config_opts* ignore, int flags)
{
  /* could fill in later if needed */
}

#undef FTL_TSTRUCT_BEGIN
#undef FTL_TUNION_BEGIN
#undef FTL_TFIELD_INT
#undef FTL_TFIELD_CONSTINT
#undef FTL_TFIELD_STRUCT
#undef FTL_TSTRUCT_END
#undef FTL_TUNION_END
#undef FTL_TFIELD_ARRAYOFINT
#undef FTL_TFIELD_ARRAYOFSTRUCT
#undef FTL_TFIELD_KINT
#undef FTL_TFIELD_ANON_STRUCT
#undef FTL_TFIELD_ANON_UNION
#undef FTL_TFIELD_ANON_ARRAYOFSTRUCT

#undef FTL_DECLARE

#define FTL_TSTRUCT_BEGIN(ctx, name, tag)                               \
  static void orm_dump_struct_body_##name(name*, int);                  \
  static void __attribute__((unused))                                   \
  orm_dump_struct_##name(const char* label, name* stats, int output_flags) \
  {                                                                     \
    /* ci_netif_stats got dumped separately above. */                   \
    if( ! strcmp(#name, "ci_netif_stats") )                             \
      return;                                                           \
                                                                        \
    dump_buf_cat("\"%s\": ", label);                                    \
    orm_dump_struct_body_##name(stats, output_flags);                   \
  }                                                                     \
  static void orm_dump_struct_body_##name(name* stats, int output_flags) \
  {                                                                     \
    dump_buf_cat("{");                                                  \
  /* don't close block here as rest of function is defined by macros
     below. FTL_TSTRUCT_END generates the corresponding closing brace */

#define FTL_TUNION_BEGIN(ctx, name, tag)        \
  FTL_TSTRUCT_BEGIN(ctx, name, tag)

#define FTL_TFIELD_INT(ctx, struct_name, type, field_name, display_flags) \
  if (output_flags & display_flags) {                                   \
    dump_buf_cat("\"%s\": ", #field_name);                              \
    dump_buf_cat(type##_fmt ", ", stats->field_name);                   \
  }

#define FTL_TFIELD_CONSTINT(ctx, struct_name, type, field_name, display_flags) \
  FTL_TFIELD_INT(ctx, struct_name, type, field_name, display_flags)

#define FTL_TFIELD_KINT(ctx, struct_name, type, field_name, display_flags) \
  FTL_TFIELD_INT(ctx, struct_name, type, field_name, display_flags)

/* the _INT2 variant is to cope for specials like IP addresses which are
   stored in one format, but need converting to another format for output */
#define FTL_TFIELD_INT2(ctx, struct_name, type, field_name, format_string, conversion_function, display_flags) \
  if (output_flags & display_flags) {                                   \
    dump_buf_cat("\"%s\": ", #field_name);                              \
    dump_buf_cat(format_string ", ", conversion_function(stats->field_name)); \
  }

#define FTL_TFIELD_STRUCT(ctx, struct_name, type, field_name, display_flags) \
  if (output_flags & display_flags) {                                   \
    orm_dump_struct_##type(#field_name, &stats->field_name, output_flags); \
  }

#define FTL_TFIELD_ARRAYOFINT(ctx, struct_name, type, field_name, len, display_flags) \
  if (output_flags & display_flags) {                                   \
    {                                                                   \
      int i;                                                            \
      dump_buf_cat("\"%s\": [", #field_name);                           \
      for( i = 0; i < (len); ++i ) {                                    \
        dump_buf_cat(type##_fmt ", ", stats->field_name[i]);            \
      }                                                                 \
      dump_buf_cleanup();                                               \
      dump_buf_cat("], ");                                              \
    }                                                                   \
  }

#define FTL_TFIELD_ARRAYOFSTRUCT(ctx, struct_name, type, field_name, len, display_flags) \
  if (output_flags & display_flags) {                                   \
    {                                                                   \
      int i;                                                            \
      dump_buf_cat("\"%s\": [", #field_name);                           \
      for( i = 0; i < (len); ++i ) {                                    \
        orm_dump_struct_body_##type(&stats->field_name[i], output_flags); \
      }                                                                 \
      dump_buf_cleanup();                                               \
      dump_buf_cat("], ");                                              \
    }                                                                   \
  }

#define FTL_TFIELD_ANON_STRUCT_BEGIN(ctx, struct_name, field_name, display_flags) \
     if (output_flags & display_flags) {                                \
      dump_buf_cat("\"%s\": {", #field_name);

#define FTL_TFIELD_ANON_STRUCT(ctx, struct_name, type, field_name, child) \
      dump_buf_cat("\"%s\": ", #child);                                 \
      dump_buf_cat(type##_fmt ", ", stats->field_name.child);

#define FTL_TFIELD_ANON_STRUCT_END(ctx, struct_name, field_name)        \
      dump_buf_cleanup();                                               \
      dump_buf_cat("}, ");                                              \
    }

/* anon union not yet implemented (only used for TCP/UDP headers) */
#define FTL_TFIELD_ANON_UNION_BEGIN(ctx, struct_name, field_name, display_flags)
#define FTL_TFIELD_ANON_UNION(ctx, struct_name, type, field_name, child)
#define FTL_TFIELD_ANON_UNION_END(ctx, struct_name, field_name)

#define FTL_TFIELD_ANON_ARRAYOFSTRUCT_BEGIN(ctx, struct_name, field_name, len, display_flags) \
    if (output_flags & display_flags) {                                 \
      int i;                                                            \
      dump_buf_cat("\"%s\": [", #field_name);                           \
      for( i = 0; i < (len); ++i ) {                                    \
        dump_buf_cat("{");

#define FTL_TFIELD_ANON_ARRAYOFSTRUCT(ctx, struct_name, type, field_name, child, len) \
        dump_buf_cat("\"%s\": ", #child);                               \
        dump_buf_cat(type##_fmt ", ", stats->field_name[i].child);

#define FTL_TFIELD_ANON_ARRAYOFSTRUCT_END(ctx, struct_name, field_name, len) \
        dump_buf_cleanup();                                             \
        dump_buf_cat("}, ");                                            \
      }                                                                 \
      dump_buf_cleanup();                                               \
      dump_buf_cat("], ");                                              \
    }

#define FTL_TSTRUCT_END(ctx)                                            \
    dump_buf_cleanup();                                                 \
    dump_buf_cat("}, ");                                                \
  }

#define FTL_TUNION_END(ctx)                                             \
  FTL_TSTRUCT_END(ctx)

#define FTL_DECLARE(a) a(DECL)

#include "ftl_decls.h"

static void orm_waitable_dump(ci_netif* ni, const char* sock_type, int output_flags)
{
  ci_netif_state* ns = ni->state;
  unsigned id;

  dump_buf_cat("\"%s\": {", sock_type);
  for( id = 0; id < ns->n_ep_bufs; ++id ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(ni, id);
    if( wo->waitable.state != CI_TCP_STATE_FREE ) {
      citp_waitable* w = &wo->waitable;

      if( (strcmp(sock_type, "tcp_listen") == 0) &&
          (w->state == CI_TCP_LISTEN) ) {
        dump_buf_cat("\"%d\": {", W_FMT(w));
        orm_dump_struct_ci_tcp_socket_listen("tcp_listen_sockets", &wo->tcp_listen, output_flags);
        dump_buf_cleanup();
        dump_buf_cat("}, ");
      }
      else if( (strcmp(sock_type, "tcp") == 0) &&
               (w->state & CI_TCP_STATE_TCP) ) {
        dump_buf_cat("\"%d\": {", W_FMT(w));
        orm_dump_struct_ci_tcp_state("tcp_state", &wo->tcp, output_flags);
        dump_buf_cleanup();
        dump_buf_cat("}, ");
      }
#if CI_CFG_UDP
      else if( (strcmp(sock_type, "udp") == 0) &&
               (w->state == CI_TCP_STATE_UDP) ) {
        dump_buf_cat("\"%d\": {", W_FMT(w));
        orm_dump_struct_ci_udp_state("udp_state", &wo->udp, output_flags);
        dump_buf_cleanup();
        dump_buf_cat("}, ");
      }
#endif

#if CI_CFG_USERSPACE_PIPE
      else if( (strcmp(sock_type, "pipe") == 0) &&
               (w->state == CI_TCP_STATE_PIPE) ) {
        dump_buf_cat("\"%d\": {", W_FMT(w));
        orm_dump_struct_oo_pipe("oo_pipe", &wo->pipe, output_flags);
        dump_buf_cleanup();
        dump_buf_cat("}, ");
      }
#endif
    }
  }
  dump_buf_cleanup();
  dump_buf_cat("}, ");
}


static int orm_shared_state_dump(ci_netif* ni, int output_flags)
{
  ci_netif_state* ns = ni->state;

  dump_buf_cat("\"stack\": {");
  orm_dump_struct_ci_netif_state("stack_state", ns, output_flags);
  orm_waitable_dump(ni, "tcp_listen", output_flags);
  orm_waitable_dump(ni, "tcp", output_flags);
  orm_waitable_dump(ni, "udp", output_flags);
  orm_waitable_dump(ni, "pipe", output_flags);
  dump_buf_cleanup();
  dump_buf_cat("}");

  return 0;
}


/**********************************************************/
/* Main */
/**********************************************************/

static int orm_netif_dump(ci_netif* ni, int id, int output_flags,
                          char* stackname)
{
  int rc;

  if (stackname != NULL) {
    if ( strcmp(stackname, ni->state->name) != 0 )
      return 0;
    dump_buf_cat("{\"%s\": {", stackname);
  }
  else {
    dump_buf_cat("{\"%d\": {", id);
  }

  if (output_flags & ORM_OUTPUT_STACK) {
    if( (rc = orm_shared_state_dump(ni, output_flags)) != 0 ) {
      fprintf(stderr,"stack error code %d\n",rc);
      return rc;
    }
    dump_buf_cleanup();
    dump_buf_cat(", ");
  }
  if (output_flags & ORM_OUTPUT_STATS) {
    if( (rc = orm_oo_stats_dump(ni)) != 0 ) {
      fprintf(stderr,"stats error code %d\n",rc);
      return rc;
    }
    dump_buf_cleanup();
    dump_buf_cat(", ");
  }
  if (output_flags & ORM_OUTPUT_OPTS) {
    if( (rc = orm_oo_opts_dump(ni)) != 0 ) {
      fprintf(stderr,"opts error code %d\n",rc);
      return rc;
    }
    dump_buf_cleanup();
    dump_buf_cat(", ");
  }
  dump_buf_cleanup();
  dump_buf_cat("}}");
  dump_buf_cat(", ");

  return 0;
}


int main(int argc, char* argv[])
{
  int i;
  char* json_buf;
  const char* buf;
  json_t* root;
  json_error_t error;
  int output_flags = ORM_OUTPUT_NONE;

  ci_app_standard_opts = 0;
  ci_app_getopt("[stats] [stack] [opts] [lots] [extra] [all]",
                &argc, argv, cfg_opts, N_CFG_OPTS);
  ++argv;  --argc;

  if (argc == 0)
    output_flags = ORM_OUTPUT_LOTS;
  for (i=0; i<argc; i++) {
    if ( !strcmp(argv[i], "stats") )
      output_flags |= ORM_OUTPUT_STATS;
    if ( !strcmp(argv[i], "stack") )
      output_flags |= ORM_OUTPUT_STACK;
    if ( !strcmp(argv[i], "opts") )
      output_flags |= ORM_OUTPUT_OPTS;
    if ( !strcmp(argv[i], "lots") )
      output_flags |= ORM_OUTPUT_LOTS;
    if ( !strcmp(argv[i], "extra") )
      output_flags |= ORM_OUTPUT_EXTRA;
    if ( !strcmp(argv[i], "all") )
      output_flags |= ORM_OUTPUT_LOTS | ORM_OUTPUT_EXTRA;
  }

  if( orm_map_stacks() != 0 )
    exit(EXIT_FAILURE);
  if( n_orm_stacks == 0 )
    return 0;

  dump_buf_cat("{\"onload_version\": \"%s\", ", ONLOAD_VERSION);
  dump_buf_cat("\"json\": [");

  for( i = 0; i < n_orm_stacks; ++i ) {
    ci_netif* ni = &orm_stacks[i]->os_ni;
    int id       = orm_stacks[i]->os_id;

    if( orm_netif_dump(ni, id, output_flags, cfg_stackname) != 0 )
      exit(EXIT_FAILURE);
  }

  dump_buf_cleanup();
  dump_buf_cat("]}");
  buf = dump_buf_get();
  if( (root = json_loads(buf, 0, &error)) == NULL ) {
    /* This should only fail if we're out of memory or we passed an
     * buf. */
    fprintf(stderr, "%s: json_loads(%s) failed.\n", __func__, buf);
    fprintf(stderr, "\terror: source:%s:%d:%d: text:%s position:%d\n",
            error.source, error.line, error.column, error.text, error.position);
    return -1;
  }

  /* This should only fail if we're out of memory. */
  json_buf = json_dumps(root, 0);
  TEST(json_buf);
  printf("%s\n", json_buf);
  free(json_buf);
  json_decref(root);

  return 0;
}
