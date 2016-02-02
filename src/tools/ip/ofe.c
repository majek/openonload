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

#include <fnmatch.h>
#include <ci/internal/ip.h>
#include "libstack.h"
#include <ci/app.h>
#include <onload/common.h>
#include <onload/unix_intf.h>
#include "ofe/onload.h"

/* Stack name of id: */
char *cfg_stack_name = NULL;
ci_uint32 cfg_stack_id;

/* For do_ofe_stats & do_ofe_command,
 * we pass argv and argc via cfg_argv & cfg_argc. */
static char **cfg_argv = NULL;
static int cfg_argc = 0;

static ci_cfg_desc cfg_opts[] = {
  { 'o', "onload_stack", CI_CFG_STR, &cfg_stack_name,
                        "stack id or stack name regexp"},
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))


static void usage(const char* msg)
{
  if( msg ) {
    ci_log(" ");
    ci_log("%s", msg);
  }

  ci_log(" ");
  ci_log("usage:");
  ci_log("  %s [options] info", ci_appname);
  ci_log("  %s [options] stats [<counter name> ...]", ci_appname);
  ci_log("  %s [options] command <ofe command>", ci_appname);

  ci_log(" ");
  ci_log("options:");
  ci_app_opt_usage(cfg_opts, N_CFG_OPTS);
  ci_log(" ");
  exit(-1);
}

static int stackfilter_match_name(ci_netif_info_t *info)
{
  if( cfg_stack_id == (ci_uint32)(-1) && cfg_stack_name == NULL )
    return 1;
  if( info->ni_index == cfg_stack_id )
    return 1;
  if( cfg_stack_name != NULL &&
      fnmatch(cfg_stack_name, info->ni_name, 0) == 0)
    return 1;
  return 0; /* Not interested */
}

static void do_ofe_info(ci_netif *ni)
{
  struct ofe_stats_usage stat;
  struct ofe_stats_table table;
  char table_name[30];
  enum ofe_status rc;

  if( ni->ofe == NULL )
    return;

  ci_log("onload stack: %s", ni->state->pretty_name);
  ci_log("Accept by default: %s",
         ofe_stats_accept_by_default(ni->ofe) ? "Yes" : "No");
  ofe_stats_mem(ni->ofe, &stat);
  ci_log("Main memory: %d/%d", stat.used, stat.max);
  rc = ofe_stats_rw_mem(ni->ofe, &stat);
  if( rc == OFE_OK ) {
    ci_log("Read-write memory: %d/%d", stat.used, stat.max);
  }
  else
    ci_log("No read-write memory allocated");
  
  table.type = OFE_STATS_TABLE_TYPE_INVALID;
  do {
    if( ofe_stats_table_next(ni->ofe, &table) != OFE_OK )
      break;
    switch( table.type ) {
    case OFE_STATS_TABLE_TYPE_OBJECTS:
       snprintf(table_name, sizeof(table_name), "Object table");
       break;
    case OFE_STATS_TABLE_TYPE_MINIADDRS:
       snprintf(table_name, sizeof(table_name), "Miniaddr table");
       break;
    case OFE_STATS_TABLE_TYPE_MAPPING_LINEAR_LPM:
       snprintf(table_name, sizeof(table_name),
                "mapping linear %s", table.name);
       break;
    case OFE_STATS_TABLE_TYPE_MAPPING_HASH:
       snprintf(table_name, sizeof(table_name),
                "mapping hash %s", table.name);
       break;
    case OFE_STATS_TABLE_TYPE_MAPPING_ARRAY:
       snprintf(table_name, sizeof(table_name),
                "mapping array %s", table.name);
       break;
    case OFE_STATS_TABLE_TYPE_MAPPING_PROTO_DEMUX:
       snprintf(table_name, sizeof(table_name),
                "mapping proto_demux %s", table.name);
       break;
    default:
       snprintf(table_name, sizeof(table_name),
                "Unknown table %s", table.name);
    }
    ci_log("%s: %0lld/%lld", table_name, table.used, table.length);
  } while(1);
}

static void do_ofe_stats(ci_netif *ni)
{
  int size;
  struct ofe_stats_counter* info;
  u64 pos = 0;
  int i;

  if( ni->ofe == NULL )
    return;

  size = ofe_stats_counter_info_size(ni->ofe);
  info = calloc(size, 1);

  if( cfg_argc == 0 ) {
    while( ofe_stats_counter_find(ni->ofe, &pos, info) == OFE_OK ) {
      ci_log("[%s] %s(%d bytes):\t0x%llx", ni->state->pretty_name,
             info->name, info->size, info->val[0]);
      pos++;
    }
    return;
  }

  for( i = 0; i < cfg_argc; i++ ) {
    if( ofe_stats_counter_get(ni->ofe, cfg_argv[i], info) == OFE_OK )
      ci_log("[%s] %s(%d bytes):\t0x%llx", ni->state->pretty_name,
             info->name, info->size, info->val[0]);
  }
}

static void do_ofe_command(ci_netif *ni)
{
  char command[200];
  char *str = command;
  int rc;
  oo_ofe_config_t op;
  int i;

  if( ni->ofe == NULL )
    return;

  for( i = 0; i < cfg_argc; i++ )
    str += snprintf(str, sizeof(command) - (str - command), "%s ", cfg_argv[i]);
  op.len = str - command;
  CI_USER_PTR_SET(op.str, command);
  rc = oo_resource_op(ci_netif_get_driver_handle(ni), OO_IOC_OFE_CONFIG, &op);

  oo_resource_op(ci_netif_get_driver_handle(ni), OO_IOC_OFE_CONFIG_DONE, NULL);

  if( rc == 0 ) {
    ci_log("[%s] %s: OK", ni->state->pretty_name, command);
    return;
  }

  ci_log("[%s] Onload Filter Engine fails to process command\n\t%s",
         ni->state->pretty_name, command);
  if( ofe_engine_get_last_error(ni->ofe) != NULL )
    ci_log("OFE ERROR: %s", ofe_engine_get_last_error(ni->ofe));
  else {
    char err[CI_LOG_MAX_LINE];
    oo_resource_op(ci_netif_get_driver_handle(ni), OO_IOC_OFE_GET_LAST_ERROR, err);
    err[CI_LOG_MAX_LINE-1] = '\0';
    ci_log("OFE ERROR: %s", err);
  }

}

int main(int argc, char* argv[])
{
  stack_ni_fn_t* do_stack_ofe = NULL;

  ci_app_usage = usage;
  cfg_lock = 0; /* don't lock when attaching */

  ci_app_getopt("info | stats ... | command ...",
                &argc, argv, cfg_opts, N_CFG_OPTS);
  --argc; ++argv;

  cfg_stack_id = (ci_uint32)(-1);
  if( cfg_stack_name != NULL ) {
    char *str;
    cfg_stack_id = strtoul(cfg_stack_name, &str, 0);
    if( str[0] != '\0' )
      cfg_stack_id = (ci_uint32)(-1);
  }

  if( argc == 0 ) {
    do_stack_ofe = do_ofe_info;
  }
  else if ( strcmp(argv[0], "info" ) == 0 ) {
    do_stack_ofe = do_ofe_info;
    if( argc != 1 )
      ci_app_usage("Do not understand parameters to the \"info\" command");
  }
  else if( strcmp(argv[0], "stats" ) == 0 ) {
    do_stack_ofe = do_ofe_stats;
    cfg_argv = argv + 1;
    cfg_argc = argc - 1;
  }
  else if( strcmp(argv[0], "command") == 0 ||
           strcmp(argv[0], "cmd") == 0 ) {
    do_stack_ofe = do_ofe_command;
    cfg_argv = argv + 1;
    cfg_argc = argc - 1;
  }
  else
    ci_app_usage("info | stats ... | command ...");

  CI_TRY(libstack_init(NULL));
  list_all_stacks2(stackfilter_match_name, do_stack_ofe, NULL, NULL);
  return 0;
}
