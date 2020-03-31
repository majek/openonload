/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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
#define OFE_MAPPING_REMOVE 0
#define OFE_MAPPING_INSERT 1
#define OFE_MAPPING_LOAD_MAX_ARGS 3
#define OFE_MAPPING_DEL_MAX_ARGS 1
#define OFE_INSERT_RULE_MIN_ARGS 2
#define OFE_DELETE_RULE_MIN_ARGS 1
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
  ci_log("  %s [options] load_ips <table name> <file name> [label]", ci_appname);
  ci_log("  %s [options] del_ips <table name> <file name>", ci_appname);

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

static void do_process_ips(ci_netif *ni)
{
  char* fname = NULL;
  char* label = NULL;
  char* token;
  int tkn_count;
  FILE* cfg_file;
#define MAX_LINE_SIZE 100
#define MAX_CMD_SIZE 100
  char line[MAX_LINE_SIZE];
  char out_cmd[MAX_CMD_SIZE];
  char* cmdptr = out_cmd;
  char* fixed_cmd;
  int rc = 0;
  int max_args = 0;
  int cmd = 0;
  oo_ofe_config_t op;
  int success_count = 0;
  int fail_count = 0;
  int line_num = 0;

  if( ni->ofe == NULL )
    return;

  /* process args:  cmd, table and file needed at minimum */
  if( cfg_argc < 3 ) {
    ci_app_usage("missing or invalid parameters! Check help");
    return;
  }
  if( strcmp(cfg_argv[0], "load_ips") == 0 ) {
    cmd = OFE_MAPPING_INSERT;
    max_args = OFE_MAPPING_LOAD_MAX_ARGS;
    cmdptr += snprintf(cmdptr, sizeof(out_cmd) - (cmdptr - out_cmd), "%s ",
                       "mapping_insert");
  }
  else if( strcmp(cfg_argv[0], "del_ips") == 0 ) {
    cmd = OFE_MAPPING_REMOVE;
    max_args = OFE_MAPPING_DEL_MAX_ARGS;
    cmdptr += snprintf(cmdptr, sizeof(out_cmd) - (cmdptr - out_cmd), "%s ",
                       "mapping_remove");
  }
  else {
    ci_app_usage("invalid command");
    return;
  }
  cmdptr += snprintf(cmdptr, sizeof(out_cmd) - (cmdptr - out_cmd),
                     "%s ", cfg_argv[1]);
  fixed_cmd = cmdptr;
  fname = cfg_argv[2];
  if( fname == NULL ) {
    ci_app_usage("Missing file name!");
    return;
  }
  if( cfg_argc > 2 )
    label = cfg_argv[3];

  if( (cfg_file = fopen(fname, "r")) == NULL ) {
    ci_log("ERROR: failed to open IP config file %s: %s", fname,
           strerror(errno));
    return;
  }

  /* process the config file */
  while( fgets(line, sizeof(line), cfg_file) != NULL ) {
    cmdptr = fixed_cmd;
    tkn_count = 0;
    line_num++;
    token = strtok(line, " ");
    while( (token != NULL) && (tkn_count < max_args) ) {
      if( (token[0] == '\n') || (token[0] == '\r') || (token[0] == '#') )
        break;
      cmdptr += snprintf(cmdptr, sizeof(out_cmd) - (cmdptr - out_cmd),
                         "%s ", token);
      tkn_count++;
      token = strtok(NULL, " ");
    }
    if( tkn_count == 0 )
      continue; /* skip - most likely empty line or comment starting with # */

    if( (cmd == OFE_MAPPING_INSERT) &&
        (tkn_count < OFE_INSERT_RULE_MIN_ARGS) ) {
      if( label != NULL ) {
        cmdptr += snprintf(cmdptr, sizeof(out_cmd) - (cmdptr - out_cmd),
                             "%s ", label);
      }
      else {
        fail_count++;
        ci_log("invalid rule! skipping to the next rule at line %d",
               line_num);
        continue;
      }
    }
    else if( (cmd == OFE_MAPPING_REMOVE) &&
             (tkn_count < OFE_DELETE_RULE_MIN_ARGS) ) {
      ci_log("invalid rule! skipping to the next rule at line %d", line_num);
      fail_count++;
      continue;
    }
    op.len = cmdptr - out_cmd;
    CI_USER_PTR_SET(op.str, out_cmd);
    rc = oo_resource_op(ci_netif_get_driver_handle(ni), OO_IOC_OFE_CONFIG,
                        &op);

    if( rc < 0 ) {
      ci_log("[%s]: failed: %s, at line %d from file %s",
             ni->state->pretty_name, out_cmd, line_num, fname);
      fail_count++;
    }
    else {
      success_count++;
    }

    fixed_cmd[0] = '\0';
  }
  oo_resource_op(ci_netif_get_driver_handle(ni), OO_IOC_OFE_CONFIG_DONE, NULL);
  ci_log("[%s] CMD:%s, processed %d rules from file %s",
         ni->state->pretty_name, cfg_argv[0], success_count, fname);
  if( fail_count )
    ci_log("[%s] CMD:%s, failed to process %d rules from file %s",
           ni->state->pretty_name, cfg_argv[0], fail_count, fname);

  fclose(cfg_file);
}

int main(int argc, char* argv[])
{
  stack_ni_fn_t* do_stack_ofe = NULL;

  ci_app_usage = usage;
  cfg_lock = 0; /* don't lock when attaching */

  ci_app_getopt("info | stats ... | command ...|load_ips...|del_ips...",
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
  else if( strcmp(argv[0], "load_ips") == 0  ||
           strcmp(argv[0], "del_ips") == 0 ) {
    do_stack_ofe = do_process_ips;
    cfg_argv = argv;
    cfg_argc = argc;
  }
  else
    ci_app_usage("info | stats ... | command ...|load_ips...|del_ips...");

  CI_TRY(libstack_init(NULL));
  list_all_stacks2(stackfilter_match_name, do_stack_ofe, NULL, NULL);
  return 0;
}
