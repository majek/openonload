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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Map in shared state of U/L stack, dump info, and do stuff.
**   \date  2005/01/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_tests_ef */
#include <stdlib.h>
#include <ci/internal/ip.h>
#include "libstack.h"
#include <ci/app.h>


static ci_cfg_desc cfg_opts[] = {
  { 'l', "lock",      CI_CFG_FLAG, &cfg_lock,    "hold netif locks"         },
  { 'n', "nolock",    CI_CFG_FLAG, &cfg_nolock,  "don't grab stack lock"    },
  { 'b', "blocklock", CI_CFG_FLAG, &cfg_blocklock,"block for locks"         },
  {   0, "nosocklock",CI_CFG_FLAG, &cfg_nosklock,"don't grab socket locks"  },
  { 'd', "dump",      CI_CFG_FLAG, &cfg_dump,    "dump packet contents"     },
  {   0, "usec",      CI_CFG_UINT, &cfg_usec,    "set watch_bw interval"    },
  {   0, "msec",      CI_CFG_UINT, &cfg_watch_msec,"set other interval"     },
  {   0, "samples",   CI_CFG_UINT, &cfg_samples, "number of samples"        },
  { 't', "notable",   CI_CFG_FLAG, &cfg_notable, "toggle table mode"},
  { 'z', "zombie",    CI_CFG_FLAG, &cfg_zombie,  "force dump of orphan stacks"},
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))

static void do_stack_ops(int argc, char* argv[])
{
  const stack_op_t* op;
  char dummy;

  if( argc == 0 ) {
    op = get_stack_op("dump");
    if( op->flags & FL_ID )
      for_each_stack_id(op->id_fn, NULL);
    else
      for_each_stack(op->fn, op->flags & FL_ONCE); 
  }

  for( ; argc; --argc, ++argv ) {
    op = get_stack_op(argv[0]);
    if( op == NULL ) {
      ci_log("unknown command: %s", argv[0]);
      continue;
    }

    if( op->flags & FL_ARG_U ) {
      if( sscanf(argv[1], " %u %c", &arg_u[0], &dummy) != 1 ) {
        ci_log("Bad argument to '%s' (expected unsigned)", op->name);
        ci_app_usage(0);
      }
      --argc;
      ++argv;
    }
    else if( op->flags & FL_ARG_X ) {
      if( sscanf(argv[1], " %x %c", &arg_u[0], &dummy) != 1 ) {
        ci_log("Bad argument to '%s' (expected hex)", op->name);
        ci_app_usage(0);
      }
      --argc;
      ++argv;
    }
    else if( op->flags & FL_ARG_S ) {
      arg_s[0] = argv[1];
      --argc;
      ++argv;
    }
    else if( op->flags & FL_ARG_SU ) {
      arg_s[0] = argv[1];
      if( sscanf(argv[2], " %u %c", &arg_u[0], &dummy) != 1 ) {
        ci_log("Bad argument to '%s' (expected unsigned)", op->name);
        ci_app_usage(0);
      }
      --argc;  ++argv;
      --argc;  ++argv;
    }

    if( op->flags & FL_ID )
      for_each_stack_id(op->id_fn, NULL);
    else
      for_each_stack(op->fn, op->flags & FL_ONCE);
  }
}

/**********************************************************************
***********************************************************************
**********************************************************************/

static void do_socket_ops(int argc, char* argv[])
{
  char* argv_dump[] = { "dump", 0 };
  const socket_op_t* op;
  char dummy;

  if( argc == 0 ) {
    argc = 1;
    argv = argv_dump;
  }

  for( ; argc; --argc, ++argv ) {
    if( ! strcmp("bw", argv[0]) ) {
      if( argc > 1 )  ci_app_usage("args after 'bw' not permitted");
      sockets_bw();
      return;
    }
    if( ! strcmp("watch_bw", argv[0]) ) {
      if( argc > 1 )  ci_app_usage("args after 'bw' not permitted");
      sockets_watch_bw();
      return;
    }
    if( ! strcmp("watch", argv[0]) ) {
      if( argc > 1 )  ci_app_usage("args after 'watch' not permitted");
      sockets_watch();
      return;
    }

    op = get_socket_op(argv[0]);

    if( ! op ) {
      ci_log("unknown command: %s", argv[0]);
      ci_app_usage(0);
    }

    if( op->flags & FL_ARG_U ) {
      if( argc < 2 || sscanf(argv[1], " %u %c", &arg_u[0], &dummy) != 1 ) {
	ci_log("Expected <int> for command %s", op->name);
	ci_app_usage(0);
      }
      --argc;
      ++argv;
    }

    for_each_socket(op);
  }
}

/**********************************************************************
***********************************************************************
**********************************************************************/

static void enum_stack_op_log(const stack_op_t *op, void *arg)
{ ci_log("  %s\t%s\t%s", op->name, op->args ? op->args : "", op->help);
}

static void enum_socket_op_log(const socket_op_t *op, void *arg)
{ ci_log("  %s\t%s\t%s", op->name, op->args ? op->args : "", op->help);
}

static void usage(const char* msg)
{
  if( msg ) {
    ci_log(" ");
    ci_log("%s", msg);
  }

  ci_log(" ");
  ci_log("usage:");
  ci_log("  %s [options] [stacks] <commands>...", ci_appname);
  ci_log("  %s [options] <sockets>... <commands>...", ci_appname);

  ci_log(" ");
  ci_log("misc commands:");
  ci_log("  doc");
  ci_log("  affinities         Show thread affinities of onload processes");
  ci_log("  env                Show onload related environment of processes");
  ci_log("  processes          Show list of onloaded processes");

  ci_log(" ");
  ci_log("stack commands:");
  for_each_stack_op(&enum_stack_op_log, NULL);

  ci_log(" ");
  ci_log("socket commands:");
  for_each_socket_op(&enum_socket_op_log, NULL);

  ci_log(" ");
  ci_log("socket spec:");
  ci_log("  <stack>:<socket>");
  ci_log("  <stack>:*");
  ci_log("  *:*");

  ci_log(" ");
  ci_log("options:");
  ci_app_opt_usage(cfg_opts, N_CFG_OPTS);
  ci_log(" ");
  exit(-1);
}


static void atexit_fn(void)
{
  libstack_end();
}


static void cant_do_both(void)
{
  ci_app_usage("Please specify either stacks or sockets, not both.");
}


static int compare (const void *arg1, const void *arg2)
{
  return strcmp (*(const char**)arg1, *(const char**)arg2);
}

static int is_min_str (const char *min_str)
{
  return (min_str && min_str[0] && strcmp (min_str, "MIN"));
}

static int is_max_str (const char *max_str)
{
  return (max_str && max_str[0] && strcmp (max_str, "MAX"));
}

static void print_docs(int argc, char* argv[])
{
#undef CI_CFG_OPT
#define IFDOC(env)  if( strlen(env) )

  static struct {
        const char *item_env;
        const char *item_name;
        unsigned    item_deflt;
        const char *item_doc;
        const char *item_min_str;
        const char *item_max_str;
        const char *item_kind;
  } items [] = {

#define CI_CFG_OPT(env, name, type, doc, bits, group, deflt, min, max, pres) \
      { .item_env = env, .item_name = #name, .item_deflt = deflt, \
        .item_doc = doc, .item_min_str=#min, .item_max_str=#max, .item_kind="per-process"},
#include <ci/internal/opts_citp_def.h>
#undef CI_CFG_OPT
#define CI_CFG_OPT(env, name, type, doc, bits, group, deflt, min, max, pres) \
      { .item_env = env, .item_name = #name, .item_deflt = deflt, \
        .item_doc = doc, .item_min_str=#min, .item_max_str=#max, .item_kind="per-stack"},
#include <ci/internal/opts_netif_def.h>
#undef CI_CFG_OPT
  };

#define NUM_ITEMS ( sizeof items / sizeof items[0])

  /* Sort the items by env. */
  qsort (items, NUM_ITEMS, sizeof items[0], compare);

  if( argc == 2 && ! strcmp(argv[1], "html") ) {
    printf("<table>\n");
    printf("<tr><td>name</td><td>default</td><td>description</td>"
            "</tr>\n");
    unsigned i;
    for( i = 0; i < NUM_ITEMS; ++i )
      if( items[i].item_env[0] && items[i].item_doc[0] )
        printf("<tr><td>%s</td><td>%u</td><td> %s</td></tr>\n",
               items[i].item_env, items[i].item_deflt, items [i].item_doc);
    printf("</table>\n");
  }
  else if( argc == 2 && ! strcmp(argv[1], "rtf") ) {
    /* Now print them out. */
    printf("{\\rtf1\\ansi\\deff0{\\fonttbl");
    printf("{\\f0 Calibri;}");
    printf("{\\f1 Courier New;}}");

    unsigned i;
    for(i = 0; i < NUM_ITEMS; ++i) {
      if (!items[i].item_env[0] || !items[i].item_doc[0])
        continue;

      printf("\\sb480 \\li0\\f0\\fs28 \\b %s \\plain", items [i].item_env);
      printf("\\par \\li240 \\sb120 \\fs20 Name: \\f1 %s \\f0 ",
              items [i].item_name);
      printf ("default: \\f1 %u \\f0", items [i].item_deflt);
      if (is_min_str (items[i].item_min_str))
          printf ("    min: \\f1 %s \\f0", items[i].item_min_str);
      if (is_max_str (items[i].item_max_str))
          printf ("    max: \\f1 %s \\f0", items[i].item_max_str);
      printf("     %s\\par \\plain \\sb120 \\fs20", items[i].item_kind);
      if (strcmp(items [i].item_doc, "doc"))
        printf("%s", items [i].item_doc);
      printf("\\par");
    }
    printf("}");
  }
  else if( argc == 1 || (argc == 2 && ! strcmp(argv[1], "text")) ) {
    unsigned i;
    for(i = 0; i < NUM_ITEMS; ++i) {
      if (!items[i].item_env[0] || !items[i].item_doc[0])
        continue;

      printf("%-25s (%s, %s)\ndefault: %d\n",
           items[i].item_env, items[i].item_name, items[i].item_kind,
           items[i].item_deflt);
      if (is_min_str (items[i].item_min_str))
        printf ("min: %s\n", items[i].item_min_str);
      if (is_max_str (items[i].item_max_str))
        printf ("max: %s\n", items[i].item_max_str);

      printf ("\n%s\n\n\n", items[i].item_doc);
    }
  }
  else {
    ci_app_usage("Expected csv, html, rtf or text.");
  }
}


int main(int argc, char* argv[])
{
  char dummy;
  int doing_stacks = 0;
  int doing_sockets = 0;
  int no_args = (argc == 1);

  ci_app_usage = usage;

  ci_app_getopt("[stack-index]", &argc, argv, cfg_opts, N_CFG_OPTS);
  --argc; ++argv;
  CI_TRY(libstack_init(NULL));

  /* Special case for onload_stackdump called with no arguments 
   * - just list stacks and pids and return
   */
  if( no_args ) {
    libstack_stack_mapping_print();
    return 0;
  }

  /* Ensure we clean-up nicely when we exit. */
  atexit(atexit_fn);

  /* Which stack(s) are we doing this to?  If no stack specified then
   * attach to all stacks 
   */
  if( argc == 0 ) {
    list_all_stacks(1);
    doing_stacks = 1;
    goto doit;
  }

  for( ; argc; --argc, ++argv ) {
    unsigned stack_id, sock_id;
    if( sscanf(argv[0], "%u %c", &stack_id, &dummy) == 1 ) {
      if( doing_sockets )  cant_do_both();
      if( ! stack_attach(stack_id) ) {
	ci_log("No such stack id: %d", stack_id);
	continue;
      }
      doing_stacks = 1;
    }
    else if( sscanf(argv[0], "%u:%u %c", &stack_id, &sock_id, &dummy) == 2 ) {
      if( doing_stacks )  cant_do_both();
      doing_sockets = 1;
      if( ! stack_attach(stack_id) ) {
	ci_log("No such stack id: %d", stack_id);
	continue;
      }
      socket_add(stack_id, sock_id);
    }
    else if( sscanf(argv[0], "%u:* %c", &stack_id, &dummy) == 1 ) {
      if( doing_stacks )  cant_do_both();
      doing_sockets = 1;
      if( ! stack_attach(stack_id) ) {
	ci_log("No such stack id: %d", stack_id);
	continue;
      }
      socket_add_all(stack_id);
    }
    else if( ! strcmp(argv[0], "*:*") ) {
      if( doing_stacks )  cant_do_both();
      doing_sockets = 1;
      list_all_stacks(1);
      socket_add_all_all();
    }
    else if( ! strcmp(argv[0], "all") ) {
      if( doing_sockets )  cant_do_both();
      list_all_stacks(1);
      doing_stacks = 1;
    }
    else if( !  strcmp(argv[0], "doc") ) {
      if( doing_sockets || doing_stacks) {
        ci_app_usage("Cannot mix doc with other commands");
      }
      print_docs(argc, argv);
      break;
    }
    else if( ! strcmp(argv[0], "affinities") ) {
      if( doing_sockets || doing_stacks )
        ci_app_usage("Cannot mix doc with other commands");
      CI_TRY(libstack_affinities_print());
    }
    else if( ! strcmp(argv[0], "env") ) {
      if( doing_sockets || doing_stacks )
        ci_app_usage("Cannot mix doc with other commands");
      CI_TRY(libstack_env_print());
    }
    else if( ! strcmp(argv[0], "processes") ) {
      if( doing_sockets || doing_stacks )
        ci_app_usage("Cannot mix doc with other commands");
      libstack_pid_mapping_print();
    }
    else if( ! cfg_zombie && ! strcmp(argv[0], "kill") ) {
      ci_app_usage("Cannot use kill without -z");
      break;
    }
    else {
      if( ! (doing_stacks | doing_sockets) ) {
	list_all_stacks(1);
	doing_stacks = 1;
      }
      break;
    }
  }

 doit:
  ci_log_fn = ci_log_stdout;
  if( doing_stacks )
    do_stack_ops(argc, argv);
  if( doing_sockets )
    do_socket_ops(argc, argv);

  return 0;
}

/*! \cidoxg_end */
