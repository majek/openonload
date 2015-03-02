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
#include <onload/ioctl.h>
#include <onload/driveraccess.h>
#include <onload/debug_intf.h>

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
/* Dump ci_netif_stats */
/**********************************************************/

struct orm_oo_stat {
  const char* oos_name;
  unsigned    oos_offset;
  unsigned    oos_size;
};


#undef stat_initialiser
#define stat_initialiser(type, field, name)             \
  { .oos_name = (name),                                 \
    .oos_offset = CI_MEMBER_OFFSET(type, field),        \
    .oos_size = CI_MEMBER_SIZE(type, field),            \
  }

#undef  OO_STAT
#define OO_STAT(desc, type, name, kind)                 \
  stat_initialiser(ci_netif_stats, name, #name),

static struct orm_oo_stat orm_oo_stats[] = {
#include <ci/internal/stats_def.h>
};
#define N_ORM_OO_STATS (sizeof(orm_oo_stats) / sizeof(orm_oo_stats[0]))


static int orm_oo_stats_dump(ci_netif* ni)
{
  ci_netif_stats* stats = &ni->state->stats;
  const struct orm_oo_stat* os;

  dump_buf_cat("\"stats\": {");
  for( os = orm_oo_stats; os < orm_oo_stats + N_ORM_OO_STATS; ++os ) {
    switch( os->oos_size ) {
    case sizeof(ci_uint32):
      dump_buf_cat("\"%s\": %u, ",os->oos_name,
                   *(const ci_uint32*) ((const char*) stats + os->oos_offset));
      break;
    case sizeof(ci_uint64): {
      dump_buf_cat("\"%s\": %llu, ",os->oos_name,
                   *(const ci_uint64*) ((const char*) stats + os->oos_offset));
      break;
    }
    default:
      fprintf(stderr, "%s: Error: %s has unknown size %d", __func__,
              os->oos_name, os->oos_size);
      TEST(0);
    }
  }

  dump_buf_cleanup();
  dump_buf_cat("}");
  return 0;
}


/**********************************************************/
/* Dump ci_netif_state using FTL defs */
/**********************************************************/

enum orm_oo_field_type {
  ORM_OO_FIELD_TYPE_INT,
  ORM_OO_FIELD_TYPE_STRUCT,
  ORM_OO_FIELD_TYPE_ARRAY_INT,
  ORM_OO_FIELD_TYPE_ARRAY_STRUCT,
  ORM_OO_FIELD_TYPE_BITFIELD,
};

struct orm_oo_struct;

struct orm_oo_field {
  union {
    struct {
      unsigned of_size;
    } i;
    struct {
      struct orm_oo_struct* of_struct;
    } s;
    struct {
      unsigned of_size;
      unsigned of_array_len;
    } ai;
    struct {
      struct orm_oo_struct* of_struct;
      unsigned              of_array_len;
    } as;
    struct {
      unsigned of_n_bits;
    } b;
  } u;
  const char*             of_name;
  unsigned                of_offset;
  enum orm_oo_field_type  of_type;
};

struct orm_oo_struct {
  const char*           os_struct_name;
  struct orm_oo_field** os_fields;
  int                   os_n_fields;
  int                   os_size;
};


struct orm_oo_struct** orm_oo_structs = NULL;
static int n_orm_oo_structs_max   = 0;
static int n_orm_oo_structs_index = 0;


static void oos_begin(struct orm_oo_struct** os_ret, const char* name)
{
  struct orm_oo_struct* os = calloc(1, sizeof(*os));
  TEST(os);
  TEST(n_orm_oo_structs_index < n_orm_oo_structs_max);
  orm_oo_structs[n_orm_oo_structs_index++] = os;
  os->os_struct_name = name;
  *os_ret = os;
}


static void oos_end(struct orm_oo_struct* os)
{
  int size = 0;
  int i;
  for( i = 0; i < os->os_n_fields; ++i ) {
    struct orm_oo_field* of = os->os_fields[i];
    switch( of->of_type ) {
    case ORM_OO_FIELD_TYPE_INT:
      size += of->u.i.of_size;
      break;
    case ORM_OO_FIELD_TYPE_STRUCT:
      size += of->u.s.of_struct->os_size;
      break;
    case ORM_OO_FIELD_TYPE_ARRAY_INT:
      size += of->u.ai.of_size * of->u.ai.of_array_len;
      break;
    case ORM_OO_FIELD_TYPE_ARRAY_STRUCT:
      size += of->u.as.of_struct->os_size * of->u.as.of_array_len;
      break;
    default:
      fprintf(stderr, "%s: Unknown type %d\n", __func__, of->of_type);
      TEST(0);
    }
  }
  os->os_size = size;
}


static struct orm_oo_field* oos_alloc_field(struct orm_oo_struct* os)
{
  struct orm_oo_field* of = calloc(1, sizeof(*of));
  TEST(of);
  os->os_fields = realloc(os->os_fields,
                          sizeof(*os->os_fields) * (os->os_n_fields + 1));
  TEST(os->os_fields);
  os->os_fields[os->os_n_fields++] = of;
  return of;
}


static void oos_add_int_field(struct orm_oo_struct* os, const char* name,
                              unsigned offset, unsigned size)
{
  struct orm_oo_field* of = oos_alloc_field(os);
  of->of_type       = ORM_OO_FIELD_TYPE_INT;
  of->of_name       = name;
  of->of_offset     = offset;
  of->u.i.of_size   = size;
}


static void oos_add_struct_field(struct orm_oo_struct* os, const char* name,
                                 unsigned offset, const char* struct_type)
{
  int i;
  struct orm_oo_field* of = oos_alloc_field(os);
  of->of_type   = ORM_OO_FIELD_TYPE_STRUCT;
  of->of_name   = name;
  of->of_offset = offset;

  for( i = 0; i < n_orm_oo_structs_index; ++i )
    if( ! strcmp(struct_type, orm_oo_structs[i]->os_struct_name) ) {
      of->u.s.of_struct = orm_oo_structs[i];
      return;
    }
  fprintf(stderr, "%s(%s, %d, %s) failed\n", __func__, name, offset,
          struct_type);
  TEST(0);
}


static void oos_add_array_int_field(struct orm_oo_struct* os, const char* name,
                                    unsigned offset, unsigned size,
                                    unsigned array_len)
{
  struct orm_oo_field* of = oos_alloc_field(os);
  of->of_type           = ORM_OO_FIELD_TYPE_ARRAY_INT;
  of->of_name           = name;
  of->of_offset         = offset;
  of->u.ai.of_size      = size / array_len;
  of->u.ai.of_array_len = array_len;
}


static void
oos_add_array_struct_field(struct orm_oo_struct* os, const char* name,
                           unsigned offset, const char* struct_type,
                           unsigned array_len)
{
  int i;
  struct orm_oo_field* of = oos_alloc_field(os);
  of->of_type           = ORM_OO_FIELD_TYPE_ARRAY_STRUCT;
  of->of_name           = name;
  of->of_offset         = offset;
  of->u.as.of_array_len = array_len;

  for( i = 0; i < n_orm_oo_structs_index; ++i )
    if( ! strcmp(struct_type, orm_oo_structs[i]->os_struct_name) ) {
      of->u.as.of_struct = orm_oo_structs[i];
      return;
    }
  fprintf(stderr, "%s(%s, %d, %s, %d) failed\n", __func__, name, offset,
          struct_type, array_len);
  TEST(0);
}


static void oos_ftl_init(void)
{
#define FTL_TSTRUCT_BEGIN(ctx, name, tag)  ++n_orm_oo_structs_max;
#define FTL_TUNION_BEGIN(ctx, name, tag)   ++n_orm_oo_structs_max;
#define FTL_TFIELD_INT(ctx, struct_name, type, field_name)
#define FTL_TFIELD_CONSTINT(ctx, struct_name, type, field_name)
#define FTL_TFIELD_STRUCT(ctx, struct_name, type, field_name)
#define FTL_TSTRUCT_END(ctx)
#define FTL_TUNION_END(ctx)
#define FTL_TFIELD_ARRAYOFINT(ctx, struct_name, type, field_name, len)
#define FTL_TFIELD_ARRAYOFSTRUCT(ctx, struct_name, type, field_name, len)
#define FTL_TFIELD_KINT(ctx, struct_name, type, field_name)
#define FTL_DECLARE(a) a(DECL)

#include "ftl_decls.h"

  /* Account for ci_netif_config_opts */
  ++n_orm_oo_structs_max;
  orm_oo_structs = calloc(n_orm_oo_structs_max, sizeof(*orm_oo_structs));
  TEST(orm_oo_structs);
}


static void oos_ftl_construct(void)
{
  struct orm_oo_struct* os;

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
#undef FTL_DECLARE

#define FTL_TSTRUCT_BEGIN(ctx, name, tag)  oos_begin(&os, #name);
#define FTL_TUNION_BEGIN(ctx, name, tag)   oos_begin(&os, #name);
#define FTL_TFIELD_INT(ctx, struct_name, type, field_name)      \
  oos_add_int_field(os, #field_name,                            \
                    CI_MEMBER_OFFSET(struct_name, field_name),  \
                    CI_MEMBER_SIZE(struct_name, field_name));
#define FTL_TFIELD_CONSTINT(ctx, struct_name, type, field_name) \
  oos_add_int_field(os, #field_name,                            \
                    CI_MEMBER_OFFSET(struct_name, field_name),  \
                    CI_MEMBER_SIZE(struct_name, field_name));
#define FTL_TFIELD_STRUCT(ctx, struct_name, type, field_name)           \
  oos_add_struct_field(os, #field_name,                                 \
                       CI_MEMBER_OFFSET(struct_name, field_name), #type);
#define FTL_TSTRUCT_END(ctx) oos_end(os);
#define FTL_TUNION_END(ctx)  oos_end(os);

#define FTL_TFIELD_ARRAYOFINT(ctx, struct_name, type, field_name, len)  \
  oos_add_array_int_field(os, #field_name,                              \
                          CI_MEMBER_OFFSET(struct_name, field_name),    \
                          CI_MEMBER_SIZE(struct_name, field_name), len);

#define FTL_TFIELD_ARRAYOFSTRUCT(ctx, struct_name, type, field_name, len) \
  oos_add_array_struct_field(os, #field_name,                           \
                             CI_MEMBER_OFFSET(struct_name, field_name), \
                             #type, len);

#define FTL_TFIELD_KINT(ctx, struct_name, type, field_name)     \
  oos_add_int_field(os, #field_name,                            \
                    CI_MEMBER_OFFSET(struct_name, field_name),  \
                    CI_MEMBER_SIZE(struct_name, field_name));

#define FTL_DECLARE(a) a(DECL)

#include "ftl_decls.h"
}


/**********************************************************/
/* Extend ci_netif_state defines above to include
 * ci_netif_config_opts */
/**********************************************************/


static void oos_cfg_opts_add_field(struct orm_oo_struct* os, const char* name,
                                   unsigned n_bits, unsigned size)
{
  struct orm_oo_field* of = oos_alloc_field(os);
  of->of_name = name;
  /* Offset will be initialized later after all the fields have been
   * discovered. */
  of->of_offset = -1;

  if( n_bits != 0 ) {
    of->of_type       = ORM_OO_FIELD_TYPE_BITFIELD;
    of->u.b.of_n_bits = n_bits;
  }
  else {
    of->of_type     = ORM_OO_FIELD_TYPE_INT;
    of->u.i.of_size = size;
  }
}


static void oos_cfg_opts_contruct(void)
{
#define ORM_BITFIELD   0
#define ORM_BITFIELD1  1
#define ORM_BITFIELD2  2
#define ORM_BITFIELD3  3
#define ORM_BITFIELD4  4
#define ORM_BITFIELD8  8
#define ORM_BITFIELD16 16

  int i;
  struct orm_oo_struct* os;
  oos_begin(&os, "ci_netif_config_opts");

#undef CI_CFG_OPT
#define CI_CFG_OPT(e, name, type, d0, bits, g, d1, m0, m1, p)      \
  oos_cfg_opts_add_field(os, #name, ORM_BITFIELD##bits, sizeof(type));

#include <ci/internal/opts_netif_def.h>
  oos_cfg_opts_add_field(os, "inited", 0, sizeof(ci_boolean_t));

  /* Set offset of individual fields based on how a compiler would do it. */
  int offset_bits = 0;
  for( i = 0; i < os->os_n_fields; ++i ) {
    struct orm_oo_field* of = os->os_fields[i];
    int n_bits, modulus;
    if( of->of_type == ORM_OO_FIELD_TYPE_BITFIELD ) {
      n_bits  = of->u.b.of_n_bits;
      modulus = 8;
    }
    else {
      ci_assert_equal(of->of_type, ORM_OO_FIELD_TYPE_INT);
      n_bits = modulus = of->u.i.of_size * 8;
    }

    if( (offset_bits / 8 == (offset_bits + n_bits) / 8) ||
        (offset_bits % modulus == 0) ) {
      of->of_offset  = of->of_type == ORM_OO_FIELD_TYPE_BITFIELD ?
        offset_bits : offset_bits / 8;
      offset_bits   += n_bits;
    }
    else {
      offset_bits    = CI_ROUND_UP(offset_bits, n_bits);
      of->of_offset  = of->of_type == ORM_OO_FIELD_TYPE_BITFIELD ?
        offset_bits : offset_bits / 8;
      offset_bits   += n_bits;
    }
  }
  os->os_size = offset_bits / 8;
  TEST(os->os_size == sizeof(ci_netif_config_opts));
}


/**********************************************************/
/* Dump functions */
/**********************************************************/

static void orm_dump_struct(const char* name, const void* stats);


static void orm_dump_int(struct orm_oo_struct* os, struct orm_oo_field* of,
                         const void* stats)
{
  ci_assert_equal(of->of_type, ORM_OO_FIELD_TYPE_INT);

  dump_buf_cat("\"%s\": ", of->of_name);
  switch( of->u.i.of_size ) {
  case sizeof(ci_uint8):
    dump_buf_cat("%u, ", *((const ci_uint8*) stats + of->of_offset));
    break;
  case sizeof(ci_uint16):
    dump_buf_cat("%u, ",
                 *(const ci_uint16*) ((const char*) stats + of->of_offset));
    break;
  case sizeof(ci_uint32):
    dump_buf_cat("%u, ",
                 *(const ci_uint32*) ((const char*) stats + of->of_offset));
    break;
  case sizeof(ci_uint64):
    dump_buf_cat("%lld, ",
                 *(const long long*) ((const char*) stats + of->of_offset));
    break;
  default:
    fprintf(stderr, "%s: switch failed: %d\n", __func__, of->u.i.of_size);
    TEST(0);
  }
}


static void orm_dump_array_int(struct orm_oo_struct* os,
                               struct orm_oo_field* of, const void* stats)
{
  int i;
  ci_assert_equal(of->of_type, ORM_OO_FIELD_TYPE_ARRAY_INT);
  dump_buf_cat("\"%s\": [", of->of_name);
  for( i = 0; i < of->u.ai.of_array_len; ++i ) {
    switch( of->u.ai.of_size ) {
    case sizeof(ci_uint8):
      dump_buf_cat("%u, ", *((const ci_uint8*) stats + of->of_offset +
                             (sizeof(ci_uint8) * i)));
      break;
    case sizeof(ci_uint16):
      dump_buf_cat("%u, ",
                   *(const ci_uint16*) ((const char*) stats + of->of_offset +
                                        (sizeof(ci_uint16) * i)));
      break;
    case sizeof(ci_uint32):
      dump_buf_cat("%u, ",
                   *(const ci_uint32*) ((const char*) stats + of->of_offset +
                                        (sizeof(ci_uint32) * i)));
      break;
    case sizeof(ci_uint64):
      dump_buf_cat("%lld, ",
                   *(const long long*) ((const char*) stats + of->of_offset +
                                        (sizeof(ci_uint64) * i)));
      break;
    default:
      fprintf(stderr, "%s: switch failed: %d\n", __func__, of->u.ai.of_size);
      TEST(0);
    }
  }
  dump_buf_cleanup();
  dump_buf_cat("], ");
}


static void orm_dump_array_struct(struct orm_oo_field* of, const void* stats)
{
  int i;
  ci_assert_equal(of->of_type, ORM_OO_FIELD_TYPE_ARRAY_STRUCT);
  dump_buf_cat("\"%s\": [", of->of_name);
  for( i = 0; i < of->u.as.of_array_len; ++i ) {
    dump_buf_cat("{");
    orm_dump_struct(of->u.as.of_struct->os_struct_name,
                    (const char*)stats + of->of_offset +
                    (of->u.as.of_struct->os_size * i));
    dump_buf_cleanup();
    dump_buf_cat("}, ");
  }
  dump_buf_cleanup();
  dump_buf_cat("], ");
}


static void orm_dump_bitfield(struct orm_oo_field* of, const void* stats)
{
  ci_assert_equal(of->of_type, ORM_OO_FIELD_TYPE_BITFIELD);
  int bit_start = of->of_offset % 8;
  int n_bits = of->u.b.of_n_bits;
  ci_uint8 byte = *((const ci_uint8*) stats + of->of_offset / 8);
  ci_uint8 mask = ~(((1 << bit_start) - 1) |
                    ~((1 << (bit_start + n_bits)) - 1));
  dump_buf_cat("\"%s\": %u, ", of->of_name, (byte & mask) >> bit_start);
}


static void orm_dump_struct(const char* name, const void* stats)
{
  int i, j;
  struct orm_oo_struct* os;

  /* ci_netif_stats got dumped separately above. */
  if( ! strcmp(name, "ci_netif_stats") )
    return;

  dump_buf_cat("\"%s\": {", name);
  for( i = 0; i < n_orm_oo_structs_index; ++i ) {
    os = orm_oo_structs[i];
    if( ! strcmp(os->os_struct_name, name) ) {
      for( j = 0; j < os->os_n_fields; ++j ) {
        struct orm_oo_field* of = os->os_fields[j];
        switch( of->of_type ) {
        case ORM_OO_FIELD_TYPE_INT:
          orm_dump_int(os, of, stats);
          break;
        case ORM_OO_FIELD_TYPE_STRUCT:
          orm_dump_struct(of->u.s.of_struct->os_struct_name,
                          (const char*)stats + of->of_offset);
          break;
        case ORM_OO_FIELD_TYPE_ARRAY_INT:
          orm_dump_array_int(os, of, stats);
          break;
        case ORM_OO_FIELD_TYPE_ARRAY_STRUCT:
          orm_dump_array_struct(of, stats);
          break;
        case ORM_OO_FIELD_TYPE_BITFIELD:
          orm_dump_bitfield(of, stats);
          break;
        default:
          fprintf(stderr, "%s: switch failed: %d\n", __func__, of->of_type);
          TEST(0);
        }
      }
      goto done;
    }
  }

  fprintf(stderr, "%s(%s) failed\n", __func__, name);
  TEST(0);

 done:
  dump_buf_cleanup();
  dump_buf_cat("}, ");
}


static void orm_waitable_dump(ci_netif* ni, const char* sock_type)
{
  ci_netif_state* ns = ni->state;
  unsigned id;

  dump_buf_cat("\"%s\": {", sock_type);
  for( id = 0; id < ns->n_ep_bufs; ++id ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(ni, id);
    if( wo->waitable.state != CI_TCP_STATE_FREE &&
        wo->waitable.state != CI_TCP_CLOSED ) {
      citp_waitable* w = &wo->waitable;

      if( (strcmp(sock_type, "tcp_listen") == 0) &&
          (w->state & CI_TCP_STATE_SOCKET) &&
          (w->state == CI_TCP_LISTEN) ) {
        dump_buf_cat("\"%d\": {", W_FMT(w));
        orm_dump_struct("ci_tcp_socket_listen", &wo->tcp_listen);
        dump_buf_cleanup();
        dump_buf_cat("}, ");
      }
      else if( (strcmp(sock_type, "tcp") == 0) &&
          (w->state & CI_TCP_STATE_SOCKET) &&
          (w->state & CI_TCP_STATE_TCP) ) {
        dump_buf_cat("\"%d\": {", W_FMT(w));
        orm_dump_struct("ci_tcp_state", &wo->tcp);
        dump_buf_cleanup();
        dump_buf_cat("}, ");
      }
#if CI_CFG_UDP
      else if( (strcmp(sock_type, "udp") == 0) &&
          (w->state & CI_TCP_STATE_SOCKET) &&
          (w->state == CI_TCP_STATE_UDP) ) {
        dump_buf_cat("\"%d\": {", W_FMT(w));
        orm_dump_struct("ci_udp_state", &wo->udp);
        dump_buf_cleanup();
        dump_buf_cat("}, ");
      }
#endif

#if CI_CFG_USERSPACE_PIPE
      else if( (strcmp(sock_type, "pipe") == 0) &&
          (w->state == CI_TCP_STATE_PIPE) ) {
        dump_buf_cat("\"%d\": {", W_FMT(w));
        orm_dump_struct("oo_pipe", &wo->pipe);
        dump_buf_cleanup();
        dump_buf_cat("}, ");
      }
#endif
    }
  }
  dump_buf_cleanup();
  dump_buf_cat("}, ");
}


static int orm_shared_state_dump(ci_netif* ni)
{
  ci_netif_state* ns = ni->state;

  dump_buf_cat("\"netif\": {");
  orm_dump_struct("ci_netif_state", ns);
  orm_waitable_dump(ni, "tcp_listen");
  orm_waitable_dump(ni, "tcp");
  orm_waitable_dump(ni, "udp");
  orm_waitable_dump(ni, "pipe");
  dump_buf_cleanup();
  dump_buf_cat("}");

  return 0;
}


/**********************************************************/
/* Main */
/**********************************************************/

static int orm_netif_dump(ci_netif* ni, int id)
{
  int rc;
  dump_buf_cat("{\"%d\": {", id);
  if( (rc = orm_shared_state_dump(ni)) != 0 )
    return rc;
  dump_buf_cleanup();
  dump_buf_cat(", ");
  if( (rc = orm_oo_stats_dump(ni)) != 0 )
    return rc;
  dump_buf_cleanup();
  dump_buf_cat("}}");
  return 0;
}


int main(int argc, char* argv[])
{
  int i;
  char* json_buf;
  const char* buf;
  json_t* root;
  json_error_t error;

  if( orm_map_stacks() != 0 )
    exit(EXIT_FAILURE);
  if( n_orm_stacks == 0 )
    return 0;
  oos_ftl_init();
  oos_cfg_opts_contruct();
  oos_ftl_construct();

  dump_buf_cat("{\"json\": [");

  for( i = 0; i < n_orm_stacks; ++i ) {
    ci_netif* ni = &orm_stacks[i]->os_ni;
    int id       = orm_stacks[i]->os_id; 
    if( orm_netif_dump(ni, id) != 0 )
      exit(EXIT_FAILURE);
    dump_buf_cleanup();
    dump_buf_cat(", ");
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
