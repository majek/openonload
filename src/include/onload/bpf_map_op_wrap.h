/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef ONLOAD_BPF_MAP_OP_WRAP_H_
#define ONLOAD_BPF_MAP_OP_WRAP_H_

/* This header file defines a bunch of boilerplate that is needed to
 * implement the BPF map lookup/manipulation functions. There are two copies
 * of those implementations, one for kernels with BPF support and one without.
 * Those two implementations need to be in different source files, hence this
 * header. */

/* Max number of bytes we'll put on the stack as temporary storage for
 * keys/values passed from userspace. Beyond this we'll do a heap
 * allocation */
#define MAX_STACK_SCRATCH_BYTES  64

/* MAP_LOOKUP_*FIX isn't here because the requirements are different between
 * oobpf and kbpf code paths: the former can do without storage for the value
 * because it's not copied by the lookup function */

#define MAP_UPDATE_PREFIX                                                \
  int rc;                                                                \
  char stackk[MAX_STACK_SCRATCH_BYTES];                                  \
  char* k = map->key_size + map->value_size > sizeof(stackk) ?           \
                  ci_alloc(map->key_size + map->value_size) : stackk;    \
                                                                         \
  if( copy_from_user(k, ukey, map->key_size) ||                          \
      copy_from_user(k + map->key_size, uvalue, map->value_size) )       \
    rc = -EFAULT;                                                        \
  else {

#define MAP_UPDATE_SUFFIX         \
  }                               \
  if( k != stackk )               \
    ci_free(k);                   \
  return rc;                      \

#define MAP_DELETE_PREFIX                               \
  int rc;                                               \
  char stackk[MAX_STACK_SCRATCH_BYTES];                 \
  char* k = map->key_size > sizeof(stackk) ?            \
                  ci_alloc(map->key_size) : stackk;     \
                                                        \
  if( copy_from_user(k, ukey, map->key_size) )          \
    rc = -EFAULT;                                       \
  else {

#define MAP_DELETE_SUFFIX                               \
  }                                                     \
  if( k != stackk )                                     \
    ci_free(k);                                         \
  return rc;

#define MAP_GET_NEXT_PREFIX                                \
  int rc;                                                  \
  char stackk[MAX_STACK_SCRATCH_BYTES];                    \
  char* k = map->key_size * 2 > sizeof(stackk) ?           \
                  ci_alloc(map->key_size * 2) : stackk;    \
                                                           \
  (void)flags;                                             \
  if( ukey && copy_from_user(k, ukey, map->key_size) )     \
    rc = -EFAULT;                                          \
  else {

#define MAP_GET_NEXT_SUFFIX                                             \
    if( rc >= 0 )                                                       \
      if( copy_to_user(unext_key, k + map->key_size, map->key_size) )   \
        rc = -EFAULT;                                                   \
  }                                                                     \
  if( k != stackk )                                                     \
    ci_free(k);                                                         \
  return rc;

#endif
