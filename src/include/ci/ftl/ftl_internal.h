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
** \author  cgg
**  \brief  Furtle (FTL) header for internal extension
**   \date  2008/09
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef _FTL_INTERNAL_H
#define _FTL_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#define STATIC_INLINE static inline

#define FTL_MALLOC malloc
#define FTL_FREE   free

/*          Values 					                     */
  
typedef void value_delete_fn_t(value_t *value);

/* set the heap version of that values dependent on this value belong to */
typedef void value_markver_fn_t(const value_t *value, int version);

typedef int value_print_fn_t(outchar_t *out,
			     const value_t *root, const value_t *value);

typedef int value_cmp_fn_t(const value_t *v1, const value_t *v2);

struct value_s
{   struct value_s *link;
    struct value_s *heap_next;  /*< next value allocated in heap */
    value_print_fn_t *print;
    value_delete_fn_t *delete;
    value_markver_fn_t *mark_version;
    value_cmp_fn_t *compare;
    int heap_version;		/*< last heap version this was a member of */
    type_t kind;		/*< type of this value */
    unsigned char local;        /*< if local this is not free for collection */
    int lineno;                 /*< used only for debugging */
} /* value_t */;

extern /*internal*/ value_t *
(value_init)(value_t *val, type_t kind, value_print_fn_t *print,
	     value_cmp_fn_t *compare, value_delete_fn_t *delete,
	     value_markver_fn_t *mark_version);

STATIC_INLINE void
_value_unlocal(const value_t *val, int lineno)
{   /* we will need to discard the const - it applies only to the real content
       of the value - not its garbage collection status
       NOTE: this is potentially dangerous if a const value has been placed in
             read-only memory
    */
    /* if (NULL != val) allow value to be garbage collected as usual */
    if (NULL != val)
    {	/*IGNORE(if (!val->local)
	       fprintf(stderr, "%s: line %5d - value %p "
		       "not local made unlocal\n",
		       codeid(), lineno, val););*/
	((value_t *)val)->local = FALSE;
    }
}

#define value_unlocal(val) _value_unlocal(val, __LINE__)

  
/*          Directories					                     */

/* create a new name-value binding - name and value assumed to have
   permanent values (the name is not in the directory)
*/
typedef bool dir_add_fn_t(dir_t *dir, const value_t *name,
			  const value_t *value);

typedef const value_t **dir_lookup_fn_t(dir_t *dir, const value_t *name);

typedef unsigned dir_count_fn_t(dir_t *dir);

typedef const value_t *dir_get_fn_t(dir_t *dir, const value_t *name);

/* result is from first enumfn to return non NULL */
typedef void *dir_forall_fn_t(dir_t *dir, dir_enum_fn_t *enumfn, void *arg);

struct dir_s
{   value_t value;           /* directory used as a value */
    bool env_end;            /* true when dir is not to be looked beyond */ 
    dir_add_fn_t    *add;    /* add a new name-value pair */
    dir_lookup_fn_t *lookup; /* find address of value */
    dir_get_fn_t    *get   ; /* find corresponding value */
    dir_forall_fn_t *forall; /* ennumerate values */
    dir_count_fn_t  *count;  /* quick count of the number of values */
} /* dir_t */;

#define dir_value(dir) (&(dir)->value)

extern /*internal*/ value_t *
dir_init(dir_t *dir, dir_add_fn_t *add, dir_lookup_fn_t *lookup,
	 dir_get_fn_t *get, dir_forall_fn_t *forall,
	 value_print_fn_t *print, value_delete_fn_t *delete,
	 value_markver_fn_t *mark);
  
#ifdef __cplusplus
}
#endif


#endif /* _FTL_INTERNAL_H */
