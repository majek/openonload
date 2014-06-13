/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
**  \brief  Furtle (FTL) header
**   \date  2005/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef _FTL_H
#define _FTL_H

#ifdef __cplusplus
extern "C" {
#endif

/* should be in stdbool.h, but we can't count on it being there */
#ifndef __bool_true_false_are_defined
#define bool  int
#define true  1
#define false 0
#define __bool_true_false_are_defined
#endif

#ifndef TRUE
#define TRUE  true
#define FALSE false
#endif

/*          O/S Independence				                     */


#include <pthread.h> /* for threads */
typedef pthread_t thread_os_t;
#define THREAD_OS_BAD 0

#define OS_PATH_SEP ':'
#define OS_FS_SEP '/';
#define OS_FS_CASE_EQ FALSE
#define OS_FS_NOWHERE "/dev/null"
#define OS_FS_DIR_HERE "."

#if defined(__ia64__) || defined(__x86_64__)
#define _SIZEOF_LONG 8
#endif

#ifndef _SIZEOF_LONG
#define _SIZEOF_LONG 4
#endif

#if _SIZEOF_LONG == 8

typedef long number_t;
typedef unsigned long unumber_t;
    
#define NUMBER(digits) digits##l
#define UNUMBER(digits) digits##ul
/* printf formats */
#define F_NUMBER_T "ld"
#define FX_UNUMBER_T "lx"
#define FXC_UNUMBER_T "lX"
#define F_UNUMBER_T "lu"

#else

typedef long long number_t;
typedef unsigned long long unumber_t;
    
#define NUMBER(digits) digits##ll
#define UNUMBER(digits) digits##ull
/* printf formats */
#define F_NUMBER_T "lld"
#define FX_UNUMBER_T "llx"
#define FXC_UNUMBER_T "llX"
#define F_UNUMBER_T "llu"

#endif /* _SIZEOF_LONG == 8 */
    

/*          O/S Independence - Threads			                     */

#define THREAD_DEFAULT_SIZE (64<<10)

typedef unsigned thread_main_fn_t(void *arg);

typedef struct
{   thread_main_fn_t *main;
} thread_work_t;

extern thread_os_t
thread_new(thread_main_fn_t *main, thread_work_t *work, size_t stacksize);

extern int /* rc */
thread_rc(thread_os_t thread);
    
extern bool
thread_active(thread_os_t thread);

extern thread_os_t
thread_self(void);
    
    
/*          O/S Independence - Time			                     */

extern void
sleep_ms(unsigned long milliseconds);

/*          O/S Independence - File Path		                     */

extern FILE *
fopen_onpath(const char *path, const char *name, size_t namelen,
             const char *mode, char *namebuf, size_t buflen);
    

/*          Code ID 				                             */

extern const char *
codeid(void);
    
extern void
codeid_set(const char *codeid);

/*          Character Sinks				                     */

typedef struct charsink_s charsink_t;


extern bool /*full*/
charsink_putc(charsink_t *sink, int ch);

extern int /*bytes*/
charsink_putwc(charsink_t *sink, wchar_t ch);

extern int
charsink_write(charsink_t *sink, const char *buf, size_t len);

extern int
charsink_vsprintf(charsink_t *sink, const char *format, va_list args);

extern int
charsink_sprintf(charsink_t *sink, const char *format, ...);

/*          Parser printing                                                  */

typedef charsink_t outchar_t;

#define outchar_printf charsink_sprintf
#define outchar_write  charsink_write
#define outchar_putc   charsink_putc

    


/*          Output Streams				                     */

extern charsink_t *
charsink_stream_new(FILE *out);

extern void
charsink_stream_delete(charsink_t **ref_sink);

/*          Output Containers				                     */

extern charsink_t *
charsink_string_new(void);

extern void
charsink_string_delete(charsink_t **ref_sink);

extern charsink_t *
charsink_fixstring_new(char *str, size_t len);

extern void
charsink_fixstring_delete(charsink_t **ref_sink);

extern void
charsink_string_buf(charsink_t *sink, const char **out_buf, size_t *out_len);
    
/*          Character Sources						     */

typedef struct charsource_s charsource_t;

extern void
charsource_close(charsource_t *source);

extern void
charsource_delete(charsource_t **ref_source);

    
/*          File-based Character Sources				     */
    
/*! data source is an already-open FILE * - closed on exit iff autoclose */
extern charsource_t *
charsource_stream_new(FILE *stream, const char *name, bool autoclose);

/*! data source a named file - closed on exit */
extern charsource_t *
charsource_file_new(const char *name);

/*! data source a named file - closed on exit */
extern charsource_t *
charsource_file_path_new(const char *path, const char *name, size_t namelen);

/*          Buffer-based Character Sources				     */

/*! data source is allocated copy of input string */
extern charsource_t *
charsource_string_new(const char *name, const char *string, size_t len);

/*! data source is the (constant) input string */
extern charsource_t *
charsource_cstring_new(const char *name, const char *string, size_t len);

/*          Prompting Character Sources				             */

/*! data source is a console on which input is prompted  */
extern charsource_t *
charsource_prompting_new(FILE *consolein, FILE *consoleout,
			 const char *prompt);

/*          Readline Character Sources				             */

/*! data source is a "readline" console on which input is prompted  */
extern charsource_t *
charsource_readline_new(const char *prompt);

/*          Charsource Stacks						     */

typedef charsource_t *instack_t;

extern instack_t *
instack_init(instack_t *ref_stack);

extern const char *
instack_source(instack_t stack);

extern int
instack_lineno(instack_t stack);

extern void
instack_push(instack_t *ref_stack, charsource_t *source);

extern charsource_t *
instack_pop(instack_t *ref_stack);

extern bool /* not empty */
instack_popdel(instack_t *ref_stack);

extern int
instack_getc(instack_t *ref_stack);

/*          Command Line Source						     */

typedef struct linesource_s linesource_t;

extern void
linesource_save(linesource_t *lines, linesource_t *saved);

extern void
linesource_restore(linesource_t *lines, linesource_t *saved);

extern void
linesource_push(linesource_t *lines, charsource_t *source);

extern charsource_t *
linesource_pop(linesource_t *lines);

extern const char *
linesource_source(linesource_t *lines);

extern int
linesource_lineno(linesource_t *lines);

extern bool
linesource_eof(linesource_t *source);

extern void
linesource_read(linesource_t *source, charsink_t *line);

extern void
linesource_pushline(linesource_t *lines, const char *name,
		    const char *cmd_str);

extern int
vreport(charsink_t *sink, linesource_t *source,
	const char *format, va_list ap);

extern int
report(charsink_t *sink, linesource_t *source, const char *format, ...);



    

/*          Types 					                     */

typedef enum
{   type_null = 1,
    type_type,
    type_int,
    type_ipaddr,
    type_macaddr,
    type_string,
    type_code,
    type_dir,
    type_closure,
    type_stream,
    type_cmd,
    type_func,
    type_coroutine,
} type_t;


extern const char *
type_name(type_t kind);

/*          Values 					                     */

typedef struct value_s value_t;

extern const char *
value_type_name(const value_t *val);

extern bool
value_type_equal(const value_t *val, type_t kind);

extern bool
value_istype(const value_t *val, type_t kind);

extern int
value_print(outchar_t *out, const value_t *root, const value_t *val);

extern int
value_cmp(const value_t *v1, const value_t *v2);

extern int
value_fprint(FILE *out, const value_t *root, const value_t *val);

#define VALUE_SHOW_RT(msg, root, val) \
{   printf("%s", msg);                \
    value_fprint(stdout, root, val);  \
    printf("\n");                     \
}

#define VALUE_SHOW_DR(msg, dir, val) \
        VALUE_SHOW_RT(msg, dir_value(dir), val)

#define VALUE_SHOW_ST(msg, state, val) \
        VALUE_SHOW_DR(msg, parser_env(state), val)

#define VALUE_SHOW(msg, val) VALUE_SHOW_RT(msg, NULL, val)

/*          NULL Values					                     */
    
extern value_t value_null;

extern const value_t *
value_nl(const value_t *value);

/*          Type Values					                     */

extern value_t *
value_type_new(type_t type_id);

extern bool
value_type_id(const value_t *value, type_t *out_type_id);

/*          IP Address Values				                     */

typedef unsigned char addr_ip_t[4]; 

extern int
ipaddr_fprint(FILE *out, const addr_ip_t *ip);

extern const value_t *
value_ipaddr_new(addr_ip_t *ref_ipaddr);

extern value_t *
value_ipaddr_new_quad(int a, int b, int c, int d);

extern void
value_ipaddr_get(const value_t *value, addr_ip_t *out_ipaddr);

extern bool
parse_ipaddr(const char **ref_line, addr_ip_t *out_ipaddr);

#define ipaddr_net32(ref_ip)                      \
        (((((unsigned char *)(ref_ip)))[3]<<24) | \
         ((((unsigned char *)(ref_ip)))[2]<<16) | \
         ((((unsigned char *)(ref_ip)))[1]<<8)  | \
         ((((unsigned char *)(ref_ip)))[0]) )

/*           Address Values				                     */

typedef unsigned char addr_mac_t[6]; 

extern int
macaddr_fprint(FILE *out, const addr_mac_t *mac);
    
extern const value_t *
value_macaddr_new(addr_mac_t *ref_macaddr);

extern value_t *
value_macaddr_new_sextet(int a, int b, int c, int d, int e, int f);

extern void
value_macaddr_get(const value_t *value, unsigned char *ref_macaddr);

extern bool
parse_macaddr(const char **ref_line, addr_mac_t *out_macaddr);

/*          Integer Values				                     */

extern value_t *
value_int_new(number_t number);

extern void
value_int_update(const value_t **ref_value, number_t n);

extern number_t
value_int_number(const value_t *value);

/*          Boolean Values				                     */
    
extern const value_t *value_true;
extern const value_t *value_false;

/*          String Values				                     */

extern value_t *
value_string_new(const char *string, size_t len);

#define value_string_new_measured(_string) \
        value_string_new(_string, strlen(_string))

extern value_t *
value_wcstring_new(const wchar_t *wcstring, size_t string_wchars);
/* convert from unicode string */

extern value_t *
value_cstring_new(const char *string, size_t len);
/* uncopied const string */

extern value_t *
value_substring_new(const value_t *string, size_t offset, size_t len);

extern void
value_string_update(const value_t **ref_value, const char *str);

extern bool
value_string_get(const value_t *value, const char **out_buf, size_t *out_len);

extern const char *
value_string_chars(const value_t *string);

/*          Code body Values				                     */

extern value_t *
value_code_new(const value_t *string, const char *defsource, int lineno);

extern bool
value_code_buf(const value_t *value, const char **out_buf, size_t *out_len);


/*          Stream Values                                                    */

typedef void
stream_close_fn_t(value_t *stream);
    
typedef void
stream_sink_close_fn_t(charsink_t *sink);
    
typedef void
stream_sink_delete_fn_t(charsink_t **ref_sink);

extern void
value_stream_close(value_t *value);

extern bool
value_stream_sink(const value_t *value, charsink_t **out_sink);

extern bool
value_stream_source(const value_t *value, charsource_t **out_source);

extern bool
value_stream_takesource(value_t *value, charsource_t **out_source);

/*          Filing System Stream Values                                      */

extern value_t *
value_stream_openfile_new(FILE *file, bool autoclose,
			  const char *name, bool read, bool write);

extern value_t *
value_stream_file_new(const char *name, bool read, bool write);

extern value_t *
value_stream_file_path_new(const char *path, const char *name, size_t namelen,
			   bool read, bool write,
	                   char *namebuf, size_t buflen);
  
/*          Socket Stream Values                                             */

extern value_t *
value_stream_opensocket_new(int fd, bool autoclose,
			    const char *name, bool read, bool write);
  
extern value_t *
value_stream_socket_new(const char *name, bool read, bool write);

  
/*          Socket Stream Values                                             */

extern value_t *
value_stream_instring_new(const char *name, const char *string, size_t len);

extern value_t *
value_stream_outstring_new(void);

extern value_t *
value_stream_outmem_new(char *str, size_t len);
  
/*          Directories					                     */

typedef struct dir_s dir_t;

typedef const void *dir_lock_state_t;

typedef void *dir_enum_fn_t(dir_t *dir, const value_t *name,
			    const value_t *value, void *arg);

extern value_t *
dir_value(dir_t *dir);

extern dir_lock_state_t *
dir_lock(dir_t *dir, dir_lock_state_t *old_lock);

extern bool
dir_islocked(dir_t *dir);

extern bool
dir_set(dir_t *dir, const value_t *name, const value_t *value);

extern const value_t *
dir_get(dir_t *dir, const value_t *name);

extern bool
dir_int_set(dir_t *dir, int index, const value_t *value);

extern bool
dir_string_set(dir_t *dir, const char *name, const value_t *value);

extern const value_t *
dir_int_get(dir_t *dir, int n);

extern const value_t *
dir_string_get(dir_t *dir, const char *name);

extern const value_t *
dir_stringl_get(dir_t *dir, const char *name, size_t namelen);

extern bool
dir_enumerable(dir_t *dir);

extern void *
dir_forall(dir_t *dir, dir_enum_fn_t *enumfn, void *arg);

extern unsigned
dir_count(dir_t *dir);
  
extern int
dir_fprint(FILE *out, const value_t *root, dir_t *dir);

#define DIR_SHOW_RT(msg, root, dir) \
{   printf("%s", msg);                \
    dir_fprint(stdout, root, dir);    \
    printf("\n");                     \
}

#define DIR_SHOW_DR(msg, root, dir) \
        DIR_SHOW_RT(msg, dir_value(root), dir)

#define DIR_SHOW_ST(msg, state, dir) \
        DIR_SHOW_DR(msg, parser_env(state), dir)

#define DIR_SHOW(msg, dir) DIR_SHOW_RT(msg, NULL, dir)


/*          Identifier Directories			                     */

extern dir_t *
dir_id_new(void);

/*          Field of Array/Structure Definition		                     */

typedef struct field_s field_t;

typedef enum
{   field_kind_val = 1,
    field_kind_struct,
    field_kind_union, 
    field_kind_array
} field_kind_t;

typedef void field_get_fn_t(const void *s, const value_t **ref_cached);
typedef void field_set_fn_t(void *s, const value_t *val);

extern void
field_init(field_t *ref_field, field_kind_t kind,
           field_set_fn_t *set, field_get_fn_t *get);

extern void
field_noset(void *mem, const value_t *val);

/*          Structure Directories			                     */

typedef struct struct_field_s struct_field_t;

typedef struct struct_spec_s struct_spec_t;
struct struct_spec_s {
    struct_field_t *fields;
    struct_field_t **end_fields;
} /* struct_spec_t */;

extern void
struct_spec_init(struct_spec_t *spec);

extern void
struct_spec_end(struct_spec_t *spec);

extern void
struct_spec_add_field(struct_spec_t *spec, field_kind_t kind,
		      const char *name, 
		      field_set_fn_t *set, field_get_fn_t *get);


#define FTL_DECLARE(struct_macro) struct_macro(DECL)
#define FTL_DEFINE(struct_macro)  struct_macro(DEF)
#define FTL_UNDEFINE(struct_macro)  struct_macro(UNDEF)

#define FTL_TSPEC(type) _ftlspec__##type

#define _FTL_STRUCT_BEGIN_DECL(_spec, tag) \
        static struct_spec_t _spec;
#define _FTL_STRUCT_BEGIN_DEF(_spec, tag) \
        struct_spec_init(&_spec);
#define _FTL_STRUCT_BEGIN_UNDEF(_spec, tag) \
        struct_spec_end(&_spec);
#define FTL_STRUCT_BEGIN(_ctx, _spec, tag) _FTL_STRUCT_BEGIN_##_ctx(_spec, tag)
#define FTL_TSTRUCT_BEGIN(_ctx, _type, tag) \
        FTL_STRUCT_BEGIN(_ctx, FTL_TSPEC(_type), tag)
        

#define _FTL_STRUCT_END_DECL()
#define _FTL_STRUCT_END_DEF()
#define _FTL_STRUCT_END_UNDEF()
#define FTL_STRUCT_END(_ctx) _FTL_STRUCT_END_##_ctx()
#define FTL_TSTRUCT_END(_ctx) FTL_STRUCT_END(_ctx)

#define FTL_UNION_BEGIN     FTL_STRUCT_BEGIN
#define FTL_TUNION_BEGIN    FTL_TSTRUCT_BEGIN
#define FTL_UNION_END       FTL_STRUCT_END
#define FTL_TUNION_END      FTL_TSTRUCT_END

#define FTL_VARS_BEGIN(ctx, spec) \
                            FTL_STRUCT_BEGIN(ctx, spec, )
#define FTL_VARS_END        FTL_STRUCT_END


#define _FTL_FIELD_INT_DECL(spec, stype, ftype, field)		        \
    static void stype##__##field##__get(const void *mem,                \
                                        const value_t **ref_cached)     \
    {   value_int_update(ref_cached, ((stype *)mem)->field); }		\
    static void stype##__##field##__set(void *mem, const value_t *val)	\
    {   ((stype *)mem)->field = (ftype)value_int_number(val); }
#define _FTL_FIELD_INT_DEF(spec, stype, ftype, field)			\
    struct_spec_add_field(&spec, field_kind_val, #field,		\
			  &stype##__##field##__set, &stype##__##field##__get);
#define _FTL_FIELD_INT_UNDEF(spec, stype, ftype, field)
#define FTL_FIELD_INT(_ctx, spec, stype, ftype, field)		        \
        _FTL_FIELD_INT_##_ctx(spec, stype, ftype, field)
#define FTL_TFIELD_INT(_ctx, _stype, ftype, field)		        \
        FTL_FIELD_INT(_ctx, FTL_TSPEC(_stype), _stype, ftype, field)


#define _FTL_FIELD_CONSTINT_DECL(spec, stype, ftype, field)	        \
    static void stype##__##field##__get(const void *mem,                \
                                        const value_t **ref_cached)     \
    {   value_int_update(ref_cached, ((stype *)mem)->field); }
#define _FTL_FIELD_CONSTINT_DEF(spec, stype, ftype, field)		\
    struct_spec_add_field(&spec, field_kind_val, #field,		\
			  NULL, &stype##__##field##__get);
#define _FTL_FIELD_CONSTINT_UNDEF(spec, stype, ftype, field)
#define FTL_FIELD_CONSTINT(_ctx, spec, stype, ftype, field)	        \
        _FTL_FIELD_CONSTINT_##_ctx(spec, stype, ftype, field)
#define FTL_TFIELD_CONSTINT(_ctx, _stype, ftype, field)		        \
        FTL_FIELD_CONSTINT(_ctx, FTL_TSPEC(_stype), _stype, ftype, field)


/* Note: these fields can be used to override a "const" field so that the
   compiler will allow us to write to it - this can be unsafe in some
   compilers.  Also the technique used can not be applied to fields that are
   based on bitfields. */
#define _FTL_FIELD_UNCONSTINT_DECL(spec, stype, ftype, field)	        \
    static void stype##__##field##__get(const void *mem,                \
                                        const value_t **ref_cached)     \
    {   value_int_update(ref_cached, ((stype *)mem)->field); }		\
    static void stype##__##field##__set(void *mem, const value_t *val)	\
    {   ftype *ptr = (ftype *)&(((stype *)mem)->field);                 \
        *ptr = (ftype)value_int_number(val);                            \
    }
#define _FTL_FIELD_UNCONSTINT_DEF(spec, stype, ftype, field)		\
    struct_spec_add_field(&spec, field_kind_val, #field,		\
			  &stype##__##field##__set, &stype##__##field##__get);
#define _FTL_FIELD_UNCONSTINT_UNDEF(spec, stype, ftype, field)
#define FTL_FIELD_UNCONSTINT(_ctx, spec, stype, ftype, field)	        \
        _FTL_FIELD_UNCONSTINT_##_ctx(spec, stype, ftype, field)
#define FTL_TFIELD_UNCONSTINT(_ctx, _stype, ftype, field)	        \
        FTL_FIELD_UNCONSTINT(_ctx, FTL_TSPEC(_stype), _stype, ftype, field)


#define _FTL_FIELD_STRUCT_DECL(spec, stype, ftype, field, fspec)  \
    static void stype##__##field##__get(const void *mem,                \
                                        const value_t **ref_cached)     \
    {   dir_struct_update(ref_cached, &fspec, /*is_const*/FALSE,        \
                          (void *)&((stype *)mem)->field);              \
    }									
#define _FTL_FIELD_STRUCT_DEF(spec, stype, ftype, field, fspec)         \
    struct_spec_add_field(&spec, field_kind_struct, #field,		\
			  &field_noset, &stype##__##field##__get);
#define _FTL_FIELD_STRUCT_UNDEF(spec, stype, ftype, field, fspec)
#define FTL_FIELD_STRUCT(_ctx, spec, stype, ftype, field, fspec)	\
        _FTL_FIELD_STRUCT_##_ctx(spec, stype, ftype, field, fspec)
#define FTL_TFIELD_STRUCT(_ctx, _stype, ftype, field)			\
        FTL_FIELD_STRUCT(_ctx, FTL_TSPEC(_stype), _stype,               \
                         ftype, field, FTL_TSPEC(ftype))


#define _FTL_VAR_INT_DECL(spec, vtype, var)		                \
    static void _var__##var##__get(const void *mem,                     \
                                   const value_t **ref_cached)          \
    {   value_int_update(ref_cached, var); }                            \
    static void _var__##var##__set(void *mem, const value_t *val)	\
    {   var = (vtype)value_int_number(val); }
#define _FTL_VAR_INT_DEF(spec, vtype, var)			        \
    struct_spec_add_field(&spec, field_kind_val, #var,		        \
			  &_var__##var##__set, &_var__##var##__get);
#define _FTL_VAR_INT_UNDEF(spec, vtype, var)
#define FTL_VAR_INT(_ctx, spec, vtype, var)		                \
        _FTL_VAR_INT_##_ctx(spec, vtype, var)


#define _FTL_VAR_CONSTINT_DECL(spec, vtype, var)		        \
    static void _var__##var##__get(const void *mem,                     \
                                   const value_t **ref_cached)          \
    {   value_int_update(ref_cached, var); }
#define _FTL_VAR_CONSTINT_DEF(spec, vtype, var)			        \
    struct_spec_add_field(&spec, field_kind_val, #var,		        \
			  NULL, &_var__##var##__get);
#define _FTL_VAR_CONSTINT_UNDEF(spec, vtype, var)
#define FTL_VAR_CONSTINT(_ctx, spec, vtype, var)	                \
        _FTL_VAR_CONSTINT_##_ctx(spec, vtype, var)


#define _FTL_VAR_CONSTSTR_DECL(spec, vtype, var)		        \
    static void _var__##var##__get(const void *mem,                     \
                                   const value_t **ref_cached)          \
    {   value_string_update(ref_cached, var); }
#define _FTL_VAR_CONSTSTR_DEF(spec, vtype, var)			        \
    struct_spec_add_field(&spec, field_kind_val, #var,		        \
			  NULL, &_var__##var##__get);
#define _FTL_VAR_CONSTSTR_UNDEF(spec, vtype, var)
#define FTL_VAR_CONSTSTR(_ctx, spec, vtype, var)	                \
        _FTL_VAR_CONSTSTR_##_ctx(spec, vtype, var)


extern dir_t *
dir_struct_new(struct_spec_t *spec, bool is_const, void *malloc_struct);

extern dir_t *
dir_struct_cast(struct_spec_t *spec, bool is_const,
		const value_t *ref, void *ref_struct);

#define dir_vars(spec, const, ref) dir_struct_cast(spec, const, ref, NULL)

extern dir_t *
dir_cstruct_new(struct_spec_t *spec, bool is_const, void *static_struct);

extern void
dir_struct_update(const value_t **ref_value,
		  struct_spec_t *spec, bool is_const, void *structmem);



/*          Array Directories			                     */

typedef struct 
{   field_t *field;
    size_t elems;
} array_spec_t;

extern void
array_spec_init(array_spec_t *spec);

extern void
array_spec_end(array_spec_t *spec);

extern void
array_spec_set_cont(array_spec_t *spec, field_kind_t kind, size_t elems,
                    field_set_fn_t *set, field_get_fn_t *get);


#define FTL_ARRAY_ELEMS(array)  (sizeof(array)/sizeof((array)[0]))
#define FTL_ARRAY_STRIDE(array) ((char *)(&(array)[1]) - (char *)(&(array)[0]))

#define _FTL_ARRAY_BEGIN_DECL(_spec) \
        static array_spec_t _spec;
#define _FTL_ARRAY_BEGIN_DEF(_spec) \
        array_spec_init(&_spec);
#define _FTL_ARRAY_BEGIN_UNDEF(_spec) \
        array_spec_end(&_spec);
#define FTL_ARRAY_BEGIN(_ctx, _spec) \
        _FTL_ARRAY_BEGIN_##_ctx(_spec)
#define FTL_TARRAY_BEGIN(_ctx, _type) \
        FTL_ARRAY_BEGIN(_ctx, FTL_TSPEC(_type))

#define _FTL_ARRAY_END_DECL()
#define _FTL_ARRAY_END_DEF()
#define _FTL_ARRAY_END_UNDEF()
#define FTL_ARRAY_END(_ctx) _FTL_ARRAY_END_##_ctx()
#define FTL_TARRAY_END(_ctx) FTL_ARRAY_END(_ctx)

#define _FTL_ARRAY_INT_DECL(spec, stype, ctype, elems)			  \
    static void stype##__get(const void *mem, const value_t **ref_cached) \
    {   value_int_update(ref_cached, ((ctype *)(mem))[0]); }		  \
    static void stype##__set(void *mem, const value_t *val)	          \
    {   ((ctype *)(mem))[0] = (ctype)value_int_number(val);}
#define _FTL_ARRAY_INT_DEF(spec, stype, ctype, elems)		          \
    array_spec_set_cont(&spec, field_kind_val, elems,                     \
		        &stype##__set, &stype##__get);
#define _FTL_ARRAY_INT_UNDEF(spec, stype, ctype, elems)
#define FTL_ARRAY_INT(_ctx, spec, _atype, ctype, elems)		          \
        _FTL_ARRAY_INT_##_ctx(spec, _atype, ctype, elems)
#define FTL_TARRAY_INT(_ctx, _atype, _ctype, elems)			  \
        FTL_ARRAY_INT(_ctx, FTL_TSPEC(_atype), _atype, _ctype, elems)


#define _FTL_ARRAY_STRUCT_DECL(aspec, _atype_uid, cspec, elems)	          \
    static void _atype_uid##___get(const void *mem,                       \
				   const value_t **ref_cached)            \
    {   dir_struct_update(ref_cached, &cspec, /*is_const*/FALSE,          \
                          (void *)mem);		                          \
    }									
#define _FTL_ARRAY_STRUCT_DEF(aspec, _atype_uid, cspec, elems)	          \
    array_spec_set_cont(&aspec, field_kind_struct, elems,                 \
			&field_noset, &_atype_uid##___get);
#define _FTL_ARRAY_STRUCT_UNDEF(aspec, _atype_uid, cspec, elems)   
#define FTL_ARRAY_STRUCT(_ctx, aspec, _atype, cspec, elems)               \
    _FTL_ARRAY_STRUCT_##_ctx(aspec, _atype, cspec, elems)
#define FTL_TARRAY_STRUCT(_ctx, _atype, _ctype, elems)		          \
        FTL_ARRAY_STRUCT(_ctx, FTL_TSPEC(_atype), _atype,		  \
                         FTL_TSPEC(_ctype), elems)

#define _FTL_FIELD_ARRAY_DECL(sspec, stype, field, fspec)                 \
    static void stype##__##field##__get(const void *mem,                  \
                                        const value_t **ref_cached)       \
    {   dir_array_update(ref_cached, &fspec, /*is_const*/FALSE,           \
			 ((stype *)mem)->field,				  \
			 FTL_ARRAY_STRIDE(((stype *)mem)->field));	  \
    }
#define _FTL_FIELD_ARRAY_DEF(sspec, stype, field, fspec)	          \
    struct_spec_add_field(&sspec, field_kind_array, #field,		  \
			  &field_noset, &stype##__##field##__get);
#define _FTL_FIELD_ARRAY_UNDEF(sspec, stype, field, fspec)
#define FTL_FIELD_ARRAY(_ctx, sspec, _stype,  field, fspec)	          \
        _FTL_FIELD_ARRAY_##_ctx(sspec, _stype, field, fspec)
#define FTL_TFIELD_ARRAY(_ctx, _stype, _ftype, field)		          \
        FTL_FIELD_ARRAY(_ctx, FTL_TSPEC(_stype), _stype,		  \
			field, FTL_TSPEC(_ftype))


#define FTL_FIELD_ARRAYOFSTRUCT(_ctx, sspec, _stype, field, cspec, elems) \
        FTL_ARRAY_BEGIN(_ctx, FTL_TSPEC(_stype##__##field))		  \
	FTL_ARRAY_STRUCT(_ctx, FTL_TSPEC(_stype##__##field),              \
			  _stype##__##field, cspec, elems)	          \
        FTL_ARRAY_END(_ctx)                                               \
	FTL_FIELD_ARRAY(_ctx, sspec, _stype, field,                       \
			FTL_TSPEC(_stype##__##field))
#define FTL_TFIELD_ARRAYOFSTRUCT(_ctx, _stype, _ctype, field, elems)	  \
        FTL_FIELD_ARRAYOFSTRUCT(_ctx, FTL_TSPEC(_stype), _stype,	  \
			  field, FTL_TSPEC(_ctype), elems)

#define FTL_FIELD_ARRAYOFINT(_ctx, sspec, _stype, field, _ctype, elems)   \
        FTL_ARRAY_BEGIN(_ctx, FTL_TSPEC(_stype##__##field))		  \
	FTL_ARRAY_INT(_ctx, FTL_TSPEC(_stype##__##field),                 \
		      _stype##__##field##__array, _ctype, elems)	  \
        FTL_ARRAY_END(_ctx)                                               \
	FTL_FIELD_ARRAY(_ctx, sspec, _stype, field,                       \
			FTL_TSPEC(_stype##__##field))
#define FTL_TFIELD_ARRAYOFINT(_ctx, _stype, _ctype, field, elems)	  \
        FTL_FIELD_ARRAYOFINT(_ctx, FTL_TSPEC(_stype), _stype,	          \
			  field, _ctype, elems)


/* you may wish to use dir_lock() after the following calls */
    
extern dir_t *
dir_carray_new(array_spec_t *spec,bool is_const,
	       void *static_array, size_t stride);

extern dir_t *
dir_array_new(array_spec_t *spec, bool is_const,
	      void *malloc_array, size_t stride);

extern dir_t *
dir_array_cast(array_spec_t *spec, bool is_const,
	       const value_t *ref, void *ref_array, size_t stride);
    
extern dir_t *
dir_array_string(array_spec_t *spec, bool is_const,
	         const value_t *string, size_t stride);

extern void
dir_array_update(const value_t **ref_value, array_spec_t *spec, bool is_const,
		 void *arraymem, size_t stride);

/*          String Argument vector Directories		                     */

extern dir_t *
dir_argvec_new(int argc, char **argv);

/*          Integer vector Directories			                     */

extern dir_t *
dir_vec_new(void);

/*          Integer Series Directories			                     */

extern dir_t *
dir_series_new(number_t first, number_t inc, number_t last);

/*          System Env Directories			                     */

extern dir_t *
dir_sysenv_new(void);


/*          Stacked Directory Directories	                             */

typedef struct dir_stack_s dir_stack_t;

typedef value_t **dir_stack_pos_t;
#define DIR_STACK_POS_BAD ((dir_stack_pos_t)NULL)

extern dir_t *
dir_stack_new(void);

extern dir_stack_t *
dir_stack_copy(dir_stack_t *old);

extern dir_stack_pos_t
dir_stack_push(dir_stack_t *dir, dir_t *newdir, bool env_end);

extern dir_stack_pos_t
dir_stack_pos_enclosing(dir_stack_t *dir, dir_t *innerdir);

extern void
dir_stack_return(dir_stack_t *dir, dir_stack_pos_t pos);

extern dir_stack_pos_t
dir_stack_last_pos(dir_stack_t *dir);

    

/*          Closure Environments			                     */

typedef struct value_env_s value_env_t;

extern value_t *
value_env_new(void);

extern void
value_env_pushdir(value_env_t *env, dir_t *newdir, bool env_end);

extern value_t * /*pos*/
value_env_pushunbound(value_env_t *env, value_t *pos, value_t *name);

extern bool
value_env_pushenv(value_env_t *env, value_env_t *newenv, bool env_end);

extern value_t *
value_env_bind(value_env_t *envval, const value_t *value);

/*          Closure Values				                     */

extern value_t *
value_closure_new(const value_t *code, value_env_t *env);

extern bool
value_closure_pushdir(const value_t *value, dir_t *dir, bool env_end);

extern bool
value_closure_pushenv(const value_t *value, value_env_t *env, bool env_end);

extern bool
value_closure_get(const value_t *value, const value_t **out_code,
		  dir_t **out_env, const value_t **out_unbound);

extern value_t * /*pos*/
value_closure_pushunbound(value_t *value, value_t *pos, value_t *name);

extern value_t *
value_closure_bind(const value_t *envval, const value_t *value);

/*          Transfer Functions					             */

extern bool
value_to_dir(const value_t *val, dir_t **out_dir);

extern bool
value_as_dir(const value_t *val, dir_t **out_dir); /* complains if uncast */

/*          Coroutine Values					             */

typedef struct value_coroutine_s value_coroutine_t;
typedef void suspend_fn_t(unsigned long milliseconds);

extern value_coroutine_t *
value_coroutine_new(dir_t *root, dir_stack_t *env, dir_t *opdefs);


/*          Parser State					             */

typedef value_coroutine_t parser_state_t;

extern parser_state_t *
parser_state_new(dir_t *root);

extern void
parser_state_free(parser_state_t *state);

extern linesource_t *
parser_linesource(parser_state_t *parser_state);

extern dir_t *
parser_root(parser_state_t *parser_state);

extern dir_t *
parser_env(parser_state_t *parser_state);

extern dir_t *
parser_env_copy(parser_state_t *parser_state);

extern const value_t *
parser_builtin_arg(parser_state_t *parser_state, int argno);

extern dir_stack_t *
parser_env_stack(parser_state_t *parser_state);

extern dir_stack_pos_t
parser_env_push(parser_state_t *parser_state, dir_t *newdir, bool env_end);

extern bool /* ok */
parser_env_push_at_pos(parser_state_t *parser_state, dir_stack_pos_t pos,
		       dir_t *newdir, bool env_end);

/* Restore environment stack back to previous (outer) level */
extern void
parser_env_return(parser_state_t *parser_state, dir_stack_pos_t pos);

/* The environment stack position when the current function was called */
extern dir_stack_pos_t
parser_env_calling_pos(parser_state_t *parser_state);

extern bool
parser_echo(parser_state_t *parser_state);

extern void
parser_echo_set(parser_state_t *parser_state, bool on);
 
extern suspend_fn_t *
parser_suspend_get(parser_state_t *parser_state);

extern void
parser_suspend_set(parser_state_t *parser_state, suspend_fn_t *sleep);

extern int
charsink_parser_vreport(charsink_t *sink, parser_state_t *parser_state,
	                const char *format, va_list ap);

#define parser_vreport(state, format, ap) \
        charsink_parser_vreport(NULL, state, format, ap)

extern int
charsink_parser_value_print(charsink_t *sink, parser_state_t *parser_state,
			    const value_t *val);

#define parser_value_print(state, val)  \
        charsink_parser_value_print(NULL, state, val)

extern int
parser_report(parser_state_t *parser_state, const char *format, ...);

extern int
parser_error(parser_state_t *parser_state, const char *format, ...);

extern const value_t *
parser_errorval(parser_state_t *parser_state, const char *format, ...);

extern int
parser_error_count(parser_state_t *parser_state);
    
extern int
parser_report_help(parser_state_t *parser_state, const value_t *cmd);

extern void
parser_collect(parser_state_t *state);

extern outchar_t *
parser_expand(parser_state_t *state, outchar_t *out,
	      const char *phrase, size_t len);

/*          Line Parsing						     */

extern bool
parse_empty(const char **ref_line);

extern bool
parse_white(const char **ref_line);

extern bool
parse_space(const char **ref_line);

extern bool
parse_key(const char **ref_line, const char *key);

extern bool
parse_int(const char **ref_line, number_t *out_int);

extern bool
parse_hex(const char **ref_line, unumber_t *out_int);

extern bool
parse_hex_width(const char **ref_line, unsigned width, unumber_t *out_int);

extern bool
parse_int_val(const char **ref_line, number_t *out_int);

extern bool
parse_int_expr(const char **ref_line, 
	       parser_state_t *state, number_t *out_int);

extern bool
parse_item(const char **ref_line, const char *delims, size_t ndelims,
	   char *buf, size_t len);

extern bool
parse_id(const char **ref_line, char *buf, size_t size);

/* note: succeeds if syntax is correct even if insufficient room in the buffer
         including when there is no room for a terminating null (len==0) */
extern bool
parse_string(const char **ref_line, char *buf, size_t len, size_t *out_len);

/* note: succeeds if syntax is correct even if insufficient room in the buffer
         including when there is no room for a terminating null (len==0) */
extern bool
parse_string_expr(const char **ref_line, parser_state_t *state,
		  char *buf, size_t len, const value_t **out_string);

extern bool
parse_itemstr(const char **ref_line, char *buf, size_t size);

extern bool
parse_type(const char **ref_line, type_t *out_type_id);

typedef bool
parse_match_fn_t(const char **ref_line, parser_state_t *state,
		 const value_t *name, void *arg);

extern bool
parse_oneof_matching(const char **ref_line, parser_state_t *state,
	             dir_t *prefixes, const value_t **out_val,
		     parse_match_fn_t *match_fn, void *match_fn_arg);
    
extern bool
parse_oneof(const char **ref_line, parser_state_t *state, dir_t *prefixes,
            const value_t **out_val);

    

/*          Command Values					             */

typedef const value_t *cmd_fn_t(const char **ref_line, const value_t *this_cmd,
		                parser_state_t *state);

extern value_t *
value_cmd_new(cmd_fn_t *exec, const value_t *fn_exec, const char *help);

extern const char *
value_cmd_help(const value_t *cmd);


/*          Function Values					             */

typedef const value_t *func_fn_t(const value_t *this_func,
				 parser_state_t *state);

extern value_t *
value_func_new(func_fn_t *exec, const char *help, int args, void *implicit);

extern void *
value_func_implicit(const value_t *func); /* deliver implicit arguments */

extern const char *
value_func_help(const value_t *func);

/*          Modules 					                     */

extern value_t *
mod_add(dir_t *dir, const char *name, const char *help, cmd_fn_t *exec);

extern value_t *
mod_addfn(dir_t *dir, const char *name, const char *help, func_fn_t *exec,
	  int args);
    
extern value_t *
mod_addfn_imp(dir_t *dir, const char *name, const char *help, func_fn_t *exec,
	      int args, void *implicit_args);

extern void
mod_add_dir(dir_t *dir, const char *name, dir_t *mod);

extern void
mod_add_val(dir_t *dir, const char *name, const value_t *val);

extern bool
mod_parse_cmd(dir_t *dir, const char **ref_line, const value_t **out_cmd);

extern void *
mod_get_implicit(const value_t *this_fn);

/*          Value Parsing						     */

extern bool
parse_int_base(const char **ref_line, parser_state_t *state,
	       number_t *out_int);

/* most complex expression built using delimiters */
extern bool
parse_retrieval(const char **ref_line, parser_state_t *state,
		const value_t **out_val);

extern bool
parse_expr(const char **ref_line, parser_state_t *state,
	   const value_t **out_val);


/*          Command Line Interpreter					     */

extern const value_t *
mod_exec_cmd(const char **ref_line, parser_state_t *state);

extern const value_t *
parser_expand_exec(parser_state_t *state, charsource_t *source,
		   const char *cmd_str, const char *rcfile_id,
		   bool expect_no_locals);

#define parser_expand_string_exec(state, cstring, stringlen, no_locals)     \
        parser_expand_exec(state,                                           \
			   charsource_cstring_new(#cstring, cstring,        \
                                                  stringlen),               \
                           NULL, NULL, no_locals)

#define parser_expand_file_exec(state, filename, no_locals) \
        parser_expand_exec(state, charsource_file_new(filename),            \
                           NULL, NULL, no_locals)

#define parser_expand_file_path_exec(state, path, filename, no_locals)        \
        parser_expand_exec(state, charsource_file_path_new(path, filename,    \
                                                           strlen(filename)), \
                           NULL, NULL, no_locals)


extern void
cli(parser_state_t *state, const char *rcfile, const char *code_name);

extern void
argv_cli(parser_state_t *state, const char *code_name, const char *execpath,
         const char **argv, int argc);


/*          Generic Commands					             */

extern void
cmds_generic(parser_state_t *state, int argc, char **argv);

/*          Library initialization				             */

extern void
ftl_version(int *out_major, int *out_minor, int *out_debug);

extern void
ftl_init(void);

extern void
ftl_end(void);


#ifdef __cplusplus
}
#endif


#endif /* _FTL_H */
