/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2010 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_DEBUGFS_H
#define EFX_DEBUGFS_H

#ifdef CONFIG_SFC_DEBUGFS

struct seq_file;

struct efx_debugfs_parameter {
	const char *name;
	size_t offset;
	int (*reader)(struct seq_file *, void *);
};

extern void efx_fini_debugfs_child(efx_debugfs_entry *dir, const char *name);
extern int efx_init_debugfs_netdev(struct net_device *net_dev);
extern void efx_fini_debugfs_netdev(struct net_device *net_dev);
extern int efx_init_debugfs_nic(struct efx_nic *efx);
extern void efx_fini_debugfs_nic(struct efx_nic *efx);
extern int efx_init_debugfs_channels(struct efx_nic *efx);
extern void efx_fini_debugfs_channels(struct efx_nic *efx);
extern int efx_init_debugfs(void);
extern void efx_fini_debugfs(void);
extern int efx_extend_debugfs_port(struct efx_nic *efx,
				   void *context, u64 ignore,
				   struct efx_debugfs_parameter *params);
extern void efx_trim_debugfs_port(struct efx_nic *efx,
				  struct efx_debugfs_parameter *params);

/* Helpers for handling debugfs entry reads */
extern int efx_debugfs_read_uint(struct seq_file *, void *);
extern int efx_debugfs_read_ulong(struct seq_file *, void *);
extern int efx_debugfs_read_string(struct seq_file *, void *);
extern int efx_debugfs_read_int(struct seq_file *, void *);
extern int efx_debugfs_read_atomic(struct seq_file *, void *);
extern int efx_debugfs_read_dword(struct seq_file *, void *);
extern int efx_debugfs_read_u64(struct seq_file *, void *);
extern int efx_debugfs_read_bool(struct seq_file *, void *);

/* Handy macros for filling out parameters */

/* Initialiser for a struct efx_debugfs_parameter with type-checking */
#define EFX_PARAMETER(container_type, parameter, field_type,		\
			reader_function) {				\
	.name = #parameter,						\
	.offset = ((((field_type *) 0) ==				\
		    &((container_type *) 0)->parameter) ?		\
		   offsetof(container_type, parameter) :		\
		   offsetof(container_type, parameter)),		\
	.reader = reader_function,					\
}

/* Likewise, but the file name is not taken from the field name */
#define EFX_NAMED_PARAMETER(_name, container_type, parameter, field_type, \
				reader_function) {			\
	.name = #_name,							\
	.offset = ((((field_type *) 0) ==				\
		    &((container_type *) 0)->parameter) ?		\
		   offsetof(container_type, parameter) :		\
		   offsetof(container_type, parameter)),		\
	.reader = reader_function,					\
}

/* Likewise, but with one file for each of 4 lanes */
#define EFX_PER_LANE_PARAMETER(prefix, suffix, container_type, parameter, \
				field_type, reader_function) {		\
	.name = prefix "0" suffix,					\
	.offset = ((((field_type *) 0) ==				\
		      ((container_type *) 0)->parameter) ?		\
		    offsetof(container_type, parameter[0]) :		\
		    offsetof(container_type, parameter[0])),		\
	.reader = reader_function,					\
},  {									\
	.name = prefix "1" suffix,					\
	.offset = offsetof(container_type, parameter[1]),		\
	.reader = reader_function,					\
}, {									\
	.name = prefix "2" suffix,					\
	.offset = offsetof(container_type, parameter[2]),		\
	.reader = reader_function,					\
}, {									\
	.name = prefix "3" suffix,					\
	.offset = offsetof(container_type, parameter[3]),		\
	.reader = reader_function,					\
}

/* A string parameter (string embedded in the structure) */
#define EFX_STRING_PARAMETER(container_type, parameter) {	\
	.name = #parameter,					\
	.offset = ((((char *) 0) ==				\
		    ((container_type *) 0)->parameter) ?	\
		   offsetof(container_type, parameter) :	\
		   offsetof(container_type, parameter)),	\
	.reader = efx_debugfs_read_string,			\
}

/* An unsigned integer parameter */
#define EFX_UINT_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,		\
		      unsigned int, efx_debugfs_read_uint)

/* An unsigned long integer parameter */
#define EFX_ULONG_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,		\
		      unsigned long, efx_debugfs_read_ulong)

/* A dword parameter */
#define EFX_DWORD_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,		\
		      efx_dword_t, efx_debugfs_read_dword)

/* A u64 parameter */
#define EFX_U64_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,		\
		      u64, efx_debugfs_read_u64)

/* An atomic_t parameter */
#define EFX_ATOMIC_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,		\
		      atomic_t, efx_debugfs_read_atomic)

/* An integer parameter */
#define EFX_INT_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,		\
		      int, efx_debugfs_read_int)

#define EFX_BOOL_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,		\
		      bool, efx_debugfs_read_bool)

#else /* !CONFIG_SFC_DEBUGFS */

static inline int efx_init_debugfs_netdev(struct net_device *net_dev)
{
	return 0;
}
static inline void efx_fini_debugfs_netdev(struct net_device *net_dev) {}
static inline int efx_init_debugfs_port(struct efx_nic *efx)
{
	return 0;
}
static inline void efx_fini_debugfs_port(struct efx_nic *efx) {}
static inline int efx_init_debugfs_nic(struct efx_nic *efx)
{
	return 0;
}
static inline void efx_fini_debugfs_nic(struct efx_nic *efx) {}
static inline int efx_init_debugfs_channels(struct efx_nic *efx)
{
	return 0;
}
static inline void efx_fini_debugfs_channels(struct efx_nic *efx) {}
static inline int efx_init_debugfs(void)
{
	return 0;
}
static inline void efx_fini_debugfs(void) {}

#endif /* CONFIG_SFC_DEBUGFS */

#endif /* EFX_DEBUGFS_H */
