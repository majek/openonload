/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* This is the userspace interface to Onload's BPF kernel facilities. The API
 * is split in to low-level (almost a raw wrapper around the ioctls) and
 * more usable high-level facilities. */

#ifndef ONLOAD_OOBPF_H_
#define ONLOAD_OOBPF_H_

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include "bpf_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OOBPFIMPL_STATIC
# define OOBPFIMPL_PUBLIC
#else
# define OOBPFIMPL_PUBLIC __attribute__((visibility("default")))
#endif

/* -*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*- */
/*                              low-level API                              */

/* prog ioctls */

/* On a /dev/onload_bpf fd, check that the user/kernel ABI is matching.
 * Returns 0 if the ABI is good, negative (and sets errno) if the application
 * must not continue.
 * This must be used first, before any other requests are made on the fd. This
 * version check will usually have to be done only once per program, however
 * be aware that if an application closes all its Onload and onload_bpf fds
 * then it is possible for the kernel driver to change while the application
 * is still running. */
OOBPFIMPL_PUBLIC
int oo_bpf_check_version(int drv);


/* Load, verify and store an eBPF program for later use by Onload. 'drv' is a
 * /dev/onload_bpf fd which has been opened by the application. The
 * newly-loaded program is represented by the fd returned from this
 * function.
 *
 * This function and many of its parameters mirror those from the
 * BPF_PROG_LOAD command in "man 2 bpf". The differences are:
 *  - This function is available on old kernels, without native support for
 *    BPF.
 *  - Onload BPF fds are mutually incompatible with kernel BPF fds. Attempting
 *    to pass an Onload BPF fd to a kernel facility (e.g. SO_ATTACH_BPF) will
 *    fail; attempting to use a kernel bpf fd with Onload facilities will also
 *    fail.
 *  - Some features of BPF are not supported by Onload. See the user guide for
 *    full information.
 *
 * Returns a non-negative fd on success. On error, -1 is returned and errno
 * is set appropriately. */
OOBPFIMPL_PUBLIC
int oo_bpf_prog_load(int drv, const struct oo_bpf_prog_load_arg* arg);


/* Retrieves a program that has been previously attached by
 * oo_bpf_prog_attach(). The fd passed in must be a /dev/onload_bpf_prog fd
 * which has been opened by the application and which has not previously had a
 * program loaded on it. After this function returns successfully, that fd will
 * identify the BPF program loaded at the specified attachment, as if
 * oo_bpf_prog_load had been used.
 *
 * Returns 0 on success. On error, -1 is returned and errno is set
 * appropriately. */
OOBPFIMPL_PUBLIC
int oo_bpf_prog_get_by_attachment(int fd,
                                  const struct oo_bpf_prog_attach_arg* arg);


/* Attach a loaded program to entities in the system, so that it will be run
 * for packets within Onload stacks. The parameters in 'arg' are:
 *   prog_fd: The program to attach, as returned by oo_bpf_prog_load()
 *   flags:
 *     OO_BPF_PROG_ATTACH_F_REPLACE: If an existing attachment with the same
 *        attach_point+ifindex+stack already exists, atomically replace it
 *        with the given program. Without this flag, such a call will fail
 *        with EEXIST.
 *   attach_point: The location during packet processing where this program
 *       is to be attached. Required. This value must match the 'prog_type'
 *       passed to oo_bpf_prog_load: different attachment points pass
 *       different context parameters to the program.
 *   ifindex: Run the program only for packets using this network interface.
 *       May be zero to run the program on all interfaces. This must be a real
 *       Solarflare interface - other values will cause EOPNOTSUPP. Suitable
 *       interfaces include sfc PFs and VFs but do not include bonds, VLANs,
 *       etc. on top of those. This is equivalent to using the 'xdpdrv' option
 *       in iproute2 with kernel BPF. Onloaded applications using derived
 *       interfaces will still be subject to BPF programs, however those
 *       programs will run on packets for the raw interfaces (e.g. they will
 *       have to process packets containing VLAN tags, etc.).
 *   stack: Run the program only for packets within the Onload stack with this
 *       name, as specified by EF_NAME or EF_CLUSTER_NAME. May be the empty
 *       string to run the program on all Onloaded processes. The stack need
 *       not exist at the time of calling this function; if it is created in
 *       the future then the attached program will be run from the very first
 *       packet processed. There may be multiple stacks with the same name
 *       (separated either by time or by network namespace); the program will
 *       be run on them all.
 *
 * Only one program may be attached to a given attach_point+ifindex+stack
 * triple. Attempting to attach a second will fail, unless
 * OO_BPF_PROG_ATTACH_F_REPLACE is passed in which case the original
 * attachment will be removed in order to replace it with the new one. This
 * constraint applies equally to attachments with the wildcard ifindex or
 * stack: there can be at most one of them as well. The replacement is
 * performed atomically, so is a technique which may be used to perform bulk
 * modification of maps without the possibility of misprocessing any packets.
 *
 * Given the wildcard support for ifindex and stack, it is possible that
 * multiple attached programs may be considered applicable for a single
 * packet. Only the single 'most specific' program will be run, where a
 * matching stack name is more specific than a matching ifindex, and both are
 * more specific than an all-wildcards attachment.
 *
 * Attachments take effect immediately, applying to current and future
 * Onloaded applications.
 *
 * Returns 0 on success. On error, -1 is returned and errno is set
 * appropriately. */
OOBPFIMPL_PUBLIC
int oo_bpf_prog_attach(int drv, struct oo_bpf_prog_attach_arg* arg);


/* Removes a program previously attached by oo_bpf_prog_attach(), so that it
 * will not be run for any future packets. The attachment specified by the
 * exact triple attach_point+ifindex+stack is removed (where wildcard values
 * only match attachments that were made with that same wildcard).
 *
 * This function may be called either with an oo_bpf_prog_attach_arg::prog_fd
 * set to a loaded program (from oo_bpf_prog_load()) or to -1. In the former
 * case, the detach is only performed if the attachment was for that specific
 * program. If fd is -1, any program attached at the specified triple is
 * detached.
 *
 * Detachments take effect immediately, applying to current and future
 * Onloaded applications.
 *
 * Returns 0 on success. On error, -1 is returned and errno is set
 * appropriately. */
OOBPFIMPL_PUBLIC
int oo_bpf_prog_detach(int drv, struct oo_bpf_prog_attach_arg* arg);


/* Run a BPF program repeatedly, in order to benchmark it. The run will be
 * done in kernelspace. To test a programme in userspace in a similar way,
 * map the program in using the normal method and then invoke it manually. The
 * parameters in 'arg' are:
 *   iterations: Number of times to run the program. There is an internal
 *               cap on this value. On return, this value will contain the
 *               number of times the program actually ran
 *   pkt_len: Number of bytes in 'pkt'. On output, this will be the number of
 *            bytes in the modified version of the pkt
 *   ticks: Output value containing the amount of time taken to run
 *          'iterations' occurrences of the program, in rdtsc ticks. Note that
 *          this value includes a small amount of per-iteration setup so may
 *          be an overestimate, particularly for large pkt_len values.
 *   max_pkt_len: Number of bytes available at 'pkt', if the program modifies
 *          the packet bytes and makes it bigger.
 *   result: The return value of the last program iteration which ran.
 *   pkt: Arbitrary packet bytes to use as input to the program. The meaning
 *        of these bytes depends on the program type which is being tested;
 *        for XDP it is a raw Ethernet frame. The program may be written to
 *        alter these bytes. In that case, the resultant value from the last
 *        iteration of the test will be written here upon return. The result
 *        from all other iterations is discarded.
 *
 * The fd 'prog' must be a valid, loaded BPF program, from oo_bpf_prog_load()
 *
 * Returns 0 on success. On error, -1 is returned and errno is set
 * appropriately. */
OOBPFIMPL_PUBLIC
int oo_bpf_prog_test_run(int prog, struct oo_bpf_prog_test_run_arg* arg);


/* Retrieves the list of existing attachments made within the current network
 * namespace. If there are more than attach_cnt attachments, only the first
 * attach_cnt are returned.
 *
 * The fd passed in can be any /dev/onload_bpf_prog fd.
 *
 * Returns the total number of attachments on success, which can be greater
 * than attach_cnt. On error, -1 is returned and errno is set appropriately. */
OOBPFIMPL_PUBLIC
int oo_bpf_prog_get_all(int fd, int attach_cnt,
                        struct oo_bpf_prog_attach_arg* attaches);


/* Retrieves information about a loaded program.
 *
 * Returns 0 on success. On error, -1 is returned and errno is set
 * appropriately. */
OOBPFIMPL_PUBLIC
int oo_bpf_prog_get_info(int fd, struct oo_bpf_prog_info* info);


/* ======================================================================== */
/*                                map ioctls                                */

/* Creates a new eBPF map object. 'drv' is a /dev/onload_bpf fd which has been
 * opened by the application. The newly-created map is represented by the fd
 * returned from this function.
 *
 * In some cases Onload may be able to use native kernel BPF support to
 * represent the map. If this is the case then the returned fd may be used
 * interchangeably with either kernel or Onload BPF facilities, or a mixture
 * of both. If this has not been possible then the map is a pure Onload map
 * and cannot be used with the kernel. To test for kernel compatibility, pass
 * the returned fd to a kernel call, such as bpf(BPF_MAP_LOOKUP_ELEM); a
 * compatible map will be able to return successfully, an Onload-only map
 * will fail with EINVAL.
 *
 * The most common reason for Onload-only maps is a kernel without native BPF
 * support, however it may also happen if requesting a map type which Onload
 * supports but the kernel cannot use. Applications should not try to
 * predict the map kind that this function might use - if the difference is
 * important then they should handle both possibilities. */
OOBPFIMPL_PUBLIC
int oo_bpf_map_create(int drv, const struct oo_bpf_map_create_arg* arg);


/* Retrieves information about a map. See oo_bpf_map_lookup_elem() for common
 * details of how map functions operate. */
OOBPFIMPL_PUBLIC
int oo_bpf_map_get_info(int drv, int fd, struct oo_bpf_map_info* info);


/* Look up the value of a key in a map. 'drv' is a /dev/onload_bpf fd which
 * has been opened by the application. 'map_fd' is the fd of the actual map to
 * be queried, which must be an Onload BFP map. This function operates
 * identically to the equivalent bpf(2) syscall request, however it works on
 * kernels without native BPF. */
OOBPFIMPL_PUBLIC
int oo_bpf_map_lookup_elem(int drv, int map_fd,
                           const void* key, void* value, uint64_t flags);


/* Create or change the value of a key in a map. See oo_bpf_map_lookup_elem()
 * for common details of how map functions operate. */
OOBPFIMPL_PUBLIC
int oo_bpf_map_update_elem(int drv, int map_fd,
                           const void* key, const void* value, uint64_t flags);


/* Remove a key in a map. See oo_bpf_map_lookup_elem() for common details of
 * how map functions operate. */
OOBPFIMPL_PUBLIC
int oo_bpf_map_delete_elem(int drv, int map_fd,
                           const void* key, uint64_t flags);


/* Retrieve the key which is 'after' the supplied key in a map. See
 * oo_bpf_map_lookup_elem() for common details of how map functions operate. */
OOBPFIMPL_PUBLIC
int oo_bpf_map_get_next_key(int drv, int map_fd,
                            const void* key, void* next_key, uint64_t flags);

/* -*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*- */
/*                             high-level API                              */

struct oo_bpf_elf;

/* Open a handle to an ELF file, loading and parsing its contents into
 * memory. This must be a BPF ELF file. Returns -1 and sets errno on
 * failure. Use oo_bpf_close_elf() to free the memory allocated by this
 * function.*/
OOBPFIMPL_PUBLIC
int oo_bpf_open_elf(const char* filename, struct oo_bpf_elf** elf_out);


/* Open a handle to an ELF file, where the contents of the file is provided
 * in a block of memory rather than a file. Otherwise this function is
 * identical to oo_bpf_open_elf(). */
OOBPFIMPL_PUBLIC
int oo_bpf_open_elf_memory(const char* image, size_t bytes,
                           struct oo_bpf_elf** elf_out);


/* Free memory allocated by oo_bpf_open_elf() / oo_bpf_open_elf_memory() */
OOBPFIMPL_PUBLIC
void oo_bpf_close_elf(struct oo_bpf_elf* elf);


/* Return value from oo_bpf_elf_get_maps */
struct oo_bpf_elf_map {
  const struct oo_bpf_map_info* info;  /* Memory is owned by the oo_bpf_elf */
  int fd;             /* fd allocated to represent this map in the kernel.
                       * Prior to oo_bpf_elf_load_prog() this may be -1 */
  const char* name;   /* Will be the same as the variable name in the BPF
                       * program's source code used to declare this map.
                       * Memory is owned by the oo_bpf_elf */
};

/* Retrieve the complete list of maps declared in the ELF file. 'maps' is a
 * caller-allocated array of size 'maps_cnt'. This function returns the total
 * number of maps declared in the file (which may be larger than 'maps_cnt',
 * in which case 'maps' is not the complete list). Setting 'maps_cnt' to 0 is
 * valid as a way to retrieve the number of maps. 'sizeof_elf_map' must be
 * sizeof(struct oo_bpf_elf_map); this parameter exists for ABI compatibility
 * reasons. Returns -1 and sets errno on failure. */
OOBPFIMPL_PUBLIC
ssize_t oo_bpf_elf_get_maps(const struct oo_bpf_elf* elf,
                            struct oo_bpf_elf_map* maps, size_t maps_cnt,
                            size_t sizeof_elf_map);


/* For the given ELF file, provide your own BPF map 'fd' in place of a
 * default-constructed one. The default behaviour of oo_bpf_elf_load_prog() is
 * to create whatever maps it needs (as described in the ELF file) prior to
 * actually loading the program. This function can be used to override that
 * behaviour and use a pre-created map instead. Any maps which have not been
 * provided by this function will still be created as normal by
 * oo_bpf_elf_load_prog() when it needs them.
 *
 * This function does not check compatibility of the map you provide with
 * what the program is expecting. A mismatch can cause the verifier to reject
 * the program at load time or for the program itself to misbehave. Use
 * oo_bpf_map_get_info() and oo_bpf_map_info_compatible() to check
 * compatibility yourself if necessary.
 *
 * This function duplicates the fd it is provided - the caller may immediately
 * close the fd it provided.
 *
 * 'drv' is an open fd to /dev/onload_bpf. 'name' must be one of the values
 * returned by oo_bpf_elf_get_maps(), indicating the map to be replaced. */
OOBPFIMPL_PUBLIC
int oo_bpf_elf_provide_map(int drv, struct oo_bpf_elf* elf, const char* name,
                           int fd);


/* Return value from oo_bpf_elf_get_progs */
struct oo_bpf_elf_prog {
  const char* section;   /* Memory is owned by the oo_bpf_elf */
};

/* Retrieve the complete list of programs declared in the ELF file. 'progs' is
 * a caller-allocated array of size 'progs_cnt'. 'sizeof_elf_prog' must be
 * sizeof(struct oo_bpf_elf_prog); this parameter exists for ABI compatibility
 * reasons. This function returns the total number of programs declared in the
 * file (which may be larger than 'progs_cnt', in which case 'progs' is not
 * the complete list). Setting 'progs_cnt' to 0 is valid as a way to retrieve
 * the number of programs. Returns -1 and sets errno on failure. Note that ELF
 * files containing more than one program are rare. */
OOBPFIMPL_PUBLIC
ssize_t oo_bpf_elf_get_progs(const struct oo_bpf_elf* elf,
                             struct oo_bpf_elf_prog* progs, size_t progs_cnt,
                             size_t sizeof_elf_prog);


enum bpf_prog_type;

/* Additional, optional parameters to oo_bpf_elf_load_prog() */
struct oo_bpf_elf_load_attrs {
  size_t struct_size;   /* Must be set to sizeof(oo_bpf_elf_load_attrs) */
  unsigned flags;       /* currently 0 */
  /* The next three members are logging settings passed directly to
   * oo_bpf_prog_load(), used to obtain messages from the verifier. */
  unsigned log_level;
  size_t log_size;
  char* log_buf;
};

/* Loads one of the programs from the ELF file in to the kernel, running the
 * BPF verifier on it in the process. Returns the fd of the loaded program on
 * success, or -1 and sets errno on failure. This returned value continues to
 * be owned by 'elf'; to make it outlive oo_bpf_close_elf(), use dup3().
 *
 * 'drv' is an open fd to /dev/onload_bpf. 'section' must be one of the values
 * returns by oo_bpf_elf_get_progs(), or may be NULL to load the first program
 * found in the ELF file (the ordering is unspecified if there is more than
 * one program). 'type' is passed to oo_bpf_prog_load() and must be
 * BPF_PROG_TYPE_XDP for current versions of Onload. 'attrs' is optional; if
 * it is not NULL then it includes additional parameters for the call to
 * oo_bpf_prog_load().
 *
 * The ELF file may contain descriptions of maps that the program needs. Those
 * that have not already been supplied by oo_bpf_elf_provide_map() will be
 * created automatically by this function. The resultant fds can be retrieved
 * by a call to oo_bpf_elf_get_maps() after this function returns. */
OOBPFIMPL_PUBLIC
int oo_bpf_elf_load_prog(int drv, struct oo_bpf_elf* elf, const char* section,
                         enum bpf_prog_type type,
                         struct oo_bpf_elf_load_attrs* attrs);


enum oo_bpf_attach_point;

/* Very high-level shorthand for open("/dev/onload_bpf"), oo_bpf_open_elf,
 * oo_bpf_elf_load_prog, oo_bpf_prog_attach, oo_bpf_close_elf, close. Returns
 * -1 and sets errno on failure.
 *
 * This function is mostly used by test code that has very simple
 * requirements. Anything more complex should call the underlying functions
 * manually. */
OOBPFIMPL_PUBLIC
int oo_bpf_elf_install(const char* filename, const char* section,
                       enum oo_bpf_attach_point attach_point,
                       struct oo_bpf_elf_load_attrs* attrs);


/* Very high-level shorthand for open("/dev/onload_bpf"), oo_bpf_prog_detach,
 * close. Returns -1 and sets errno on failure.
 *
 * This function exists for symmetry with oo_bpf_elf_install(), however its
 * implementation is trivial. */
OOBPFIMPL_PUBLIC
int oo_bpf_elf_uninstall(enum oo_bpf_attach_point attach_point);


/* Compares two maps for interchangability. Returns nonzero if 'a' and 'b' are
 * equivalent to each other, in the sense that a BPF program written to act on
 * one will behave as expected with the other. This generally means equality,
 * except for some flags. */
OOBPFIMPL_PUBLIC
int oo_bpf_map_info_compatible(const struct oo_bpf_map_info* a,
                               const struct oo_bpf_map_info* b);

#ifdef __cplusplus
}
#endif

#endif
