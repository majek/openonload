/*
** Copyright 2005-2018  Solarflare Communications Inc.
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

/* Cplane interface to be used from Onload */
#include <cplane/cplane.h>
#include <cplane/mmap.h>

#ifdef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_H__
#error "don't include ci/internal/transport_config_opt.h from binary-only code"
#endif


#ifndef __KERNEL__
/* Maps the shared memory regions that are used as the interface between the
 * control plane and its clients.  On failure, this function will clean up any
 * partially-initialised state. */
int
oo_cp_create(int fd, struct oo_cplane_handle* cp, enum cp_sync_mode mode)
{
  struct cp_mibs* mibs = cp->mib;
  int rc;
  void* mem;
  ci_uint32 op = mode;

  /* Check user-kernel interface version. */
  rc = cp_ioctl(fd, OO_IOC_CP_CHECK_VERSION, &oo_cplane_api_version);
  if( rc != 0 )
    return rc;

  /* Wait for the control plane server to start if necessary. */
  rc = cp_ioctl(fd, OO_IOC_CP_WAIT_FOR_SERVER, &op);
  if( rc != 0 )
    return rc;

  /* Find out the MIB size */
  rc = cp_ioctl(fd, OO_IOC_CP_MIB_SIZE, &cp->bytes);
  if( rc != 0 )
    return rc;

  ci_assert(cp->bytes);
  ci_assert_equal(cp->bytes & (CI_PAGE_SIZE - 1), 0);

  /* Mmap MIBs */
  mem = mmap(NULL, cp->bytes, PROT_READ , MAP_SHARED, fd,
             OO_MMAP_TYPE_CPLANE << OO_MMAP_TYPE_SHIFT);
  if( mem == MAP_FAILED ) {
    ci_log("ERROR: failed to mmap cplane MIBs: %s", strerror(errno));
    return -errno;
  }

  /* Build MIBs */
  mibs[1].dim = mibs[0].dim = mem;
  cp_init_mibs(mem, mibs);

  /* Mmap rw memory */
  mibs[1].fwd_rw = mibs[0].fwd_rw = mmap(
          NULL,
          CI_ROUND_UP((mibs[0].dim->fwd_mask + 1) * sizeof(mibs[0].fwd_rw[0]),
                      CI_PAGE_SIZE),
          PROT_READ | PROT_WRITE, MAP_SHARED, fd,
#ifdef CP_UNIT
          /* see server.c init_memory() */
          CI_ROUND_UP(cp->bytes, CI_PAGE_SIZE) +
#endif
          ((OO_MMAP_TYPE_CPLANE << OO_MMAP_TYPE_SHIFT) |
           (OO_MMAP_CPLANE_ID_FWD_RW << OO_MMAP_ID_SHIFT)));
  if( mibs[0].fwd_rw == MAP_FAILED ) {
    ci_log("ERROR: failed to mmap rw part of Control Plane memory: %s",
           strerror(errno));
    rc = -errno;
    munmap(mem, cp->bytes);
    return rc;
  }

  cp->fd = fd;

  return 0;
}

/* Tear down the mappings of the control plane.  Necessary only if
 * oo_cp_create() succeeded. */
void
oo_cp_destroy(struct oo_cplane_handle* cp)
{
  munmap(cp->mib->fwd_rw,
         CI_ROUND_UP((cp->mib->dim->fwd_mask + 1) * sizeof(cp->mib->fwd_rw[0]),
                     CI_PAGE_SIZE));
  munmap(cp->mib->dim, cp->bytes);
}
#endif

#if !defined(__KERNEL__)
static int
oo_op_route_resolve(struct oo_cplane_handle* cp, struct cp_fwd_key* key)
{
  int rc;

  rc = cp_ioctl(cp->fd, OO_IOC_CP_FWD_RESOLVE, key);
  /* Fixme: should we re-start in case of EAGAIN? */
  if( rc < 0 )
    return rc;
  return 0;
}
#endif

int __oo_cp_route_resolve(struct oo_cplane_handle* cp,
                          cicp_verinfo_t* verinfo,
                          struct cp_fwd_key* key,
                          int/*bool*/ ask_server,
                          struct cp_fwd_data* data)
{
  struct cp_mibs* mib = &cp->mib[0];
  cp_version_t ver, old_ver;
  cicp_mac_rowid_t id;
  struct cp_fwd_row* fwd;

 find_again:
  id = cp_fwd_find_match(mib, key);
  if( id == CICP_MAC_ROWID_BAD ||
      ~(fwd = cp_get_fwd_by_id(mib, id))->flags & CICP_FWD_FLAG_DATA_VALID ||
      ! cp_fwd_find_row_found_perfect_match(mib, id, key) ) {
    if( ! ask_server )
      return -ENOENT;
    oo_op_route_resolve(cp, key);
    ask_server = CI_FALSE;
    goto find_again;
  }

  ver = OO_ACCESS_ONCE(*cp_fwd_version(fwd));
  do {
    if( ~ fwd->flags & CICP_FWD_FLAG_DATA_VALID ||
        ! cp_fwd_key_match(fwd, key) )
        goto find_again;
    ci_rmb();
    *data = *cp_get_fwd_data_current(fwd);

    /* We can accidentally increase TTL for a wrong row  - we do not care */
    if( fwd->flags & CICP_FWD_FLAG_STALE )
      mib->fwd_rw[id].frc_used = ci_frc64_get();
    old_ver = ver;
    ci_rmb();
  } while( old_ver != (ver = OO_ACCESS_ONCE(*cp_fwd_version(fwd))) );

  verinfo->id = id;
  verinfo->version = ver;

  /* Cplane server will refresh ARP when it reads fwd_rw[id], but it may
   * happen after some time.  Ask for the ARP immediately. */
  if( ask_server && ! data->arp_valid )
    oo_cp_arp_resolve(cp, verinfo);
  return 0;
}

int
oo_cp_get_hwport_properties(struct oo_cplane_handle* cp, ci_hwport_id_t hwport,
                            ci_uint8* out_mib_flags,
                            ci_uint32* out_oo_vi_flags_mask,
                            ci_uint32* out_efhw_flags_extra,
                            ci_uint8* out_pio_len_shift,
                            ci_uint32* out_ctpio_start_offset)
{
  struct cp_mibs* mib;
  cp_version_t version;
  int rc;

  CP_VERLOCK_START(version, mib, cp)

  rc = 0;

  if( cicp_hwport_row_is_free(&mib->hwport[hwport]) ) {
    rc = -ENOENT;
    goto out;
  }

  if( out_mib_flags != NULL )
    *out_mib_flags = mib->hwport[hwport].flags;
  if( out_oo_vi_flags_mask != NULL )
    *out_oo_vi_flags_mask = mib->hwport[hwport].oo_vi_flags_mask;
  if( out_efhw_flags_extra != NULL )
    *out_efhw_flags_extra = mib->hwport[hwport].efhw_flags_extra;
  if( out_pio_len_shift != NULL )
    *out_pio_len_shift = mib->hwport[hwport].pio_len_shift;
  if( out_ctpio_start_offset != NULL )
    *out_ctpio_start_offset = mib->hwport[hwport].ctpio_start_offset;

 out:
  CP_VERLOCK_STOP(version, mib)
  return rc;
}
#ifdef __KERNEL__

/* Retrieves all hwports with a licence that allows Onload to run.  The return
 * value is a bitmap of licensed hwports. */
cicp_hwport_mask_t oo_cp_get_licensed_hwports(struct oo_cplane_handle* cp)
{
  struct cp_mibs* mib;
  cp_version_t version;
  cicp_hwport_mask_t licensed_hwports = 0;

  ci_assert(cp);

  CP_VERLOCK_START(version, mib, cp)

  licensed_hwports =
    cp_get_licensed_hwports(mib,
                            cp_hwport_make_mask(mib->dim->hwport_max) - 1,
                            CP_LLAP_ALL_ONLOAD_LICENCES);

  CP_VERLOCK_STOP(version, mib)

  return licensed_hwports;
}


int oo_cp_get_acceleratable_llap_count(struct oo_cplane_handle* cp)
{
  struct cp_mibs* mib;
  cp_version_t version;
  int llap_count = 0;

  ci_assert(cp);

  CP_VERLOCK_START(version, mib, cp)
  llap_count = cp_get_acceleratable_llap_count(mib);
  CP_VERLOCK_STOP(version, mib)

  return llap_count;
}


/* The current use-case for this function is the installation of scalable
 * filters on all interfaces.  Otherwise, iterating over ifindices is probably
 * the wrong approach. */
int oo_cp_get_acceleratable_ifindices(struct oo_cplane_handle* cp,
                                      ci_ifid_t* ifindices, int max_count)
{
  struct cp_mibs* mib;
  cp_version_t version;
  int llap_count = 0;

  ci_assert(cp);

  CP_VERLOCK_START(version, mib, cp)
  llap_count = cp_get_acceleratable_ifindices(mib, ifindices, max_count);
  CP_VERLOCK_STOP(version, mib)

  return llap_count;
}
#endif
