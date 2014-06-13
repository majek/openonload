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

/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  ds
**  \brief  Efab configuration database; holds intercept, netif, user options
**   \date  2005/11/18
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <onload/efabcfg.h>
#include <ci/internal/citp_opts.h>
#include <onload/debug.h>

#ifdef DO
#undef DO
#endif

#ifdef IGNORE
#undef IGNORE
#endif

#define DPRINTF ci_log

#define DO(_x) _x
#define IGNORE(_x)

/* #define DEBUG_INTERCEPT DO */
/* #define DEBUG_QUERY DO */
#define DEBUG_LOCK DO

#ifdef NDEBUG
#undef DEBUG_INTERCEPT
#undef DEBUG_LOCK
#undef DEBUG_QUERY
#endif

#ifndef DEBUG_INTERCEPT
#define DEBUG_INTERCEPT IGNORE
#endif
#ifndef DEBUG_LOCK
#define DEBUG_LOCK IGNORE
#endif
#ifndef DEBUG_QUERY
#define DEBUG_QUERY IGNORE
#endif


typedef struct {
  ci_lock_t            lock;    /* rw lock that protects this struct */
  ci_atomic_t          readers; /* number of readers */
#define CI_CFG_READERS_MAX 100  /* max concurent readers */
  int                  writing; /* true, if someone is writing */

  ci_cfg_hdr_t        *hdr;   /*< config database header and start of blob, if
                                this pointer isn't set then the database isn't
                                installed yet */
  ci_cfg_str_part_t   *str;   /*< pointer to strings partition */
  ci_cfg_excl_part_t  *excl;  /*< pointer to exclusions partition */
  ci_cfg_patch_part_t *patch; /*< pointer to patches partition */
  ci_cfg_user_part_t  *user;  /*< pointer to users partition */
  ci_cfg_app_part_t   *app;   /*< pointer to apps partition */
} ci_cfg_handle_t;


/*! hdr pointer doubles up as an "in_use" flag */
#define ci_cfg_handle_is_in_use(handle) ((int)((handle)->hdr))


/*! Config database handle */
static ci_cfg_handle_t ci_cfg_handle;
static int /*bool*/ ci_cfg_handle_open = 0;


ci_inline int ci_cfg_readers(void)
{
  return ci_atomic_read(&ci_cfg_handle.readers);
}


extern int ci_cfg_drv_ctor(void)
{
  /* initialise the efabcfg kernel handle */
  memset(&ci_cfg_handle, 0, sizeof(ci_cfg_handle));

  /* construct the efabcfg lock */
  ci_lock_ctor(&ci_cfg_handle.lock);

  ci_cfg_handle_open = 1;

  return 0;
}


extern void ci_cfg_drv_dtor(void)
{
  if (ci_cfg_handle_open)
  {   ci_lock_dtor(&ci_cfg_handle.lock);
      if (ci_cfg_handle.hdr) {
	ci_cfg_free(ci_cfg_handle.hdr);
	ci_cfg_handle.hdr = NULL;
      }
      ci_cfg_handle_open = 0;
  }
}


extern int ci_cfg_rd_trylock(void)
{
  int rc = 0;
  if (!ci_cfg_handle_open)
  {   ci_log("config: attempt to access configuration "
	     "before initialization");
      rc = -ENXIO; /* "no such device or address"? */
  } else 
  {   int readers;
      ci_lock_lock(&ci_cfg_handle.lock);
      if (CI_UNLIKELY(ci_cfg_handle.writing == 1))
      {   DEBUG_LOCK(DPRINTF("config: read denied during a write"););
	  rc = -EAGAIN;
      } else if (CI_UNLIKELY((readers=ci_cfg_readers()) >= CI_CFG_READERS_MAX))
      {   DEBUG_LOCK(DPRINTF("config: read denied because we "
			     "already have %d readers (>= %d)",
			     readers, CI_CFG_READERS_MAX););
	  rc = -EAGAIN;
      } else
	  ci_atomic_inc(&ci_cfg_handle.readers);
      ci_lock_unlock(&ci_cfg_handle.lock);
  }
  return rc;
}


extern void ci_cfg_rd_unlock(void)
{
  ci_lock_lock(&ci_cfg_handle.lock);
  ci_assert_equal(ci_cfg_handle.writing, 0);
  ci_assert_le(ci_cfg_readers(), CI_CFG_READERS_MAX);
  ci_assert_nequal(ci_cfg_readers(), 0);
  ci_atomic_dec(&ci_cfg_handle.readers);
  ci_lock_unlock(&ci_cfg_handle.lock);
}


static int ci_cfg_wr_trylock(void)
{
  int rc = 0;
  if (!ci_cfg_handle_open)
      rc = -ENXIO; /* "no such device or address"? */
  else
  {   ci_lock_lock(&ci_cfg_handle.lock);
      if (ci_cfg_readers() != 0) {
        DEBUG_LOCK(DPRINTF("config: write denied during a read"););
	rc = -EAGAIN;
      } else if (ci_cfg_handle.writing != 0) {
        DEBUG_LOCK(DPRINTF("config: write denied during a write"););
	rc = -EAGAIN;
      } else {
	ci_cfg_handle.writing = 1;
      }
      ci_lock_unlock(&ci_cfg_handle.lock);
  }
  return rc;
}


extern void ci_cfg_wr_unlock(void)
{
  ci_lock_lock(&ci_cfg_handle.lock);
  ci_assert_equal(ci_cfg_readers(), 0);
  ci_assert_equal(ci_cfg_handle.writing, 1);
  ci_cfg_handle.writing = 0;
  ci_lock_unlock(&ci_cfg_handle.lock);
}


extern ci_cfg_hdr_t * ci_cfg_get(void)
{
  return ci_cfg_handle.hdr;
}


/*! Set the configuration database.
 *  \TODO: we need simultaneous access protection
 *  \TODO: if this function is not used outside this file - make it static
 */
extern int ci_cfg_set(ci_cfg_hdr_t *db, ci_uint32 len)
{
  void *old_db;
  
  /* check the database for consistency */
  if (!ci_cfg_is_valid(db, len)) {
    ci_log("%s: database didn't pass the consistency checks!", __FUNCTION__);
    return -EINVAL;
  }

  /* if a database is already installed, then we must keep a record of the old
   * one so that we can free it
   */
  old_db = (void*) ci_cfg_handle.hdr;
  
  /* install the database */
  ci_cfg_handle.hdr = db;
  ci_cfg_handle.str = ci_cfg_str_part(db);
  ci_cfg_handle.excl = ci_cfg_excl_part(db);
  ci_cfg_handle.patch = ci_cfg_patch_part(db);
  ci_cfg_handle.user = ci_cfg_user_part(db);
  ci_cfg_handle.app = ci_cfg_app_part(db);

  /* free the old database, if one existed */
  if (old_db) ci_cfg_free(old_db);
  
  OO_DEBUG_VERB(ci_log("Installed efabcfg database."));
  return 0;
}


/*! Delete the configuration database.
 */
extern int ci_cfg_unset(void)
{
  void *old_db = (void*) ci_cfg_handle.hdr;
  
  /* install the database */
  ci_cfg_handle.hdr = NULL;
  ci_cfg_handle.str = NULL;
  ci_cfg_handle.excl = NULL;
  ci_cfg_handle.patch = NULL;
  ci_cfg_handle.user = NULL;
  ci_cfg_handle.app = NULL;

  /* free the old database, if one existed */
  if (NULL != old_db) ci_cfg_free(old_db);
  
  OO_DEBUG_VERB(ci_log("Uninstalled efabcfg database."));
  return 0;
}


/*! query the efabcfg database
 *  The return value of this function should be copied in
 *  ci_cfg_ioctl_desc_t.err
 *  \TODO: if this function is not used outside this file - make it static
 */
extern ci_cfg_ioctl_desc_err_t
ci_cfg_database_query(ci_uint8 *buf[CICFG_BLOB_ID_COUNT],
                      size_t bufsize[CICFG_BLOB_ID_COUNT],
                      ci_cfg_uid_t *uid,
                      const char *proc_name)
{
  /* if there is no database installed, return an error */
  if (!ci_cfg_handle.hdr) {
    DEBUG_QUERY(DPRINTF("config: no configuration to read"););
    return CICFG_DESC_ENOTINST;
  }
  /* check whether excluded */
  if (ci_cfg_app_excluded(proc_name, ci_cfg_handle.hdr)) {
    DEBUG_INTERCEPT(DPRINTF("config: acceleration of '%s' and uid %u excluded",
			    proc_name, (unsigned)*uid););
    return CICFG_DESC_EPROCEXCL;
  } else {
    DEBUG_INTERCEPT(DPRINTF("config: acceleration of '%s' and uid %u not "
			    "excluded",
			    proc_name, (unsigned)*uid););
    /* apply the patches */
    ci_cfg_apply_patches(buf, bufsize, *uid, proc_name, ci_cfg_handle.hdr);

    return 0;
  }
}


/* Common IOCTL handlers for both linux and windows */

int ci_cfg_handle_set_ioctl(struct ci_private_s *unused, void *arg)
{
  ci_cfg_ioctl_desc_t *pdesc = arg;
  void *blob;

  if (!ci_cfg_is_sysadmin()) {
    ci_log("You have no permission to install a database!");
    pdesc->err = CICFG_DESC_EPERM;
    return 0;
  }
  
  /* allocate a large enough memory block to hold the database */
  blob = ci_cfg_malloc(pdesc->len);
  if (blob == 0) {
    pdesc->err = CICFG_DESC_ENOMEM;
    return 0;
  }

  /* copy the blob from user space to the kernel space */
  if (copy_from_user(blob, CI_USER_PTR_GET(pdesc->ptr), pdesc->len)) {
    pdesc->err = CICFG_DESC_EFAULT;
    goto free;
  }

  if (ci_cfg_wr_trylock() != 0) {
    pdesc->err = CICFG_DESC_EAGAIN;
    goto free;
  }

  /* we got the lock; validate and install the database */
  if (ci_cfg_set(blob, pdesc->len)) {
    pdesc->err = CICFG_DESC_EINVAL;
  }

  ci_cfg_wr_unlock();
  return 0;

free:
  ci_cfg_free(blob);
  return 0;
}


int ci_cfg_handle_unset_ioctl(struct ci_private_s *unused, void *arg)
{
  ci_cfg_ioctl_desc_t *pdesc = arg;
  pdesc->err = 0;
  
  if (!ci_cfg_is_sysadmin()) {
    ci_log("You have no permission to install a database!");
    pdesc->err = CICFG_DESC_EPERM;
  } else
  
  if (ci_cfg_wr_trylock() != 0) {
    pdesc->err = CICFG_DESC_EAGAIN;
  } else
  {   /* we got the lock; uninstall the database */
      if (0 != ci_cfg_unset()) {
	pdesc->err = CICFG_DESC_EINVAL;
      }

      ci_cfg_wr_unlock();
  }
  return 0;
}


int ci_cfg_handle_query_ioctl(struct ci_private_s *unused, void *arg)
{
  ci_cfg_ioctl_desc_t *pdesc = arg;
  ci_ioctl_cfg_query_t *q = NULL;
  ci_cfg_uid_t uid;
  char *proc_name = 0;
  char *proc_name_p;

  if ((q = ci_alloc(sizeof(*q))) == NULL) {
    pdesc->err = CICFG_DESC_ENOMEM;
    goto end;
  }

  /* copy the uid, process name and the data structures from user space */
  if (copy_from_user(q, CI_USER_PTR_GET(pdesc->ptr), sizeof(*q))) {
    pdesc->err = CICFG_DESC_EFAULT;
    goto end;
  }
  
  /* check that the data struct area is big enough */
  {
    unsigned data_area;
    data_area = pdesc->len - CI_MEMBER_OFFSET(ci_ioctl_cfg_query_t, opts);
    if (CI_UNLIKELY(sizeof(ci_cfg_opts_t) > data_area)) {
      /* FYI: common cause - bad userlib/driver version match */
      DEBUG_QUERY(
	  ci_log("config: query given %u-%u bytes but %u needed, query is %ub",
		 pdesc->len,
		 (unsigned)CI_MEMBER_OFFSET(ci_ioctl_cfg_query_t, opts),
		 (unsigned)sizeof(ci_cfg_opts_t),
		 (unsigned)sizeof(ci_ioctl_cfg_query_t));
      );
      pdesc->err = CICFG_DESC_ETOOSMALL;
      goto end;
    }
  }
  
  /* get the user name, if we haven't been provided with a user name then
   * retrieve one from the current context
   */
  if (CI_USER_PTR_GET(q->uid_n_proc.uid_ptr)) {
    void *puid = CI_USER_PTR_GET(q->uid_n_proc.uid_ptr);
    if (q->uid_n_proc.uid_len != sizeof(uid)) {
      pdesc->err = CICFG_DESC_EBADUID;
      goto end;
    }
    if (copy_from_user(&uid, puid, sizeof(uid))) {
      pdesc->err = CICFG_DESC_EFAULT;
      goto end;
    }
  } else {
    uid = ci_cfg_uid_get();
  }

  /* get the process name, if we haven't been provided with a process name
   * then retrieve one from the current context
   */
  if (CI_USER_PTR_GET(q->uid_n_proc.proc_name_ptr)) {
    void *pname = CI_USER_PTR_GET(q->uid_n_proc.proc_name_ptr);
    proc_name = ci_alloc(q->uid_n_proc.proc_name_len+1);
    if (proc_name == 0) goto end;
    proc_name_p = proc_name;
    if (copy_from_user(proc_name, pname, q->uid_n_proc.proc_name_len)) {
      pdesc->err = CICFG_DESC_EFAULT;
      goto end_free_proc_name;
    }
    proc_name[q->uid_n_proc.proc_name_len] = 0;
  } else {
    proc_name = (char *) ci_cfg_proc_name_get(&proc_name_p);
    if( proc_name == NULL )
      goto end;
  }

  //CI_TRACE_INT(uid);
  //CI_TRACE(proc_name, "%s");

  /* query the database and return the result */
  {
    ci_uint8 *buf[CICFG_BLOB_ID_COUNT];
    size_t bufsize[CICFG_BLOB_ID_COUNT];

    memset(buf, 0, sizeof(buf)); /* initialize unknown to NULL */
    buf[CICFG_BLOB_ID_OS] = (ci_uint8*) &q->opts.citp_opts;
    buf[CICFG_BLOB_ID_NETIF] = (ci_uint8*) &q->opts.netif_opts;
    buf[CICFG_BLOB_ID_USER] = (ci_uint8*) &q->opts.user_opts;

    memset(bufsize, 0, sizeof(bufsize)); /* initialize unknown to 0 */
    bufsize[CICFG_BLOB_ID_OS] = sizeof(q->opts.citp_opts);
    bufsize[CICFG_BLOB_ID_NETIF] = sizeof(q->opts.netif_opts);
    bufsize[CICFG_BLOB_ID_USER] = sizeof(q->opts.user_opts);

    if (CI_LIKELY(ci_cfg_rd_trylock() == 0)) {
      pdesc->err = ci_cfg_database_query(buf, bufsize, &uid, proc_name);
      ci_cfg_rd_unlock();
    } else {
      pdesc->err = CICFG_DESC_EAGAIN;
    }
        
    if (pdesc->err == 0) {
      if (copy_to_user(CI_USER_PTR_GET(pdesc->ptr), q, sizeof(*q))) {
        pdesc->err = CICFG_DESC_EFAULT;
        goto end_free_proc_name;
      }
    }
  }

 end_free_proc_name:
  ci_assert(proc_name_p);
  ci_free(proc_name_p);
 end:
  if (q != NULL)
    ci_free(q);
  return 0;
}


int ci_cfg_handle_get_ioctl(struct ci_private_s *unused, void *arg)
{
  ci_cfg_ioctl_desc_t *pdesc = arg;
  ci_cfg_hdr_t *hdr;

  if (CI_UNLIKELY(ci_cfg_rd_trylock() != 0)) {
    pdesc->err = CICFG_DESC_EAGAIN;
  } else {

    /* validate and install the database */
    hdr = ci_cfg_get();
    if (hdr == 0) {
      DEBUG_QUERY(ci_log("config: configuration database not installed "
			 "or invalid"););
      pdesc->err = CICFG_DESC_ENOTINST;
    } else

    /* check that the user's buffer is big enough */
    if (pdesc->len < hdr->len) {
      DEBUG_QUERY(
	  ci_log("config: configuration area is %ub but we need to write %ub "
		 "into it",
		 pdesc->len, hdr->len);
      );
      pdesc->err = CICFG_DESC_ETOOSMALL;
    } else

    /* copy the blob to the user buffer */
    if (copy_to_user(CI_USER_PTR_GET(pdesc->ptr), hdr, hdr->len)) {
      pdesc->err = CICFG_DESC_EFAULT;
    }

    ci_cfg_rd_unlock();
  }
  return 0;
}

