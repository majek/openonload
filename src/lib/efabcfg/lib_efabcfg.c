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

/*****************************************************************************
 *                                                                           *
 *          Headers                                                          *
 *          =======							     *
 *                                                                           *
 *****************************************************************************/

/* warning: */
/*#include <stdlib.h>*/ /* don't include in linux - name clashes */
/*#include <wchar.h>*/ /* don't include this on windows - off_t duplication */

#include <ci/internal/efabcfg.h> /* also sets USE_TOMBLOWER */

#ifndef __KERNEL__
#include <stdio.h>
#endif

#ifdef USE_TOMBLOWER
#include <stdlib.h>
#include <wctype.h>
#endif

/*****************************************************************************
 *                                                                           *
 *          Configuration                                                    *
 *          =============						     *
 *                                                                           *
 *****************************************************************************/


#define EXCLUDE_CASE_INSENSITIVE 

#ifdef USE_TOMBLOWER

#define HAS_WCRTOMB 0  /* wcrtomb in windows hdrs but not in library */

#ifdef MAX_PATH
#define PAT_PATH_MAXBYTES MAX_PATH
#else
#define PAT_PATH_MAXBYTES 256
#endif

#else

#undef EXCLUDE_CASE_INSENSITIVE

#endif /* USE_TOMBLOWER */

/*****************************************************************************
 *                                                                           *
 *          Debugging                                                        *
 *          =========							     *
 *                                                                           *
 *****************************************************************************/

#ifdef IGNORE
#undef IGNORE
#endif

#ifdef DO
#undef DO
#endif

#define DO(x) do { x; } while(0)
#define IGNORE(x)

/* #define DEBUGMATCH DO */
/* #define DEBUGEXCLUSION DO */

#ifndef DEBUGMATCH
#define DEBUGMATCH IGNORE
#endif

#ifndef DEBUGEXCLUSION
#define DEBUGEXCLUSION IGNORE
#endif

/* #define CICFG_VERB DO */
/* #define CI_CFG_CHKDEBUG_ABORT */

#ifndef CICFG_VERB
#define CICFG_VERB IGNORE
#endif

#define CI_CFG_PRINT(counter, cmd)                  \
  do {                                              \
    int rc = cmd;                                   \
    if (rc < 0) {                                   \
      ci_log("%s:%d:%s] ERROR! rc=%d",              \
             __FILE__, __LINE__, __FUNCTION__, rc); \
      return rc;                                    \
    }                                               \
    (counter) += rc;                                \
  } while(0)


#define CI_CFG_DEBUG(x) do { x; ci_assert(0); } while(0)

#ifdef CI_CFG_CHKDEBUG_ABORT
#define CI_CFG_CHKDEBUG(x) CI_CFG_DEBUG(x)
#else
#define CI_CFG_CHKDEBUG(x) do { x; } while(0)
#endif

#define NEWLINE(bytes, buf, len) do {                                      \
  CI_CFG_PRINT((bytes), snprintf((buf) + (bytes), (len) - (bytes), "\n")); \
} while(0)


/*****************************************************************************
 *                                                                           *
 *          Lower-case multibyte string                                      *
 *          ===========================					     *
 *                                                                           *
 *****************************************************************************/

#ifdef USE_TOMBLOWER

/*! write the lower-cased version of the given multi-byte string
 *
 * The output buffer must be sufficient for both the translated lower-case
 * version of the string plus MB_LEN_MAX+1 bytes
 */
extern int /* len/-rc */
tomblower(char *outbuf, size_t outlen, const char *buf)
{   size_t len = strlen(buf); /* no. of octets, not characters */
    int rc = 0;
#if HAS_WCRTOMB
    mbstate_t mbstate; /* write multi-byte counting state */
    (void)wcrtomb(NULL, L'\0', &mbstate); /* reset write state */
#else
    (void)wctomb(NULL, L'\0'); /* reset write state */
#endif
    (void)mbtowc(NULL, NULL, 0); /* reset read mb counting state */

    while (len > 0 && rc == 0 && outlen > MB_LEN_MAX+1)
    {   wchar_t wc = 0;

	int mbchrs = mbtowc(&wc, buf, len); /* get next wide char */
	
	if (mbchrs > 0)
	{   
#if HAS_WCRTOMB
	    int olen = wcrtomb(outbuf, towlower(wc), &mbstate); 
#else
            int olen = wctomb(outbuf, towlower(wc)); 
#endif

	    if (olen >= 0)
	    {   outbuf += olen;
		outlen -= olen;
	    } else
		rc = EINVAL;
	    
	    buf += mbchrs;
	    len -= mbchrs;
	} else if (mbchrs == 0)
	{   /* couldn't convert it - just copy the byte */
	    *outbuf++ = *buf++;
	    len--;
	    outlen--;
	} else
	    rc = EINVAL;
    }
    if (len > 0)
	rc = ENOMEM;
    else
        *outbuf = '\0';
    
    return rc == 0? -rc: len;
}

#endif /* USE_TOMBLOWER */


/*****************************************************************************
 *                                                                           *
 *          Main code                                                        *
 *          =========							     *
 *                                                                           *
 *****************************************************************************/

static int ci_cfg_hex_dump = 0;


/*--------------------------------------------------------------------
 * DATABASE DATA OBJECT (BLOB)
 *--------------------------------------------------------------------*/


static ci_uintptr_t _ci_cfg_part_end(const ci_cfg_hdr_t *hdr,
                                     unsigned part_type)
{
  ci_assert_gt(CICFG_PARTS_COUNT, 2);
  if (part_type >= CICFG_PARTS_COUNT - 1) {
    return (ci_uintptr_t) ((ci_uint8*)hdr + hdr->len);
  } else {
    return (ci_uintptr_t) ((ci_uint8*)hdr + hdr->part_off[part_type+1] - 1);
  }
}


static unsigned _ci_cfg_part_len(const ci_cfg_hdr_t *hdr, unsigned part_type)
{
  ci_assert_ge(_ci_cfg_part_end(hdr, part_type),
               _ci_cfg_part(ci_uintptr_t, hdr, part_type));
  return (unsigned) (_ci_cfg_part_end(hdr, part_type) -
                     _ci_cfg_part(ci_uintptr_t, hdr, part_type) + 1);
}


ci_inline size_t
ci_cfg_blob_id_sizeof(ci_cfg_blob_id_t blob_id, size_t *bufsize, size_t sizes)
{
  if (blob_id >= sizes)
      /* we haven't specified the size of this blob so we can't check it */
      return 0;
  else
      /* if this is 0 it means we don't know the size of this blob */
      return bufsize[blob_id];
}




static int ci_cfg_blob_off_is_valid(const ci_cfg_hdr_t *hdr,
				    size_t *bufsize, size_t sizes,
				    ci_cfg_blob_id_t blob_id,
				    ci_uint32 blob_off)
{
  size_t bloblen = ci_cfg_blob_id_sizeof(blob_id, bufsize, sizes);
  if (bloblen > 0 && blob_off >= bloblen) {
    CI_CFG_CHKDEBUG(ci_log("%s: invalid blob_off off=%u blob_id=%u blob_sz=%lu",
                           __FUNCTION__, blob_off, blob_id,
                           (unsigned long)bloblen));
    return 0;
  }

  return 1;
}


static int ci_cfg_ver_is_valid(ci_uint32 ver)
{
  if (((ver & CICFG_VER_MAJOR_MASK) == CICFG_VER_MAJOR) &&
      ((ver & CICFG_VER_MINOR_MASK) >= CICFG_VER_MINOR)) {
    return 1;
  } else {
    CI_CFG_CHKDEBUG(ci_log("%s: version mismatch, file=0x%08X driver=0x%08X",
                    __FUNCTION__, ver, CICFG_VER_NUM));
    return 0;
  }
}



/*--------------------------------------------------------------------
 * STRINGS
 *--------------------------------------------------------------------*/


static int ci_cfg_str_part_is_valid(ci_cfg_hdr_t *cfg_hdr,
                                    ci_cfg_str_part_t *part,
                                    unsigned len)
{
  unsigned datalen = len - CI_MEMBER_OFFSET(ci_cfg_str_part_t, data);

  /* check that we have enough space for a header */
  if (CI_UNLIKELY(len < sizeof(ci_cfg_str_hdr_t))) {
    CI_CFG_CHKDEBUG(ci_log("%s: not enough space in string header",
			   __FUNCTION__));
    return 0;
  }

  /* check that we have enough space for "str_hdr->strings" empty strings */
  if (CI_UNLIKELY(part->hdr.strings > datalen)) {
    CI_CFG_CHKDEBUG(ci_log("%s: not enough space %d for strings",
			   __FUNCTION__, part->hdr.strings));
    return 0;
  }

  /* check that the last byte of the section is zero */
  if (CI_UNLIKELY( ((char*)&part->hdr) [len-1] )) {
    CI_CFG_CHKDEBUG(ci_log("%s: last byte isn't zero", __FUNCTION__));
    return 0;
  }

  return 1;
}


static int ci_cfg_str_off_is_valid(ci_cfg_hdr_t *cfg_hdr,
                                   ci_cfg_str_off_t offset)
{
  unsigned part_len = _ci_cfg_part_len(cfg_hdr, CICFG_PART_STR);
  /* the offset must point to the region after the strings header and before the
   * end of the partition
   */
  if (offset >= part_len - sizeof(ci_cfg_str_hdr_t)) {
    CI_CFG_CHKDEBUG(ci_log("%s: string offset %d out of range",
			   __FUNCTION__, offset));
    return 0;
  }

  return 1;
}


static size_t ci_cfg_pprint_str(char *buf, size_t len,
                                const ci_cfg_hdr_t *hdr,
                                ci_cfg_str_off_t off)
{
  return snprintf(buf, len, "%s", ci_cfg_string(hdr, off));
}


static size_t ci_cfg_pprint_str_part(char *buf, size_t len,
                                     const ci_cfg_hdr_t *hdr)
{
  int rc;
  unsigned i;
  size_t bytes=0, offset=0;
  const char * const separator = "\n";
  ci_cfg_str_part_t *part = ci_cfg_str_part(hdr);
  
  for (i=0; i < part->hdr.strings; i++) {
    rc = snprintf(buf + bytes, len - bytes, "%s", &part->data[offset]);
    if (rc < 0) return rc;
    bytes += rc;
    offset += rc + 1; /* skip over the trailing zero */
    rc = snprintf(buf + bytes, len - bytes, "%s", separator);
    if (rc < 0) return rc;
    bytes += rc;
  }

  return bytes;
}



/*--------------------------------------------------------------------
 * EXCLUSIONS
 *--------------------------------------------------------------------*/


static int ci_cfg_excl_part_is_valid(ci_cfg_hdr_t *cfg_hdr,
                                     ci_cfg_excl_part_t *part,
                                     unsigned len)
{
  unsigned datalen = len - CI_MEMBER_OFFSET(ci_cfg_excl_part_t, exclude);
  int i;

  /* check that we have enough space for a header */
  if (CI_UNLIKELY(len < sizeof(ci_cfg_excl_hdr_t))) {
    CI_CFG_CHKDEBUG(ci_log("%s: not enough space for exclusions header",
			   __FUNCTION__));
    return 0;
  }

  /* check that we have enough space for the array of exclusions */
  if (CI_UNLIKELY(part->hdr.rows > datalen / sizeof(ci_cfg_excl_t))) {
    CI_CFG_CHKDEBUG(ci_log("%s: not enough space for exclusions, "
                        "rows=%u datalen=%u part_len=%u",
                        __FUNCTION__, part->hdr.rows, datalen, len));
    return 0;
  }

  /* check the string ids for validity */
  for (i=0; i < part->hdr.rows; i++) {
    if (!ci_cfg_str_off_is_valid(cfg_hdr, part->exclude[i].str_off)) {
      CI_CFG_CHKDEBUG(ci_log("%s: exclusion %d - string id is invalid",
			     __FUNCTION__, i));
      return 0;
    }
  }

  return 1;
}


static size_t ci_cfg_pprint_excl(char *buf, size_t len,
                                 const ci_cfg_hdr_t *hdr,
                                 const ci_cfg_excl_t *excl)
{
  return ci_cfg_pprint_str(buf, len, hdr, excl->str_off);
}


static size_t ci_cfg_pprint_excl_part(char *buf, size_t len,
                                      const ci_cfg_hdr_t *hdr)
{
  unsigned i;
  size_t bytes=0;
  const char * const separator = "\n";
  ci_cfg_excl_part_t *part = ci_cfg_excl_part(hdr);
  const ci_cfg_excl_t *excl = &part->exclude[0];
  
  for (i=0; i < part->hdr.rows; i++, excl++) {
    CI_CFG_PRINT(bytes, ci_cfg_pprint_excl(buf + bytes, len - bytes,
                                           hdr, excl));
    CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "%s", separator));
  }

  return bytes;
}



/*--------------------------------------------------------------------
 * PATCHES
 *--------------------------------------------------------------------*/


static int ci_cfg_patch_item_is_valid(ci_cfg_hdr_t *cfg_hdr,
                                      size_t *bufsize, size_t sizes,
				      ci_cfg_patch_item_t *item)
{
  /* check that the mask isn't zero */
  if (CI_UNLIKELY(item->mask == 0)) {
    CI_CFG_CHKDEBUG(ci_log("%s: patch item mask is zero", __FUNCTION__));
    return 0;
  }

  /* check the blob_id */
  if (!ci_cfg_blob_id_is_valid(item->blob_id)) {
    CI_CFG_CHKDEBUG(ci_log("%s: patch item blob id %d is invalid",
			   __FUNCTION__, item->blob_id));
    return 0;
  }

  /* check the blob offset */
  if (!ci_cfg_blob_off_is_valid(cfg_hdr, bufsize, sizes,
				item->blob_id, item->blob_off)) {
    CI_CFG_CHKDEBUG(ci_log("%s: patch item offset %d is invalid "
			   "(for blob id %d)",
			   __FUNCTION__, item->blob_off, item->blob_id));
    return 0;
  }

  return 1;
}


static int ci_cfg_patch_part_is_valid(ci_cfg_hdr_t *cfg_hdr,
                                      size_t *bufsize, size_t sizes,
				      ci_cfg_patch_part_t *part,
                                      int len)
{
  unsigned datalen = len - CI_MEMBER_OFFSET(ci_cfg_patch_part_t, item);
  unsigned i;

  /* check that we have enough space for a header */
  if (CI_UNLIKELY(len < sizeof(ci_cfg_patch_hdr_t))) {
    CI_CFG_CHKDEBUG(ci_log("%s: not enough space for patch header",
			   __FUNCTION__));
    return 0;
  }

  /* check that we have enough space for the patch items */
  if (CI_UNLIKELY(part->hdr.rows > datalen / sizeof(ci_cfg_patch_item_t))) {
    CI_CFG_CHKDEBUG(ci_log("%s: not enough space for patch items, "
                        "rows=%u datalen=%u", __FUNCTION__,
                        part->hdr.rows, datalen));
    return 0;
  }

  /* check the patch items */
  for (i=0; i < part->hdr.rows; i++)
    if (!ci_cfg_patch_item_is_valid(cfg_hdr, bufsize, sizes, &part->item[i])) {
      CI_CFG_CHKDEBUG(ci_log("%s: invalid patch item %d/%d",
			     __FUNCTION__, i, part->hdr.rows));
      return 0;
    }

  return 1;
}


static int ci_cfg_patch_id_is_valid(ci_cfg_patch_part_t *part,
                                    ci_cfg_patch_id_t *id)
{
  /* special case: if length is zero ignore index */
  if (id->patch_length == 0)
    return 1;
  
  /* check the patch length */
  if (id->patch_length > part->hdr.rows) {
    CI_CFG_CHKDEBUG(ci_log("%s: invalid patch length %u",
                        __FUNCTION__, id->patch_length));
    return 0;
  }

  /* check the patch index */
  if (id->patch_index > part->hdr.rows) {
    CI_CFG_CHKDEBUG(ci_log("%s: invalid patch index", __FUNCTION__));
    return 0;
  }

  /* check that the last patch item doesn't fall outside the array */
  if (id->patch_index + id->patch_length - 1u > part->hdr.rows) {
    CI_CFG_CHKDEBUG(ci_log("%s: last patch item is out of range",
			   __FUNCTION__));
    return 0;
  }

  return 1;
}


static void ci_cfg_apply_patch_item(ci_uint8 *buf[CICFG_BLOB_ID_COUNT],
                                    size_t bufsize[CICFG_BLOB_ID_COUNT],
                                    const ci_cfg_patch_item_t *item)
{
  int blob_id = item->blob_id;
  if (CI_LIKELY(blob_id < CICFG_BLOB_ID_COUNT)) {
    ci_uint8 *blob = buf[blob_id];
    if (NULL != blob) {
      ci_uint16 blob_off = item->blob_off;
      if (blob_off < bufsize[blob_id]) {
	ci_uint8 mask = item->mask;
	ci_uint8 value = item->value;
	CICFG_VERB(ci_log("apply patch: blob_id=%d blob_off=%d val=0x%02X"
			   " mask=0x%02X", blob_id, blob_off, value, mask));
	blob[blob_off] = (value & mask) | (blob[blob_off] & ~mask);
      } else
	ci_log("%s: illegal offset in blob %u - %u is larger than %u(max)",
	       __FUNCTION__, blob_id, item->blob_off,
               (unsigned int)bufsize[blob_id]);
    }
  } else
    ci_log("%s: illegal blob_id, %u is larger than %u(max)",
           __FUNCTION__, item->blob_id, CICFG_BLOB_ID_MAX);
}


static void ci_cfg_apply_patch(ci_uint8 *buf[CICFG_BLOB_ID_COUNT],
                               size_t bufsize[CICFG_BLOB_ID_COUNT],
                               const ci_cfg_patch_part_t *part,
                               const ci_cfg_patch_id_t *id)
{
  const ci_cfg_patch_item_t *p;
  int i;

  ci_assert_nequal(id, NULL);
  ci_assert_nequal(part, NULL);
  
  if (id->patch_length == 0) return;
  
  p = &part->item[id->patch_index];
  for (i=0; i < id->patch_length; i++, p++) {
    ci_cfg_apply_patch_item(buf, bufsize, p);
  }
}


static size_t ci_cfg_pprint_patch_item(char *buf, size_t len,
                                       const ci_cfg_patch_item_t *item)
{
  return snprintf(buf, len, "blob_id=%s off=%u val=0x%02X mask=0x%02X",
                  ci_cfg_blob_id_2_str(item->blob_id),
                  item->blob_off, item->value, item->mask);
}


static size_t ci_cfg_pprint_patch_id (char *buf, size_t len,
                                      const ci_cfg_patch_id_t *id)
{
  return snprintf(buf, len, "idx=%u len=%u",
                  id->patch_index, id->patch_length);
}


static size_t ci_cfg_pprint_patch(char *buf, size_t len,
                                  const ci_cfg_patch_part_t *part,
                                  const ci_cfg_patch_id_t *id)
{
  unsigned i;
  size_t bytes=0;
  const char * const separator = "\n";
  const ci_cfg_patch_item_t *item = &part->item[id->patch_index];
  
  for (i=0; i < id->patch_length; i++, item++) {
    CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "%u: ", i));
    CI_CFG_PRINT(bytes, ci_cfg_pprint_patch_item(buf + bytes,
                                                 len - bytes, item));
    CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "%s", separator));
  }

  return bytes;
}


static size_t ci_cfg_pprint_patch_part(char *buf, size_t len,
                                       const ci_cfg_patch_part_t *part)
{
  ci_cfg_patch_id_t id = {0, (ci_uint16) part->hdr.rows};
  return ci_cfg_pprint_patch(buf, len, part, &id);
}



/*--------------------------------------------------------------------
 * PATTERNS
 *--------------------------------------------------------------------*/


static int ci_cfg_str_pattern_is_valid(ci_cfg_hdr_t *cfg_hdr,
                                       ci_cfg_str_pattern_t *pattern)
{
  /* check that the flags are set correctly */
  if (CI_UNLIKELY((pattern->match_type & ~CICFG_MATCH_MASK) != 0)) {
    CI_CFG_CHKDEBUG(ci_log("%s: bad pattern string flags - %x",
			      __FUNCTION__, pattern->match_type));
    return 0;
  }

  /* check that the string offset is valid */
  if (CI_UNLIKELY(!ci_cfg_str_off_is_valid(cfg_hdr, pattern->str_off))) {
    CI_CFG_CHKDEBUG(ci_log("%s: invalid pattern string offset %d",
			   __FUNCTION__, pattern->str_off));
    return 0;
  }

  return 1;
}


static size_t ci_cfg_pprint_str_pattern(char *buf, size_t len,
                                        const ci_cfg_hdr_t *hdr,
                                        const ci_cfg_str_pattern_t *pattern)
{
  return snprintf(buf, len, "%s%s%s",
                  (pattern->match_type & CICFG_MATCH_START) ? "^" : "*",
                  ci_cfg_string(hdr, pattern->str_off),
                  (pattern->match_type & CICFG_MATCH_END) ? "$" : "*");
}



/*--------------------------------------------------------------------
 * USERS
 *--------------------------------------------------------------------*/


static int ci_cfg_user_part_is_valid(ci_cfg_hdr_t *cfg_hdr,
                                     ci_cfg_user_part_t *part,
                                     int len)
{
  unsigned datalen = len - CI_MEMBER_OFFSET(ci_cfg_user_part_t, user);
  int i;

  if (ci_cfg_hex_dump) {
    ci_log("user part:");
    ci_hex_dump(ci_log_fn, part, len, 0);
  }

  /* check that we have enough space for a header */
  if (CI_UNLIKELY(len < sizeof(ci_cfg_user_hdr_t))) {
    CI_CFG_CHKDEBUG(ci_log("%s: not enough space for user header",
			   __FUNCTION__));
    return 0;
  }

  /* check that we have enough space for the user entries */
  if (CI_UNLIKELY(part->hdr.rows > datalen / sizeof(ci_cfg_user_t))) {
    CI_CFG_CHKDEBUG(ci_log("%s: not enough space for %d user entries",
			   __FUNCTION__, part->hdr.rows));
    return 0;
  }

  /* check the user entries */
  for (i=0; i < part->hdr.rows; i++) {
    /* check the user ids? */

    /* check the patch ids */
    if (!ci_cfg_patch_id_is_valid(ci_cfg_patch_part(cfg_hdr),
                                  &part->user[i].patch)) {
      CI_CFG_CHKDEBUG(ci_log("%s: user %d - invalid patch id",
			     __FUNCTION__, i));
      return 0;
    }
  }

  return 1;
}


static void ci_cfg_apply_user_patch(ci_uint8 *buf[CICFG_BLOB_ID_COUNT],
                                    size_t bufsize[CICFG_BLOB_ID_COUNT],
                                    ci_cfg_uid_t uid,
                                    const ci_cfg_hdr_t *hdr)
{
  const ci_cfg_user_part_t *part = ci_cfg_user_part(hdr);
  const ci_cfg_user_t *user;
  unsigned i;

  ci_assert_nequal(hdr, NULL);
  
  if (part->hdr.rows <= 0) return;

  user = &part->user[0];
  for (i=0; i < part->hdr.rows; i++, user++) {
    if (uid == user->uid) {
      ci_cfg_apply_patch(buf, bufsize, ci_cfg_patch_part(hdr), &user->patch);
      return;
    }
  }
}


static size_t ci_cfg_pprint_user(char *buf, size_t len,
                                 const ci_cfg_user_t *user)
{
  size_t bytes=0;
  CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes,
                               "uid=%u patch_id={", user->uid));
  CI_CFG_PRINT(bytes, ci_cfg_pprint_patch_id(buf + bytes, len - bytes,
                                             &user->patch));
  CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "}"));
  return bytes;
}


static size_t ci_cfg_pprint_user_part(char *buf, size_t len,
                                      const ci_cfg_hdr_t *hdr)
{
  unsigned i;
  size_t bytes=0;
  const char * const separator = "\n";
  const ci_cfg_user_part_t *part = ci_cfg_user_part(hdr);
  const ci_cfg_user_t *user = &part->user[0];


  if (ci_cfg_hex_dump) {
    ci_log("config: Hexdump of user partition:");
    ci_hex_dump(ci_log_fn, part, _ci_cfg_part_len(hdr, CICFG_PART_USERS), 0);
  }
  
  for (i=0; i < part->hdr.rows; i++, user++) {
    CI_CFG_PRINT(bytes, ci_cfg_pprint_user(buf + bytes, len - bytes, user));
    CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "%s", separator));
  }

  return bytes;
}



/*--------------------------------------------------------------------
 * APPS
 *--------------------------------------------------------------------*/


static int ci_cfg_app_part_is_valid(ci_cfg_hdr_t *cfg_hdr,
                                    ci_cfg_app_part_t *part,
                                    int len)
{
  unsigned datalen = len - CI_MEMBER_OFFSET(ci_cfg_app_part_t, app);
  ci_cfg_patch_part_t *patch_part;
  int i;

  /* check that we have enough space for a header */
  if (CI_UNLIKELY(len < sizeof(ci_cfg_app_hdr_t))) {
    CI_CFG_CHKDEBUG(ci_log("%s: not enough space for header", __FUNCTION__));
    return 0;
  }

  /* check that we have enough space for the app entries */
  if (CI_UNLIKELY(part->hdr.rows > datalen / sizeof(ci_cfg_app_t))) {
    CI_CFG_CHKDEBUG(ci_log("%s: not enough space for %d app entries",
			   __FUNCTION__, part->hdr.rows));
    return 0;
  }

  /* check the app entries */
  for (i=0; i < part->hdr.rows; i++) {
    /* check the patterns */
    if (!ci_cfg_str_pattern_is_valid(cfg_hdr, &part->app[i].pattern)) {
      CI_CFG_CHKDEBUG(ci_log("%s: app %d - invalid app pattern",
			     __FUNCTION__, i));
      return 0;
    }

    /* check the patch ids */
    patch_part = _ci_cfg_part(ci_cfg_patch_part_t*, cfg_hdr, CICFG_PART_PATCH);
    if (!ci_cfg_patch_id_is_valid(patch_part, &part->app[i].patch)) {
      CI_CFG_CHKDEBUG(ci_log("%s: app %d - invalid app patch id",
			     __FUNCTION__, i));
      return 0;
    }
  }

  return 1;
}


static void ci_cfg_apply_app_patch(ci_uint8 *buf[CICFG_BLOB_ID_COUNT],
                                   size_t bufsize[CICFG_BLOB_ID_COUNT],
                                   const char *proc_name,
                                   const ci_cfg_hdr_t *hdr)
{
  const ci_cfg_app_part_t *part = ci_cfg_app_part(hdr);
  const ci_cfg_app_t *app;
  const char *pattern;
  unsigned i;

  ci_assert_nequal(hdr, NULL);
  
  if (part->hdr.rows <= 0) return;

  app = &part->app[0];
  for (i=0; i < part->hdr.rows; i++, app++) {
    pattern = ci_cfg_string(hdr, app->pattern.str_off);
    if (ci_cfg_pattern_matches(pattern, proc_name, app->pattern.match_type)) {
      ci_cfg_apply_patch(buf, bufsize, ci_cfg_patch_part(hdr), &app->patch);
      return;
    }
  }
}


static size_t ci_cfg_pprint_app(char *buf, size_t len,
                                const ci_cfg_hdr_t *hdr,
                                const ci_cfg_app_t *app)
{
  size_t bytes=0;
  CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "app=\""));
  CI_CFG_PRINT(bytes, ci_cfg_pprint_str_pattern(buf + bytes, len - bytes,
                                                hdr, &app->pattern));
  CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "\" patch_id={"));
  CI_CFG_PRINT(bytes, ci_cfg_pprint_patch_id(buf + bytes, len - bytes,
                                             &app->patch));
  CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "}"));
  return bytes;
}


static size_t ci_cfg_pprint_app_part(char *buf, size_t len,
                                      const ci_cfg_hdr_t *hdr)
{
  unsigned i;
  size_t bytes=0;
  const char * const separator = "\n";
  const ci_cfg_app_part_t *part = ci_cfg_app_part(hdr);
  const ci_cfg_app_t *app = &part->app[0];
  
  if (ci_cfg_hex_dump)
    ci_hex_dump(ci_log_fn, part, _ci_cfg_part_len(hdr, CICFG_PART_APPS), 0);
  
  for (i=0; i < part->hdr.rows; i++, app++) {
    CI_CFG_PRINT(bytes, ci_cfg_pprint_app(buf + bytes, len - bytes, hdr, app));
    CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "%s", separator));
  }

  return bytes;
}



/*--------------------------------------------------------------------
 * OTHER
 *--------------------------------------------------------------------*/


extern int ci_cfg_is_valid_for(ci_cfg_hdr_t *hdr, ci_uint32 len,
			       size_t *bufsize, size_t sizes)
{
  int i;

  /* check the length field */
  if (hdr->len < sizeof(ci_cfg_hdr_t)     + sizeof(ci_cfg_excl_hdr_t)  +
                 sizeof(ci_cfg_str_hdr_t) + sizeof(ci_cfg_patch_hdr_t) +
                 sizeof(ci_cfg_app_hdr_t) + sizeof(ci_cfg_user_hdr_t))
    return 0;

  if (hdr->len != len) {
    ci_log("config: Database length doesn't match length given to "
	   "ioctl function db_len=%u len_arg=%u", hdr->len, len);
    return 0;
  }

  if (ci_cfg_hex_dump)
    ci_hex_dump(ci_log_fn, hdr, hdr->len, 0);

  /* check the version number */
  if (!ci_cfg_ver_is_valid(hdr->ver)) {
    ci_log("%s: version mismatch (file) 0x%x != 0x%x (driver)",
           __FUNCTION__, hdr->ver, CICFG_VER_NUM);
    return 0;
  }

  /* check that we have at least the expected number of rows */
  if (hdr->rows < CICFG_PARTS_COUNT) {
    ci_log("%s: expected %d parts but found only %d",
           __FUNCTION__, CICFG_PARTS_COUNT, hdr->rows);
    return 0;
  }

  /* no offset must lie outside the data block */
  for (i=0; i < CICFG_PARTS_COUNT; i++) {
    /*CI_TRACE_INT(hdr->part_off[i]);*/
    if (hdr->part_off[i] >= hdr->len)
      return 0;
  }

  /* exclusion partition follows the main database header */
  if (sizeof(ci_cfg_hdr_t) > hdr->part_off[CICFG_PART_EXCL])
    return 0;

  /* strings partition follows the exclusion partition */
  if (hdr->part_off[CICFG_PART_EXCL] >= hdr->part_off[CICFG_PART_STR])
    return 0;

  /* patches partition follows the strings partition */
  if (hdr->part_off[CICFG_PART_STR] >= hdr->part_off[CICFG_PART_PATCH])
    return 0;

  /* users partition follows the patches partition */
  if (hdr->part_off[CICFG_PART_PATCH] >= hdr->part_off[CICFG_PART_USERS])
    return 0;

  /* apps partition follows the users partition */
  if (hdr->part_off[CICFG_PART_USERS] >= hdr->part_off[CICFG_PART_APPS])
    return 0;

  /* check the exclusions partition */
  if (!ci_cfg_excl_part_is_valid(hdr, ci_cfg_excl_part(hdr),
                                 _ci_cfg_part_len(hdr, CICFG_PART_EXCL)))
    return 0;

   /* check the strings partition */
  if (!ci_cfg_str_part_is_valid(hdr, ci_cfg_str_part(hdr),
                                _ci_cfg_part_len(hdr, CICFG_PART_STR)))
    return 0;

  /* check the patches partition */
  if (!ci_cfg_patch_part_is_valid(hdr, bufsize, sizes,
				  ci_cfg_patch_part(hdr),
                                  _ci_cfg_part_len(hdr, CICFG_PART_PATCH)))
    return 0;

  /* check the default patch */
  if (!ci_cfg_patch_id_is_valid(ci_cfg_patch_part(hdr), &hdr->default_config))
    return 0;

  /* check the users partition */
  if (!ci_cfg_user_part_is_valid(hdr, ci_cfg_user_part(hdr),
                                 _ci_cfg_part_len(hdr, CICFG_PART_USERS)))
    return 0;

  /* check the apps partition */
  if (!ci_cfg_app_part_is_valid(hdr, ci_cfg_app_part(hdr),
                                _ci_cfg_part_len(hdr, CICFG_PART_APPS)))
    return 0;

   return 1;
}


/*! This function will apply the appropriate app and user patches to the
 *  data structures pointed by buf. buf elements are allowed to be zero.
 */
extern void ci_cfg_apply_patches(ci_uint8 *buf[CICFG_BLOB_ID_COUNT],
				 size_t bufsize[CICFG_BLOB_ID_COUNT],
                                 ci_cfg_uid_t uid,
                                 const char *proc_name,
                                 const ci_cfg_hdr_t *hdr)
{
  ci_assert_nequal(hdr, NULL);
  ci_assert_nequal(buf, NULL);
  
  /* apply the default patch */
  CICFG_VERB(ci_log("config: applying the default patch"));
  ci_cfg_apply_patch(buf, bufsize, ci_cfg_patch_part(hdr),
		     &hdr->default_config);
  
  /* apply the application patches */
  CICFG_VERB(ci_log("config: applying the application patches"));
  ci_cfg_apply_app_patch(buf, bufsize, proc_name, hdr);

  /* apply the user patches */
  CICFG_VERB(ci_log("config: applying the user patches"));
  ci_cfg_apply_user_patch(buf, bufsize, uid, hdr);
}


/*! Search the exclusion list for a match
 *
 *  Where EXCLUDE_CASE_INSENSITIVE is set we assume that the exclusions held
 *  in the database are all stored in lower case.
 */
extern int ci_cfg_app_excluded(const char *str, const ci_cfg_hdr_t *hdr)
{
#ifdef EXCLUDE_CASE_INSENSITIVE
  static char lower_str[PAT_PATH_MAXBYTES];

  if (tomblower(&lower_str[0], sizeof(lower_str), str) < 0)
  { ci_log("config: application name or too long - '%s'", str);
    return 0;
  } else {
    IGNORE(ci_log("config: lower '%s' is '%s'", str, &lower_str[0]););
    str = &lower_str[0];
  }
#endif
  
  {
    const ci_cfg_excl_part_t *part = ci_cfg_excl_part(hdr);
    int matches = 0;
    if (part->hdr.rows > 0) {
      unsigned i;
      const ci_cfg_excl_t *increc;

      increc = &part->exclude[0];
      for (i=0; !matches && i < part->hdr.rows; i++, increc++) {
	const char *appname = ci_cfg_string(hdr, increc->str_off);
	DEBUGMATCH(ci_log("config: compare '%s' with record '%s' - %s",
			  str, appname,
			  strcmp(str, appname) == 0? "matches":
			                             "doesn't match"););
	if (strcmp(str, appname) == 0) {
	  matches = 1;
	}
      }
    }
    DEBUGEXCLUSION(ci_log("config: application '%s' %sfound in "
			  "exclusion list",
		          str, matches? "": "not "););
    
    return matches;
  }
}


/*! Print a human readable dump of the config database into buf. Returns the
 *  number of bytes written or negative for error.
 */
extern size_t ci_cfg_pprint(char *buf, size_t len, const ci_cfg_hdr_t *hdr)
{
  size_t bytes=0;

  /* version */
  CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "VERSION: %u.%u\n",
                               (hdr->ver & CICFG_VER_MAJOR_MASK) >> 8,
                               (hdr->ver & CICFG_VER_MINOR_MASK)));
  NEWLINE(bytes, buf, len);

  /* strings */
  CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "STRINGS:\n"));
  CI_CFG_PRINT(bytes, ci_cfg_pprint_str_part(buf + bytes, len - bytes, hdr));
  NEWLINE(bytes, buf, len);

  /* exclusions */
  CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "EXCLUSIONS:\n"));
  CI_CFG_PRINT(bytes, ci_cfg_pprint_excl_part(buf + bytes, len - bytes, hdr));
  NEWLINE(bytes, buf, len);

  /* list of patches */
  CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "LIST OF PATCHES:\n"));
  CI_CFG_PRINT(bytes, ci_cfg_pprint_patch_part(buf + bytes, len - bytes,
                                               ci_cfg_patch_part(hdr)));
  NEWLINE(bytes, buf, len);

  /* default patch */
  CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "DEFAULT PATCH:\n"));
  CI_CFG_PRINT(bytes, ci_cfg_pprint_patch_id(buf + bytes, len - bytes,
                                             &hdr->default_config));
  NEWLINE(bytes, buf, len);
  NEWLINE(bytes, buf, len);

  /* user records */
  CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "USER RECORDS:\n"));
  CI_CFG_PRINT(bytes, ci_cfg_pprint_user_part(buf + bytes, len - bytes, hdr));
  NEWLINE(bytes, buf, len);

  /* app records */
  CI_CFG_PRINT(bytes, snprintf(buf + bytes, len - bytes, "APP RECORDS:\n"));
  CI_CFG_PRINT(bytes, ci_cfg_pprint_app_part(buf + bytes, len - bytes, hdr));
  NEWLINE(bytes, buf, len);
  
  return bytes;
}




extern void ci_cfg_create_empty_db(ci_cfg_empty_db_t *db)
{
  memset(db, 0, sizeof(*db));

  db->excl.rows = 0;
  db->str.strings = 0;
  db->patch.rows = 0;
  db->user.rows = 0;
  db->app.rows = 0;

  db->hdr.len = sizeof(*db);
  db->hdr.ver = CICFG_VER_NUM;
  db->hdr.default_config.patch_index = 0;
  db->hdr.default_config.patch_length = 0;
  db->hdr.rows = 5;
  
  db->hdr.part_off[CICFG_PART_EXCL]
      = CI_MEMBER_OFFSET(ci_cfg_empty_db_t, excl);
  
  db->hdr.part_off[CICFG_PART_STR]
      = CI_MEMBER_OFFSET(ci_cfg_empty_db_t, str);
  
  db->hdr.part_off[CICFG_PART_PATCH]
      = CI_MEMBER_OFFSET(ci_cfg_empty_db_t, patch);
  
  db->hdr.part_off[CICFG_PART_USERS]
      = CI_MEMBER_OFFSET(ci_cfg_empty_db_t, user);
  
  db->hdr.part_off[CICFG_PART_APPS]
      = CI_MEMBER_OFFSET(ci_cfg_empty_db_t, app);
}

