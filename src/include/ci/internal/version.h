/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Version information
**   \date  2003/06/03
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */

#ifndef __CI_INTERNAL_VERSION_H__
#define __CI_INTERNAL_VERSION_H__


/**********************************************************************
 ************************* Version management *************************
 **********************************************************************/

/* These numbers are updated manually, each time the software is "released" */

#define CI_MAJ_RELEASE_VERSION            (3)
#define CI_MIN_RELEASE_VERSION            (3)
#define CI_MAINT_RELEASE_VERSION          (0)
#define CI_INCREMENTING_VERSION           (6207)
#define CI_VERSION_STRING                 "v3.3.0.6207"

/* version number in format as needed for Windows .rc files */
#define CI_RC_PRODUCT_VERSION             CI_MAJ_RELEASE_VERSION,CI_MIN_RELEASE_VERSION,CI_MAINT_RELEASE_VERSION,CI_INCREMENTING_VERSION

/* Don't show incrementing version (build number) by default in Windows .rc files */
#define CI_RC_VERSION_STRING              "v3.3.0"

/* The family version string written to the VPD. Must be of the form "xx.yy.zz" 
** for Dell (see SF-103197-PS) */
#define CI_VPD_FAMILY_VERSION_STRING      "3.3.0"

#define CI_COPYRIGHT_STRING \
  "Copyright Solarflare Communications 2006-2012, Level 5 Networks 2002-2005 "
#define CI_COMPANY_NAME                   "Solarflare"
#define CI_PRODUCT_NAME                   "Solarstorm"


#endif  /* __CI_INTERNAL_VERSION_H__ */
/*! \cidoxg_end */

