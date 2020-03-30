/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  mch
**  \brief  Version information
**   \date  2003/06/03
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */

#ifndef __CI_INTERNAL_RCVERSION_H__
#define __CI_INTERNAL_RCVERSION_H__

#include <ci/internal/version.h>

#undef  VER_COMPANYNAME_STR
#define VER_COMPANYNAME_STR       CI_COMPANY_NAME

#define VER_LEGALCOPYRIGHT_STR    CI_COPYRIGHT_STRING

#undef  VER_PRODUCTNAME_STR
#define VER_PRODUCTNAME_STR       CI_PRODUCT_NAME

#undef  VER_PRODUCTVERSION
#define VER_PRODUCTVERSION        CI_RC_PRODUCT_VERSION

#undef  VER_PRODUCTVERSION_STR
#define VER_PRODUCTVERSION_STR    CI_RC_VERSION_STRING


/* Make file version same as product version unless redefined later */
#define VER_FILEVERSION           VER_PRODUCTVERSION
#define VER_FILEVERSION_STR       VER_PRODUCTVERSION_STR

/* Default to language-independent software */
#define VER_LANGNEUTRAL

#endif  /* __CI_INTERNAL_VERSION_H__ */
/*! \cidoxg_end */

