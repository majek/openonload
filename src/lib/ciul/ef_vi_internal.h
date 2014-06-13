/*
** Copyright 2005-2013  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of version 2.1 of the GNU Lesser General Public
** License as published by the Free Software Foundation.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
*/

/****************************************************************************
 * Copyright 2002-2005: Level 5 Networks Inc.
 * Copyright 2005-2008: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

/*
 * \author  djr
 *  \brief  Really-and-truely-honestly internal stuff for libef.
 *   \date  2004/06/13
 */

/*! \cidoxg_include_ci_ul */
#ifndef __CI_EF_VI_INTERNAL_H__
#define __CI_EF_VI_INTERNAL_H__


/**********************************************************************
 * Headers
 */

#include <etherfabric/ef_vi.h>
#include "sysdep.h"
#include "ef_vi_falcon.h"


/**********************************************************************
 * Debugging.
 */

#define __EF_VI_BUILD_ASSERT_NAME(_x) __EF_VI_BUILD_ASSERT_ILOATHECPP(_x)
#define __EF_VI_BUILD_ASSERT_ILOATHECPP(_x)  __EF_VI_BUILD_ASSERT__##_x
#define EF_VI_BUILD_ASSERT(e)                                           \
	{ typedef char __EF_VI_BUILD_ASSERT_NAME(__LINE__)[(e) ? 1 : -1]; }


#ifdef NDEBUG
# ifdef __KERNEL__
#  define EF_VI_BUG_ON(x)  WARN_ON(x)
# else
#  define EF_VI_BUG_ON(x)  do{}while(0)
# endif
#else
# define EF_VI_BUG_ON(x)  BUG_ON(x)
#endif


/* *********************************************************************
 * Miscellaneous goodies
 */

#ifdef NDEBUG
# define EF_VI_DEBUG(x)
#else
# define EF_VI_DEBUG(x)            x
#endif

#define EF_VI_ROUND_UP(i, align)   (((i)+(align)-1u) & ~((align)-1u))
#define EF_VI_ALIGN_FWD(p, align)  (((p)+(align)-1u) & ~((align)-1u))
#define EF_VI_ALIGN_BACK(p, align) ((p) & ~((align)-1u))
#define EF_VI_PTR_ALIGN_BACK(p, align)					\
	((char*)EF_VI_ALIGN_BACK(((intptr_t)(p)), ((intptr_t)(align))))
#define EF_VI_IS_POW2(x)           ((x) && ! ((x) & ((x) - 1)))


#define EF_VI_PAGE_SIZE   4096
#define EF_VI_PAGE_SHIFT  12


/**********************************************************************
 * Extracting bit fields.
 */

#define _QWORD_GET_LOW(f, v)                                    \
  (((v).u32[0] >> f##_LBN) & ((1u << f##_WIDTH) - 1u))
#define _QWORD_GET_HIGH(f, v)                                   \
  (((v).u32[1] >> (f##_LBN - 32u)) & ((1u << f##_WIDTH) - 1u))
#define _QWORD_GET_ANY(f, v)                                            \
  (((v).u64[0] >> f##_LBN) & (((uint64_t) 1u << f##_WIDTH) - 1u))

#define QWORD_GET(f, v)                                                 \
  ((f##_LBN + f##_WIDTH) <= 32u                                         \
   ? _QWORD_GET_LOW(f, (v))                                             \
   : ((f##_LBN >= 32u) ? _QWORD_GET_HIGH(f, (v)) : _QWORD_GET_ANY(f, (v))))

#define QWORD_GET_U(f, v)  ((unsigned) QWORD_GET(f, (v)))

#define _QWORD_TEST_BIT_LOW(f, v)   ((v).u32[0] & (1u << f##_LBN))
#define _QWORD_TEST_BIT_HIGH(f, v)  ((v).u32[1] & (1u << (f##_LBN - 32u)))

#define QWORD_TEST_BIT(f, v)                                            \
  (f##_LBN < 32 ? _QWORD_TEST_BIT_LOW(f, (v)) : _QWORD_TEST_BIT_HIGH(f, (v)))


/* ******************************************************************** 
 */

extern void falcon_vi_init(ef_vi*, void* vvis ) EF_VI_HF;
extern void ef_eventq_state_init(ef_vi* evq) EF_VI_HF;


#endif  /* __CI_EF_VI_INTERNAL_H__ */
