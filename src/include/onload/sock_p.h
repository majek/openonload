/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_SOCK_P_H__
#define __ONLOAD_SOCK_P_H__



typedef ci_int32 oo_sp;

# define OO_SP_FROM_INT(ni, id)   (id)
# define OO_SP_TO_INT(p)          (p)

# define OO_SP_IS_NULL(p)         ((p) < 0)
# define OO_SP_NOT_NULL(p)        ((p) >= 0)
# define OO_SP_EQ(pa, pb)         ((pa) == (pb))
# define OO_SP_FMT(p)             ((int) (p))

# define OO_SP_NULL               -1
# define OO_SP_INVALID            -2



#endif  /* __ONLOAD_SOCK_P_H__ */
