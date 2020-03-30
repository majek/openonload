/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_STATE_P_H__
#define __ONLOAD_STATE_P_H__



typedef ci_int32 oo_p;

# define OO_P_INIT(p, ni, off)   ((p) = (off))
# define OO_P_OFF(p)             (p)

# define OO_P_IS_NULL(p)         ((p) < 0)
# define OO_P_NOT_NULL(p)        ((p) >= 0)
# define OO_P_EQ(pa, pb)         ((pa) == (pb))
# define OO_P_FMT(p)             ((int) (p))
# define OO_P_ADD(p, off)        do{ (p) += (off); }while(0)

# define OO_P_NULL               -1
# define OO_P_INVALID            -2



#endif  /* __ONLOAD_STATE_P_H__ */
