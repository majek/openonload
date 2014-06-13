/*
** Copyright 2005-2013  Solarflare Communications Inc.
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
** <L5_PRIVATE L5_SOURCE>
** \author  cgg
**  \brief  FTL support for invoking MCDI operations
**   \date  2009/01/14
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_tests_nic */

#ifndef _FTL_MCDI_H
#define _FTL_MCDI_H

/* you need to include the ftl.h header prior to this one */

extern unumber_t last_mcdi_error;
extern bool log_mcdi_errors;

#define MCDI_SET_SYS_ERROR(ref_val, rc) *(ref_val) = ((unumber_t)(rc)<<32)
#define MCDI_SET_ERROR(ref_val, code)   *(ref_val) = ((unumber_t)(code))

#define MCDI_GET_SYS_ERROR(ref_val)   (*(ref_val) >> 32)
#define MCDI_GET_ERROR(ref_val)       (*(ref_val) & 0xFFFFFFFFul)

extern bool
cmds_mcdi_errs(parser_state_t *state, dir_t *cmds);

extern bool
mcdiop_read32vec(parser_state_t *state, mcdi_handle_t *mcdi,
                 mcdi_addr_t addr, uint32_t *out_buf, size_t words);

extern bool
mcdiop_write32vec(parser_state_t *state, mcdi_handle_t *mcdi,
                  mcdi_addr_t addr, uint32_t *buf, size_t words);

extern bool
cmds_mcdi_ops(parser_state_t *state, dir_t *cmds);

extern bool
cmds_mcdi_csr_ops(parser_state_t *state, dir_t *cmds);

extern bool
cmds_mcdi_mdio_ops(parser_state_t *state, dir_t *cmds);

extern bool
cmds_mcdi_dbi_ops(parser_state_t *state, dir_t *cmds);

extern bool
cmds_mcdi_port_ops(parser_state_t *state, dir_t *cmds);


/* This function must be supplied by the (only) library user */
extern bool
get_mcdi(parser_state_t *state, mcdi_handle_t **out_mcdi);


extern bool
check_range(parser_state_t *state, const char *thing,
            number_t n, number_t min, number_t max);

extern bool
check_urange(parser_state_t *state, number_t val, number_t max);

extern bool
check_is_u32bit(parser_state_t *state, number_t val);

extern bool
check_is_u16bit(parser_state_t *state, number_t val);

extern bool
check_is_u8bit(parser_state_t *state, number_t val);

extern bool
check_basealigned(parser_state_t *state, number_t addr, number_t mask);

extern bool
check_alignedaddr(parser_state_t *state, number_t addr, number_t mask);

extern bool
check_32addr(parser_state_t *state, number_t addr);

extern bool
check_16addr(parser_state_t *state, number_t addr);

extern bool
check_wholewords(parser_state_t *state, number_t bytesize);

extern bool
check_align(parser_state_t *state, const char *thing,
            number_t n, number_t mask, number_t alignment);

extern bool
check_mcdiop_return(parser_state_t *state,
                    const char *opname, int rc, mcdi_error_t mc_code);

#endif /* _FTL_MCDI_H */
