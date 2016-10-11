/*
** Copyright 2005-2016  Solarflare Communications Inc.
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
** \author  mj
**  \brief  ZF API
**   \date  2015/10/20
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ZF_H__
#define __ZF_H__

#include <zf/zf_platform.h>
#include <zf/muxer.h>

struct zf_stack;
struct zf_attr;

/*! \brief Initialize zf library.
**
** \return 0 on success, or a negative error code.
*/
LIBENTRY int zf_init(void);

/*! \brief Deinitialize zf library.
**
** \return 0 on success, or a negative error code.
*/
LIBENTRY int zf_deinit(void);

/*! \brief Allocate a stack with the supplied attributes
**
** \param attr       A set of properties to apply to the stack.
** \param stack_out  A pointer to the newly allocated stack.
**
** \return 0 on success, or a negative error code.
*/
LIBENTRY int zf_stack_alloc(struct zf_attr* attr, struct zf_stack** stack_out);

/*! \brief Free a stack previously allocated with zf_stack_alloc
**
** \param stack  Stack to free
**
** \return 0 on success, or a negative error code.
*/
LIBENTRY int zf_stack_free(struct zf_stack* stack);

/**
 * \brief Event indicating stack quiescence.
 * \sa zf_stack_to_waitable()
 */
#define EPOLLSTACKHUP EPOLLRDHUP

/**
 * \brief Returns a waitable object representing the quiescence of a stack.
 *
 * The waitable will be ready for #EPOLLSTACKHUP if the stack is quiescent.
 *
 * \sa zf_stack_is_quiescent()
 *
 * \returns Waitable.
 */
LIBENTRY struct zf_waitable* zf_stack_to_waitable(struct zf_stack*);

/**
 * \brief Returns a boolean value indicating whether a stack is quiescent.
 *
 * A stack is quiescent precisely when all of the following are true:
 *   - the stack will not transmit any packets except in response to external
 *     stimuli (including relevant API calls),
 *   - closing zockets will not result in the transmission of any packets, and
 *   - (optionally, controlled by the \c tcp_wait_for_time_wait stack
 *     attribute) there are no TCP zockets in the TIME_WAIT state.
 * In practice, this is equivalent altogether to the condition that there are
 * no open TCP connections.
 *
 * This can be used to ensure that all connections have been closed gracefully
 * before destroying a stack (or exiting the application).  Destroying a stack
 * while it is not quiescent is permitted by the API, but when doing so there
 * is no guarantee that sent data has been acknowledged by the peer or even
 * transmitted, and there is the possibility that peers' connections will be
 * reset.
 *
 * \sa zf_stack_to_waitable()
 *
 * \returns Non-zero if the stack is quiescent, or zero otherwise.
 */
LIBENTRY int zf_stack_is_quiescent(struct zf_stack*);

/**
 * \brief Print library name and version to stderr.
 */
LIBENTRY void zf_version(void);

#endif /* __ZF_H__ */
