/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
**  \brief  TCPDirect stack API
*//*
\**************************************************************************/

#ifndef __ZF_STACK_H__
#define __ZF_STACK_H__

#ifndef __IN_ZF_TOP_H__
# error "Please include zf.h to use TCPDirect."
#endif


/*! \struct zf_stack
**
** A stack encapsulates hardware and protocol state.  It is the fundamental
** object used to drive TCPDirect.  Individual objects for handling TCP and UDP
** traffic --- <i>zockets</i> --- are created within a stack.
**
** \see zf_stack_alloc()
** \see zf_stack_free()
** \see zf_reactor_perform()
**/
struct zf_stack;
struct zf_attr;

/*! \brief Initialize zf library.
**
** Should be called exactly once per process, and before any other API calls
** are made.
**
** \return 0 on success, or a negative error code.  This function uses
** attributes internally and can return any of the error codes returned by
** zf_attr_alloc().  Additionally, it can return the following:
** \return -ENOENT  Failed to initialize control plane.  A likely cause is that
**                  Onload drivers are not loaded.
*/
ZF_LIBENTRY int zf_init(void);

/*! \brief Deinitialize zf library.
**
** \return 0.  Negative values are reserved for future use as error returns.
*/
ZF_LIBENTRY int zf_deinit(void);

/*! \brief Allocate a stack with the supplied attributes.
**
** \param attr       A set of properties to apply to the stack.
** \param stack_out  A pointer to the newly allocated stack.
**
** A stack encapsulates hardware and protocol state.  A stack binds to a single
** network interface, specified by the `interface` attribute in @p attr.  To
** process events on a stack, call zf_reactor_perform() or zf_muxer_wait().
**
** Relevant attributes to set in @p attr are those in the `zf_stack`,
** `zf_pool` and `zf_vi` categories described in the attributes documentation
** in \ref attributes.
**
** \return 0 on success, or a negative error code:
** \return -EBUSY   Out of VI instances or resources for alternatives.
** \return -EINVAL  Attribute out of range.
** \return -ENODEV  Interface was not specified or was invalid.
** \return -ENOENT  Failed to initialize ef_vi or Onload libraries.  A likely
**                  cause is that Onload drivers are not loaded.
** \return -ENOKEY  Adapter is not licensed for TCPDirect.
** \return -ENOMEM  Out of memory.  N.B. Huge pages are required.
** \return -ENOSPC  Out of PIO buffers.
** \return Errors from system calls are also possible.  Please consult your
** system's documentation for `errno(3)`.
*/
ZF_LIBENTRY int
zf_stack_alloc(struct zf_attr* attr, struct zf_stack** stack_out);

/*! \brief Free a stack previously allocated with zf_stack_alloc().
**
** \param stack  Stack to free
**
** \return When called with a valid stack, this function always returns zero.
**         Results on invalid stacks are undefined.
*/
ZF_LIBENTRY int zf_stack_free(struct zf_stack* stack);

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
ZF_LIBENTRY struct zf_waitable* zf_stack_to_waitable(struct zf_stack*);

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
ZF_LIBENTRY int zf_stack_is_quiescent(struct zf_stack*);

/**
 * \brief Returns library name and version.
 */
ZF_LIBENTRY const char* zf_version(void);

/**
 * \brief Prints library name and version to stderr, then exits.
 */
ZF_LIBENTRY void zf_print_version(void);

#endif /* __ZF_STACK_H__ */
/** @} */
