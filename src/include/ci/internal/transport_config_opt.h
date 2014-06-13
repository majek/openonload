/*
** Copyright 2005-2012  Solarflare Communications Inc.
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
** \author  stg
**  \brief  Configuration options for transport lib
**   \date  2004/10/29
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */

#ifndef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_H__
#define __CI_INTERNAL_TRANSPORT_CONFIG_OPT_H__

/* This header is solely for configuration/compilation options!!
**
** In order to check for version skew between the driver and the user-mode
** library, we check against the CVS id for this header file.
** TODO: Checking against MD5 has of the file would be better.
** See also include/ci/internal/ip.h where we do the same thing.
*/
#define CI_CVS_OPT_HDR_VERSION ("$Revision$")

/* This just makes it a little neater to test for kernel. */
#ifdef __KERNEL__
# define CI_CFG_KERNEL                  1
#else
# define CI_CFG_KERNEL                  0
#include "libc_compat.h"
#endif

/* Maximum number of network interfaces (ports) per stack. */
#define CI_CFG_MAX_INTERFACES           6

/* Maximum number of networks interfaces that can be registered with the
 * onload driver.
 */
#define CI_CFG_MAX_REGISTER_INTERFACES  6

/* Maximum number of network interfaces that can be blacklisted as non
 * accelerated
 */
#define CI_CFG_MAX_BLACKLIST_INTERFACES 4

/* Some defaults.  These can be overridden at runtime. */
#define CI_CFG_NETIF_MAX_ENDPOINTS_SHIFT 10
/* The real max for endpoint order */
#define CI_CFG_NETIF_MAX_ENDPOINTS_SHIFT_MAX 15

/* ANVL assumes the 2MSL time is 60 secs. Set slightly smaller */
#define CI_CFG_TCP_TCONST_MSL		25

# define CI_CFG_TCP_FIN_TIMEOUT         60

#define CI_CFG_BURST_CONTROL            1
#if CI_CFG_BURST_CONTROL
#define CI_CFG_TCP_BURST_CONTROL_LIMIT  0
#endif

#define CI_CFG_CONG_AVOID_NOTIFIED 0
#if CI_CFG_CONG_AVOID_NOTIFIED
#define CI_CFG_CONG_NOTIFY_THRESH 24
#endif

/*! Enable rate pacing through IPG stretching on a per netif basis */
#define CI_CFG_RATE_PACING 1

/*! Maximum number of pages per endpoint allowed to pin for sendfile() */
#define CI_CFG_SENDFILE_MAX_PAGES_PER_EP    512

/* Features.  You probably want these.  On by default. */
#define CI_CFG_UDP                      1

/* Make UDP unlocked send path a runtime option.
 *
 * ?? TODO: This option only exists to aid development, and should be
 * purged once this bit of development and testing is complete.
 */
#define CI_CFG_UDP_SEND_UNLOCK_OPT      1

/* Debug aids.  Off by default, as some add lots of overhead. */
#ifndef CI_CFG_RANDOM_DROP
#define CI_CFG_RANDOM_DROP		0
#endif
#ifndef CI_CFG_POISON_BUFS
#define CI_CFG_POISON_BUFS		0
#endif
#ifndef CI_CFG_DETAILED_CHECKS
#define CI_CFG_DETAILED_CHECKS		0
#endif

/*
** Use userland select function. (env. var. EF_UL_SELECT & EF_UL_POLL)
*/
#define CI_CFG_USERSPACE_SELECT		1

/* Use userland epoll_* functions. (env. var. EF_UL_EPOLL, off by default) */
#define CI_CFG_USERSPACE_EPOLL          1

#if CI_CFG_USERSPACE_EPOLL

/* Maximum number of onload stacks handled by single epoll object.
 * Used for EF_UL_EPOLL=2 mode.  See also epoll2_max_stacks module
 * parameter.
 * Socket from other stacks will look just like "regular file descriptor"
 * for the onload object, without onload-specific acceleration. */
#define CI_CFG_EPOLL2_MAX_STACKS         16

/* Maximum number of postponed epoll_ctl operations, in case of
 * EF_UL_EPOLL=2 and EF_EPOLL_CTL_FAST=1 */
#define CI_CFG_EPOLL_MAX_POSTPONED      10


/* Workaround for handing over sockets from the epoll set.
 * 0: UL workaround, for EF_UL_EPOLL=1 only
 * 1: in-kernel workaround, for all epoll implementations
 */
#define CI_CFG_EPOLL_HANDOVER_WORKAROUND 1

#endif

/* Use userland pipe() implementation. */
#define CI_CFG_USERSPACE_PIPE           1

/* Enable this to support port striping. */
#define CI_CFG_PORT_STRIPING            0

/* Non-RFC1191 recovery time:
 * when PMTU goes to min (a very small number, poss. a DoS attack) use
 * a shorter recovery time than the RFC allows. 
 * Set to 0 to keep ANVL happy */
#define CI_CFG_FAST_RECOVER_PMTU_AT_MIN 0 

#define CI_CFG_SUPPORT_STATS_COLLECTION	1
#define CI_CFG_TCP_SOCK_STATS           0

/* Enable this to cause buffered stats (from sockopt) to be output
 * to the log rather than written to a buffer */
#define CI_CFG_SEND_STATS_TO_LOG        1

#define CI_CFG_IP_TIMER_DEBUG		0

/* Enable this to be strict about requiring all calls that use 
 * a sockaddr to set the family to AF_INET.  Disable to allow
 * the family to be AF_INET or AF_UNSPEC (which seems to be 
 * closer to what Linux allows) */
#define CI_CFG_REQUIRE_SOCKADDR_FAM	0

/* Enable this to use full IP ID block allocation functionality.
 * Disable this to use a single range (currently 1024) and do
 * less work on the fast path */
#define CI_CFG_FULL_IP_ID_HANDLING      0

/* Normally, if an initial block allocation fails, the netif
 * ctor will fail - and the UL stack will terminate.  Enable
 * this option to use ID block 0 instead of failing (not a 
 * recommended course of events!) */
#define CI_CFG_NO_IP_ID_FAILURE         1

/* Enable this to return ENOTCONN when recv/recvfrom/recvmsg are
 * called when not bound/connected (UDP) (see udp_recv.c) */
#define CI_CFG_POSIX_RECV               0

/* Enable this to have recvmsg() on TCP socket fill the [msg_name].  Linux
 * certainly doesn't. */
#define CI_CFG_TCP_RECVMSG_MSGNAME	0

/*!
 * Enable this to return EOPNOTSUPP when connect() is called after
 * listen() on the same socket (see tcp_connect.c).
 */
#define CI_CFG_POSIX_CONNECT_AFTER_LISTEN   0

/*!
 * Enable this to return EAGAIN (EWOULDBLOCK) as close() errno,
 * if socket fails to send all data before linger timeout.
 */
#define CI_CFG_POSIX_SO_LINGER          0

/* send reset for connections with invalid options in SYN packets */ 
#define CI_CFG_TCP_INVALID_OPT_RST	1

/* slack factor when setting zero window probe timer 
** Useful as many ANVL test advertise zero/small windows during 
** shutdown which we can probe causing fails in some tests.
*/
#define CI_CFG_TCP_ZWIN_SLACK_FACTOR	2

/* additional slack time when setting zero window probe timer */
#define CI_CFG_TCP_ZWIN_SLACK_TICKS	20

/* initial cwnd setting possible according to rfcs:
** 2001, 2581, 3390
*/
#define CI_CFG_TCP_INITIAL_CWND_RFC	2581

/* check PAWs on fastpath
** Not necessary by rfc1323, but by ANVL tcp_highperf4.17
*/
#define CI_CFG_TCP_PAWS_ON_FASTPATH	1

/* strict check of SEG.SEQ <= Last.ACK.sent < SEG.SEQ + SEG.LEN 
** as on rfc1323 p16 or the looser on p35:
** SEG.SEQ <= Last.ACK.sent <= SEG.SEQ + SEG.LEN implied
** Setting this to 1 will cause it to not update the echoed value
** unless a packet contains tcp payload data.
** Setting this to 0 will leave it vulnerable to misdetection of
** failures when zero length packets get reordered.
*/
#define CI_CFG_TCP_RFC1323_STRICT_TSO	0

/* Minimum MSS value */
/* ANVL requires some pretty small MSS values.  
   This is chosen to match the ANVL parameter */
#define CI_CFG_TCP_MINIMUM_MSS		64

/* How many RX descriptors to push at a time. */
#define CI_CFG_RX_DESC_BATCH		16

/* How many packets to fill on TX path before pushing them out. */
#define CI_CFG_TCP_TX_BATCH		8

/* Maximum receive window size.  This used to be 0x7fff.  Here's why:
**
** A weakness in ANVL (described in bug 828) means that if we set this
** to 0xffff, ANVL will incorrectly fail a test, even though we are
** not doing anything wrong. When bug 953 is fixed, that will also mean
** that the legal scenario ANVL fails on should not occur.
**
** There's no other clear reason why this should not be 0xffff, although
** there's a rumour that issues with signed arithmetic may become a problem.
** We have done a few development days of testing with 0xffff without this.
*/
#define CI_CFG_TCP_MAX_WINDOW           0xffff

/* RFCs specify that if the receiver shrinks the window the sender
 * should be robust and notice this. We used to, in the name of
 * efficiency, ignore shrinking windows.  Set to zero to get this old
 * behaviour */
#define CI_CFG_NOTICE_WINDOW_SHRINKAGE  1

/*
** Base value for dupack threshold.
*/ 
#define CI_CFG_TCP_DUPACK_THRESH_BASE 3

/*
** Maximum value for dupack threshold. Should be less than typical window 
** size (in calculated packets, not in bytes).
*/
#define CI_CFG_TCP_DUPACK_THRESH_MAX 127

/* IP TTL settings */
#define CI_IP_DFLT_TTL 64
#define CI_IP_MAX_TTL 255 

/* IP TOS setting */
#define CI_IP_DFLT_TOS 0
#define CI_IP_MAX_TOS 255
/* 8-bit field - but individual bits have (ignored) meaning */

/* Should we generate code that protects us against invalid shared state?
** By default we want the kernel to be robust to arbitrary shared state,
** but user-level to be fast.
*/
#ifndef CI_CFG_NETIF_HARDEN
# ifdef __KERNEL__
#  define CI_CFG_NETIF_HARDEN       1
# else
#  define CI_CFG_NETIF_HARDEN       0
# endif
#endif

/* Support H/W timer to give stack a kick when events are left unhandled
 * for a while.
 */
#define CI_CFG_HW_TIMER                 1

/* Implement pointers to packets as actual pointers. */
#define CI_CFG_PP_IS_PTR                0

/* Implement stack pointers as actual pointers. */
#define CI_CFG_OOP_IS_PTR               0

/* Implement socket pointers as actual pointers. */
#define CI_CFG_SOCKP_IS_PTR             0

# define CI_CFG_CHIMNEY                 0

/* Set to 1 if falcon is configured to deliver the RSS hash. */
#define CI_CFG_RSS_HASH                1

/* Enable invariant checking on entry/exit to library (sockcall intercept) */
#define CI_CFG_FDTABLE_CHECKS          0

/*
** Configuration options for TCP/IP striping.
**  - we stripe between hosts if we have a common netmask
**  - dupack threshold can be rasied to make the stack more 
**    tolerant to reordering
**  - default is all 1s - i.e. striping off
*/
#define CI_CFG_STRIPE_DEFAULT_NETMASK           0xffffffff
#define CI_CFG_STRIPE_DEFAULT_DUPACK_THRESHOLD  3

/* The default TCP header option number used for striping.  We'd like a
** proper assignment, but for now this will have to do:
**
** "And then they all sat down to supper.  And Black Mumbo ate Twenty-seven
** pancakes, and Black Jumbo ate Fifty-five but Little Black Sambo ate a
** Hundred and Sixty-nine, because he was so hungry."
*/
#define CI_CFG_STRIPE_DEFAULT_TCP_OPT		251

/* 
** Defaults for non-Linux and for broken Linux.
** Normally, we hope to get these values from OS. 
*/
#define CI_CFG_UDP_SNDBUF_DEFAULT		65535
#define CI_CFG_UDP_RCVBUF_DEFAULT		65535
#define CI_CFG_UDP_SNDBUF_MAX		131071
#define CI_CFG_UDP_RCVBUF_MAX		131071

#ifdef SOCK_MIN_SNDBUF
# define CI_CFG_UDP_SNDBUF_MIN		SOCK_MIN_SNDBUF
#else
#  define CI_CFG_UDP_SNDBUF_MIN		2048
#endif

# define CI_CFG_UDP_RCVBUF_MIN		256

/* TCP sndbuf */
#define CI_CFG_TCP_SNDBUF_MIN		0
# define CI_CFG_TCP_SNDBUF_DEFAULT	65535
#define CI_CFG_TCP_SNDBUF_MAX		65535

/* Receive buffer should be large enough to keep one jumbo frame */
#define CI_CFG_TCP_RCVBUF_MIN		10240
# define CI_CFG_TCP_RCVBUF_DEFAULT	65535
#define CI_CFG_TCP_RCVBUF_MAX		65535

/* These configuration "options" describe whether the host O/S normally
 * inherits specific socket state when accept() is called.
 */
# define CI_CFG_ACCEPT_INHERITS_NONBLOCK 0
# define CI_CFG_ACCEPT_INHERITS_NODELAY  1

/* Should the number of bytes reported by ioctl(FIONREAD) be limited
   to a maximum of the recieve buffer size? */
# define CI_CFG_FIONREAD_LIMIT          0

/* Maximum possible value for listen queue (backlog).
 * It is substituted from OS, when possible. */
#define CI_TCP_LISTENQ_MAX 256

/* TCP window scale maximum and default.
 * Maximum is taken from RFC1323 and may be overriden by OS settings for
 * send value.
 * Default is overriden based on receive buffer. */
#define CI_TCP_WSCL_MAX      14     /* RFC 1323 max shift                 */
#define CI_TCP_WSCL_DEFAULT   0     /* default advertised window scale    */

/* It is supposed that 
 * CI_TCP_RETRANSMIT_THRESHOLD > CI_TCP_RETRANSMIT_THRESHOLD_SYN.
 * Do not break this! */
#define CI_TCP_RETRANSMIT_THRESHOLD     15  /* retransmit 15 times */
#define CI_TCP_RETRANSMIT_THRESHOLD_SYN 4   /* retransmit SYN 4 times */

/* Should we send DSACK option? */
#define CI_CFG_TCP_DSACK 1

/* Path to the /proc/sys/ */
#define CI_CFG_PROC_PATH		"/proc/sys/"
/* The real max is 30, but let's use larger value. */
#define CI_CFG_PROC_PATH_LEN_MAX	70
/* Stolen from procps/sysctl.c */
#define CI_CFG_PROC_LINE_LEN_MAX	1025

/*
 * CI_CFG_HANDLE_UDP_FRAG enables support for fragmented UDP interception
 * in the net driver (when disabled all UDP frags are passed to the kernel).
 * It also enabled the addition & removal of driverlink filters.
 *
 * When disabled no filter add/remove requests are sent from the char driver
 * and any ICMP messages seen at the net driver are filtered for type/code
 * and then passed across without reference to the dest. IP address.  In the
 * char driver the address is checked.
 *
 * DEPRECATED - ALWAYS set to 0 (net driver/kernel handle UDP frags)
 */
#define CI_CFG_HANDLE_UDP_FRAG      0

/*
 * Whether the control plane synchronization operations are made available
 * to the user must be 1 for Windows, but optional otherwise
 */
#define CI_CFG_CONTROL_PLANE_USER_SYNC    1

/* Compile-time control for "no fail" exit from UDP connect/bind.
 * Provided on the premis that we at least want to fail gracefully & therefore,
 * if we're about to fail because of the UL stack, we let the OS have a go. 
 *
 * NOTES: 
 * 1. this will probably mask problems in the UL library - so the debug
 *    build defauls to all "no fail" options disabled & the release version
 *    defaults to all "no fail" options enabled. 
 *
 * 2. Better than "graceless", but of very limited appeal for UDP where
 *    the traffic includes fragmented messages and CI_CFG_UDP_TUNNELLING==1
 *    as the OS socket cannot handle our software-only scheme (
 *    now, if we had a hardware scheme ... 8-) )
 */
#define CI_CFG_NO_FAIL_BIND           1  /* UDP  */
#define CI_CFG_NO_FAIL_CONNECT        1  /* UDP  */

/*
 * CI_CFG_CONGESTION_WINDOW_VALIDATION actviates RFC2861 compliance;
 * if no packets are sent for N round trip times, then reduced the
 * congestion window by a factor of 2 for each round trip time since
 * the last transmit.  This is good for congested backbone links, but
 * not helpful for switched LANs, where round trip times can be very
 * short, and thus if applications do not send anything for even a few
 * miliseconds, they end with a tiny congestion window which needs to
 * be opened up.
 *
 * Make sure you read the comment below for 
 * CI_CFG_CONGESTION_WINDOW_VALIDATION_DELACK_SCALING if you activate this; 
 * it is recommended that you activate that option as well if you want this 
 * option.
 */
#define CI_CFG_CONGESTION_WINDOW_VALIDATION 0

/*
 * A substantial performance problem with congestion window validation
 * as it is defined in RFC2861 is that it will bottom out the
 * congestion window at one one MSS. The trouble with that is that if
 * using delayacked acknowledgements, there may still be a full
 * segment of unacknowledged data already with the client, which means
 * that we will choose not to send any more data until it has been
 * acknowledged. Enabling this option causes the congestion window to
 * bottom out at one MSS per delayed ack (i.e. typically two
 * MSS). This is in keeping with the idea in RFC2581 of setting the
 * initial congestion window to two MSS.
 *
 * See bug 623.
 */
#define CI_CFG_CONGESTION_WINDOW_VALIDATION_DELACK_SCALING 0

/* When the netif is wedged, due to userspace dying while the kernel is in an
 * inconsistent state, rather than go through the full process of closing the
 * endpoint (which could fail, due to the inconsistent state), if DESTROY_WEDGED
 * is set, we remove the filters and go straight to deleting data structures.
 */
#define CI_CFG_DESTROY_WEDGED 1


/* Include support for reducing the rate at which the congestion window is
 * increased during congestion avoidance.
 */
#define CI_CFG_CONG_AVOID_SCALE_BACK	1

/* 
 * Define how aggressive we should be in opening the congestion window
 * during slow start.  Define to non-zero to get RFC2581 behaviour
 * (1MSS increase for each received ACK) or zero to get RFC3465
 * behaviour (at most 2MSS increase for each received ACK).  See
 * Section 2.2 and 2.3 of RFC3465 for discussion of this.
 */
#define CI_CFG_CONG_AVOID_CONSERVATIVE_SLOW_START 0

/* 
 * When CI_CFG_CONG_AVOID_CONSERVATIVE_SLOW_START is zero, and so
 * RFC3465 behaviour is selected, this supplies the value for "L" from
 * that RFC.  It should be between 1 and 2 to comply
 */ 
#define CI_CFG_CONG_AVOID_RFC3465_L_VALUE 2

/* EXPERIMENTAL
 * Enable TCP filtering in the net driver.  When enabled all unfragmented
 * TCP that is destined for a UL TCP address/port will be discarded by the
 * driverlink filter.  Rx & Tx are handled separately.
 * 
 * DEFAULTS: 0
 */
#define CI_CFG_NET_TCP_RX_FILTER 0
#define CI_CFG_NET_TCP_TX_FILTER 0

/* Enable filtering of DHCP packets from the net driver, which the DHCP client
 * code inside the iSCSI module can register to receive.  (This is required for
 * the DHCP client to work, but the iSCSI DHCP client is only needed for
 * Windows.)
 */
#define CI_CFG_NET_DHCP_FILTER 0

/* Detect cases where delayed acks could be detrimental to performance
 * (e.g. in slow start, or after data loss) and send ACKs for all
 * packets.
 */
#define CI_CFG_TCP_FASTSTART   1

/* Number of zero window probes to be sent before we try to split packets
** and fill the small window. We will never split packets when we have just 
** received an ack with zero window; we will wait for at least one zwin 
** timeout. Current default is CI_CFG_TCP_ZWIN_THRESH = 1, it means to wait 
** for two zwin timeouts.
*/
#define CI_CFG_TCP_ZWIN_THRESH 1

/* If a tail drop is suspected, try to probe it with a retransmission.
*/
#define CI_CFG_TAIL_DROP_PROBE 0

/* Dump users of TCP and UDP sockets to a log file. */
#define CI_CFG_LOG_SOCKET_USERS         0


/* Include fake IPv6 support (0 - off, 1 - on) */
#define CI_CFG_FAKE_IPV6 1


/* Include support for caching file descriptors at user-level.
**
** NB. At time of writing this feature is broken.
*/
#define CI_CFG_FD_CACHING      0

/* Enable iSCSI features. */
#define CI_CFG_ISCSI           0

/*
 * If set to 1, enable asynchronous zero-copy transmit for iSCSI.
 */
#define CI_CFG_ISCSI_ZC_TX 1

/*
 * If set to 1, enable iSCSI digest offload.  Only works properly on falcon
 * B silicon and later, but necessary to get iSCSI to load these days
 */
# define CI_CFG_ISCSI_TX_DIGEST_OFFLOAD 0
# define CI_CFG_ISCSI_RX_DIGEST_OFFLOAD 0

/* Support physical addressing (as well as protected buffer addressing). */
#ifdef __KERNEL__
# define CI_CFG_SUPPORT_PHYS_ADDR  1
#else
# define CI_CFG_SUPPORT_PHYS_ADDR  0
#endif

/* If set to 1, build ci_netif_dump() and friends inside the kernel, to allow
 * stackdump-like output to be generated for debugging purposes (useful for
 * iSCSI in particular).  Only tested with Linux so far.
 */
# define CI_CFG_BUILD_DUMP_CODE_IN_KERNEL 1

/* Maintain statistics for listening sockets.  At time of writing these are
** all gathered off the fast path, so there is no significant performance
** penalty for having them on.
*/
#define CI_CFG_STATS_TCP_LISTEN		1

/* Maintain per-netif statistics for things like event-queue callbacks etc.
** At time of writing these are all gathered off the fast path, so there is
** no significant performance penalty for having them on.
*/
#define CI_CFG_STATS_NETIF		1

/*
 * install broadcast hardware filters for UDP
 * - not needed currently as all such sockets get passed to OS
 */
#define CI_CFG_INSTALL_UDP_BROADCAST_FILTERS  0

/* Size of packet buffers.  Must be 2048 or 4096.  The larger value reduces
 * overhead when packets are large, but wastes memory when they aren't.
 */
#define CI_CFG_PKT_BUF_SIZE             2048

/* Allow WaitFor[Single,Multiple]Object to spin polling netifs before
 * blocking.
 */
#define CI_CFG_BLOCKING_SPIN_WFMO 1 /* WaitForMultipleObjects */
#define CI_CFG_BLOCKING_SPIN_WFSO 1 /* WaitForSingleObject (also affects
                                       GetOverlappedResult())*/
#define CI_CFG_BLOCKING_SPIN_GQCS 1 /* GetQueuedCompletionStatus */
#define CI_CFG_BLOCKING_SPIN_SLEEPEX 1 /* SleepEx */
#define CI_CFG_BLOCKING_SPIN_SOAW 1 /* SignalObjectAndWait */

/* Number of buckets in the listen queue hash table.  Must be a power of
** 2. */
#define CI_CFG_TCP_LISTENQ_BUCKETS  32

#ifndef CI_CFG_REF_WIN32_FO
#define CI_CFG_REF_WIN32_FO 1 /* keep ref to file object to
				 stop it disappearing too soon */
#endif

#define CI_CFG_SENDFILE   0
#define CI_CFG_SENDFILEV  0
# undef  CI_CFG_SENDFILE
# define CI_CFG_SENDFILE  1

/* Enable support for recvmmsg(). */
#define CI_CFG_RECVMMSG          1

/* Enable support for sendmmsg(). */
#define CI_CFG_SENDMMSG          1

/* Enable filtering of packets before delivery */
#define CI_CFG_ZC_RECV_FILTER    1

/* HACK: Limit the advertised MSS for TCP because our TCP path does not
 * currently cope with frames that don't fit in a single packet buffer.
 * This define really exists just to make it easy to find and remove this
 * hack.
 */
#define CI_CFG_LIMIT_AMSS  1
#define CI_CFG_LIMIT_SMSS  1


/* Max length of "name" of a stack. */
#define CI_CFG_STACK_NAME_LEN  16

/* Teaming support in OpenOnload */
#define CI_CFG_TEAMING 1

/* Time (usecs) between calling clock_gettime() to resync SO_TIMESTAMP clock */
#define CI_CFG_TIMESTAMP_RESYNC_TIME 1000000

/* Allow the TCP RX path to assume it holds the only reference to packets. */
#define CI_CFG_TCP_RX_1REF  0

/* Onload tcpdump support */
#define CI_CFG_TCPDUMP 1

#if CI_CFG_TCPDUMP
/* Dump queue length, should be 2^x, x <= 8 */
#define CI_CFG_DUMPQUEUE_LEN 128

#if CI_CFG_TCP_RX_1REF
#error "CI_CFG_TCP_RX_1REF and CI_CFG_TCPDUMP cannot both be enabled."
#endif
#endif /* CI_CFG_TCPDUMP */


/* Set to use flag if you want stronger assertions, only zero-copy API
 * needs the re-entrancy of counting implementation 
 */
#define CI_CFG_CITP_INSIDE_LIB_IS_FLAG 0

/* Support for reducing ACK rate at high throughput to improve efficiency */
#define CI_CFG_DYNAMIC_ACK_RATE 1

/* Mmap each packet set from kernel to userspace separately.
 * CI_CFG_MMAP_EACH_PKTSET=0 is going to be removed sooner or later.
 *
 * In Linux, this is necessary for huge pages, since huge pages
 * should be mmaped separately.  If you are not going to use huge pages,
 * feel set this to 0 to speed up non-huge mappings.
 *
 * Solaris needs this to 1.
 */
#define CI_CFG_MMAP_EACH_PKTSET 1

/* Allocate packets in huge pages when possible */
#if defined(__linux__) && CI_CFG_MMAP_EACH_PKTSET
/* Can be turned off.  Does not really work unless your kernel has
 * CONFIG_HUGETLB_PAGE on and your kernel is 64-bit. */
#define CI_CFG_PKTS_AS_HUGE_PAGES 1
#else
/* Huge pages are not supported on non-linux or
 * with CI_CFG_MMAP_EACH_PKTSET=0 */
#define CI_CFG_PKTS_AS_HUGE_PAGES 0
#endif

/* Compatibility check */
#if CI_CFG_PKTS_AS_HUGE_PAGES && \
    (!defined(__linux__) || !CI_CFG_MMAP_EACH_PKTSET)
#error "Incompatible CI_CFG settings"
#endif


/* Page=4KiB=2pkts; huge page=2MiB=2^10pkts.
 * To use huge pages, we should allocate exactly 2^10 pkts per set.
 * DO NOT CHANGE THIS VALUE if you have CI_CFG_PKTS_AS_HUGE_PAGES=1 */
#if CI_CFG_PKT_BUF_SIZE == 2048
#define CI_CFG_PKTS_PER_SET_S  10u
#elif CI_CFG_PKT_BUF_SIZE == 4096
#define CI_CFG_PKTS_PER_SET_S  9u
#else
#error "Incorrect CI_CFG_PKT_BUF_SIZE value"
#endif


#if CI_CFG_PKTS_AS_HUGE_PAGES
/* Maximum number of packet sets; each packet set is 2Mib (huge page)
 * = 2^9 or 2^10 packets, depending on CI_CFG_PKT_BUF_SIZE.
 * See also max_packets_per_stack module parameter. */
#define CI_CFG_MAX_PKT_SETS 1024
#endif





#endif /* __CI_INTERNAL_TRANSPORT_CONFIG_OPT_H__ */
/*! \cidoxg_end */
