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
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Definition of stack statistics
**   \date  2008/04/25
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*
 * OO_STAT(description, datatype, name, kind)
 */

OO_STAT("Number of times event queue was polled from kernel.",
        ci_uint32, k_polls, count)
OO_STAT("Number of times event queue was polled from user-level.",
        ci_uint32, u_polls, count)
OO_STAT("Number of RX events handled.",
        ci_uint32, rx_evs, count)
OO_STAT("Number of TX events handled.",
        ci_uint32, tx_evs, count)
OO_STAT("Number of times periodic timer has polled for events.",
        ci_uint32, periodic_polls, count)
OO_STAT("Number of network events handled by periodic timer.",
        ci_uint32, periodic_evs, count)
OO_STAT("Number of times periodic timer could not get the stack lock.",
        ci_uint32, periodic_lock_contends, count)
OO_STAT("Number of interrupts.",
        ci_uint32, interrupts, count)
OO_STAT("Number of times an interrupt polled for network events.",
        ci_uint32, interrupt_polls, count)
OO_STAT("Number of network events handled in interrupts.",
        ci_uint32, interrupt_evs, count)
OO_STAT("Number of times an interrupt woke one or more processes.",
        ci_uint32, interrupt_wakes, count)
OO_STAT("Number of times interrupts were re-enabled.",
        ci_uint32, interrupt_primes, count)
OO_STAT("Number of times an interrupt found no network events.",
        ci_uint32, interrupt_no_events, count)
OO_STAT("Number of times an interrupt could not lock the stack.",
        ci_uint32, interrupt_lock_contends, count)
OO_STAT("Number of times poll has been deferred to lock holder.",
        ci_uint32, deferred_polls, count)
OO_STAT("Number of timeout interrupts.",
        ci_uint32, timeout_interrupts, count)
OO_STAT("Number of times timeout interrupts polled for network events.",
        ci_uint32, timeout_interrupt_polls, count)
OO_STAT("Number of network events handled in timeout interrupts.",
        ci_uint32, timeout_interrupt_evs, count)
OO_STAT("Number of times a timeout interrupt woke one or more processes.",
        ci_uint32, timeout_interrupt_wakes, count)
OO_STAT("Number of times timeout interrupts found no network events.",
        ci_uint32, timeout_interrupt_no_events, count)
OO_STAT("Number of times timeout interrupts could not lock the stack.",
        ci_uint32, timeout_interrupt_lock_contends, count)
OO_STAT("Number of times select/poll/epoll enabled interrupts.",
        ci_uint32, select_primes, count)
OO_STAT("Times a thread has blocked on a single socket.",
        ci_uint32, sock_sleeps, count)
OO_STAT("Times a thread has enabled interrupts before blocking on a socket.",
        ci_uint32, sock_sleep_primes, count)
OO_STAT("Times Onload has woken threads waiting on a socket for receive.",
        ci_uint32, sock_wakes_rx, count)
OO_STAT("Times Onload has woken threads waiting on a socket for transmit.",
        ci_uint32, sock_wakes_tx, count)
OO_STAT("Times OS has woken threads waiting on an Onload socket for receive.",
        ci_uint32, sock_wakes_rx_os, count)
OO_STAT("Times OS has woken threads waiting on an Onload socket for transmit.",
        ci_uint32, sock_wakes_tx_os, count)
OO_STAT("Times Onload has potentially sent a signal due to O_ASYNC.",
        ci_uint32, sock_wakes_signal, count)
#if CI_CFG_PKTS_AS_HUGE_PAGES
OO_STAT("Number of huge pages allocated for packet sets.",
        ci_uint32, pkt_huge_pages, count)
#endif
OO_STAT("Number of packet buffers cycled through the non-blocking pool.",
        ci_uint32, pkt_nonb, count)
OO_STAT("Times we've taken a packet from the non-blocking pool while locked.",
        ci_uint32, pkt_nonb_steal, count)
OO_STAT("Times we've woken threads waiting for free packet buffers.",
        ci_uint32, pkt_wakes, count)
OO_STAT("Number of times we've scrambled (l0) to find free buffers",
        ci_uint32, pkt_scramble0, count)
OO_STAT("Number of times we've scrambled (l1) to find free buffers.",
        ci_uint32, pkt_scramble1, count)
OO_STAT("Number of times we've scrambled (l2) to find free buffers.",
        ci_uint32, pkt_scramble2, count)
OO_STAT("Times a thread has spun waiting for a packet.",
        ci_uint32, pkt_wait_spin, count)
OO_STAT("Times we've taken the slow path unlocking the stack lock.",
        ci_uint32, unlock_slow, count)
OO_STAT("Times packet memory shortage provoked the unlock slow path.",
        ci_uint32, unlock_slow_pkt_waiter, count)
OO_STAT("Times the unlock slow path was taken to wake threads.",
        ci_uint32, unlock_slow_wake, count)
OO_STAT("Times the unlock slow path was taken to close sockets/pipes.",
        ci_uint32, unlock_slow_close, count)
OO_STAT("Times a syscall was needed on the unlock slow path.",
        ci_uint32, unlock_slow_syscall, count)
OO_STAT("Times we've woken a thread blocked on the stack lock.",
        ci_uint32, lock_wakes, count)
OO_STAT("Times a thread has spun waiting for the stack lock.",
        ci_uint32, stack_lock_buzz, count)
OO_STAT("Times work has been done by the lock holder for another thread.",
        ci_uint32, deferred_work, count)
OO_STAT("Times a thread has slept waiting for a sock lock.",
        ci_uint32, sock_lock_sleeps, count)
OO_STAT("Times a thread has spun waiting for a sock lock.",
        ci_uint32, sock_lock_buzz, count)
OO_STAT("Number of times TCP sendmsg() found the non-blocking poll empty.",
        ci_uint32, tcp_send_nonb_pool_empty, count)
OO_STAT("Number of times TCP sendmsg() contended the stack lock.",
        ci_uint32, tcp_send_ni_lock_contends, count)
OO_STAT("Number of times UDP sendmsg() contended the stack lock.",
        ci_uint32, udp_send_ni_lock_contends, count)
OO_STAT("Number of times getsockopt() contended the stack lock.",
        ci_uint32, getsockopt_ni_lock_contends, count)
OO_STAT("Number of times setsockopt() contended the stack lock.",
        ci_uint32, setsockopt_ni_lock_contends, count)
OO_STAT("Multicast loop-back sends.",
        ci_uint32, udp_send_mcast_loop, count)
OO_STAT("Multicast loop-back send was dropped due to RX packet buffer limit.",
        ci_uint32, udp_send_mcast_loop_drop, count)
OO_STAT("Number of active opens that reached established.",
        ci_uint32, active_opens, count)
OO_STAT("Number of TCP sockets passed to O/S in socket().",
        ci_uint32, tcp_handover_socket, count)
OO_STAT("Number of TCP sockets passed to O/S in bind().",
        ci_uint32, tcp_handover_bind, count)
OO_STAT("Number of TCP sockets passed to O/S in listen().",
        ci_uint32, tcp_handover_listen, count)
OO_STAT("Number of TCP sockets passed to O/S in connect().",
        ci_uint32, tcp_handover_connect, count)
OO_STAT("Number of TCP sockets passed to O/S in setsockopt().",
        ci_uint32, tcp_handover_setsockopt, count)
OO_STAT("Number of UDP sockets passed to O/S in socket().",
        ci_uint32, udp_handover_socket, count)
OO_STAT("Number of UDP sockets passed to O/S in bind().",
        ci_uint32, udp_handover_bind, count)
OO_STAT("Number of UDP sockets passed to O/S in connect().",
        ci_uint32, udp_handover_connect, count)
OO_STAT("Number of UDP sockets passed to O/S in setsockopt().",
        ci_uint32, udp_handover_setsockopt, count)
OO_STAT("Number of times we couldn't install filters for UDP bind().",
        ci_uint32, udp_bind_no_filter, count)
OO_STAT("Number of times we couldn't install filters for UDP connect().",
        ci_uint32, udp_connect_no_filter, count)
OO_STAT("Number of sockets reaped from timewait (for socket).",
        ci_uint32, timewait_reap, count)
OO_STAT("Number of sockets reaped from timewait (for filter).",
        ci_uint32, timewait_reap_filter, count)
OO_STAT("Max hops in a hash table lookup.",
        ci_uint32, table_max_hops, val)
OO_STAT("Rolling mean of number of hops in recent inserts.",
        ci_uint32, table_mean_hops, val)
OO_STAT("Number of entries in hash table.",
        ci_uint32, table_n_entries, val)
OO_STAT("Number of slots occupied in hash table.",
        ci_uint32, table_n_slots, val)
OO_STAT("Number of retransmit timeouts.",
        ci_uint32, tcp_rtos, count)
OO_STAT("Number of times a connection has been reset while in accept queue.",
        ci_uint32, rst_recv_acceptq, count)
OO_STAT("Number of times a connection has been reset while in the listen "
        "queue.",
        ci_uint32, rst_recv_synrecv, count)
OO_STAT("Number of connections reset with data in the receive queue.",
        ci_uint32, rst_recv_has_recvq, count)
OO_STAT("Number of connections reset with data in the send queue.",
        ci_uint32, rst_recv_has_sendq, count)
OO_STAT("Number of connections reset with unacknowledged data.",
        ci_uint32, rst_recv_has_unack, count)
OO_STAT("Number of times a connection has been reset while in the listen "
        "queue.",
        ci_uint32, rst_recv_unacceptable, count)

OO_STAT("Number of unacceptable ACKs replied to with a RST.",
        ci_uint32, rst_sent_unacceptable_ack, count)
OO_STAT("Number of RSTs sent due to bad SYN received in SYNRECV.",
        ci_uint32, rst_sent_synrecv_bad_syn, count)
OO_STAT("Number of RSTs sent due to bad ACK received in SYNRECV.",
        ci_uint32, rst_sent_synrecv_bad_ack, count)
OO_STAT("Number of RSTs sent due to .",
        ci_uint32, rst_sent_listen_got_ack, count)
OO_STAT("Number of RSTs sent due to .",
        ci_uint32, rst_sent_bad_options, count)
OO_STAT("Number of RSTs sent due to .",
        ci_uint32, rst_sent_bad_seq, count)
OO_STAT("Number of RSTs sent due to .",
        ci_uint32, rst_sent_no_match, count)

OO_STAT("Number of unacceptable ACKs received.",
        ci_uint32, unacceptable_acks, count)
OO_STAT("Times a connection has been dropped because we can't send a FIN.",
        ci_uint32, tcp_drop_cant_fin, count)
OO_STAT("Number of SYNRECV retransmits.",
        ci_uint32, synrecv_retransmits, count)
OO_STAT("Number of sends from SYNRECVs that failed.",
        ci_uint32, synrecv_send_fails, count)
OO_STAT("Number of times synrecvs have been dropped due to timeout.",
        ci_uint32, synrecv_timeouts, count)
OO_STAT("Times a synrecv has been purged to make room for a new one.",
        ci_uint32, synrecv_purge, count)
OO_STAT("Times a SYN has been dropped due to overload.",
        ci_uint32, syn_drop_busy, count)
OO_STAT("Transitions from LISTEN to SYN-RECV.",
        ci_uint32, listen2synrecv, count)
OO_STAT("Transitions from SYN-RECV to ESTABLISHED.",
        ci_uint32, synrecv2established, count)
OO_STAT("Number of successful user-level accept()s.",
        ci_uint32, ul_accepts, count)
OO_STAT("Number of times accept() returned EAGAIN.",
        ci_uint32, accept_eagain, count)
OO_STAT("Times TCP_DEFER_ACCEPT has kicked-in.",
        ci_uint32, accepts_deferred, count)
OO_STAT("Number of TCP ACKs sent.",
        ci_uint32, acks_sent, count)
OO_STAT("Number of TCP window updates sent.",
        ci_uint32, wnd_updates_sent, count)
OO_STAT("Number of TCP segments processed on slow path.",
        ci_uint32, rx_slow, count)
OO_STAT("Number of out-of-order TCP segments received.",
        ci_uint32, rx_out_of_order, count)
OO_STAT("Number of TCP segments received in-order when ROB is non-empty.",
        ci_uint32, rx_rob_non_empty, count)
OO_STAT("Number of TCP segments retransmited.",
        ci_uint32, retransmits, count)
OO_STAT("Number of TX packet errors.",
        ci_uint32, tx_error_events, count)
OO_STAT("Number of RX discards (checksum bad).",
        ci_uint32, rx_discard_csum_bad, count)
OO_STAT("Number of RX discards (multicast mismatch).",
        ci_uint32, rx_discard_mcast_mismatch, count)
OO_STAT("Number of RX discards (crc bad).",
        ci_uint32, rx_discard_crc_bad, count)
OO_STAT("Number of RX discards (frame truncated).",
        ci_uint32, rx_discard_trunc, count)
OO_STAT("Number of RX discards (buffer ownership error).",
        ci_uint32, rx_discard_rights, count)
OO_STAT("Number of RX discards (other).",
        ci_uint32, rx_discard_other, count)
OO_STAT("Number of times we have refilled RX ring from recv() path.",
        ci_uint32, rx_refill_recv, count)
OO_STAT("Number of times we've tried to free buffers by reaping.",
        ci_uint32, reap_rx_limited, count)
OO_STAT("Number of times we've tried to free buffers by reaping.",
        ci_uint32, reap_buf_limited, count)
OO_STAT("Number of packet buffers freed by reaping.",
        ci_uint32, pkts_reaped, count)
OO_STAT("Number of times we could not refill RX ring due to RX limit.",
        ci_uint32, refill_rx_limited, count)
OO_STAT("Number of times we could not refill RX ring due to lack of buffers.",
        ci_uint32, refill_buf_limited, count)
OO_STAT("Number of times we couldn't defer work to lock holder due to limit",
        ci_uint32, defer_work_limited, count)
OO_STAT("Maximum fill level of TX DMA overflow queue.",
        ci_uint32, tx_dma_max, val)
OO_STAT("Number of TX DMA doorbells.",
        ci_uint32, tx_dma_doorbells, count)
OO_STAT("Number of sends that failed due to alien (i.e. Non-SFC) route.",
        ci_uint32, tx_discard_alien_route, count)
OO_STAT("Number of attempts to allocate packet buffer set which have failed.",
        ci_uint32, bufset_alloc_fails, count)
OO_STAT("Number of times MSS has been forcibly limited.",
        ci_uint32, mss_limitations, count)
OO_STAT("Number of times stack has entered 'memory pressure' state.",
        ci_uint32, memory_pressure_enter, count)
OO_STAT("Number of times stack has exited 'memory pressure' state via poll.",
        ci_uint32, memory_pressure_exit_poll, count)
OO_STAT("Number of times stack has exited 'memory pressure' state via recv.",
        ci_uint32, memory_pressure_exit_recv, count)
OO_STAT("Number of packets dropped due to 'memory pressure'.",
        ci_uint32, memory_pressure_drops, count)
OO_STAT("Number of UDP packets dropped because no socket matched.",
        ci_uint32, udp_rx_no_match_drops, count)
OO_STAT("Number times inserting filter into software table failed.",
        ci_uint32, sw_filter_insert_table_full, count)
#if CI_CFG_SENDFILE
OO_STAT("Number of calls to tcp file-op sendpage().",
        ci_uint32, tcp_sendpages, count)
#endif
OO_STAT("Number of times when failed to allocate packet from stack poll",
        ci_uint32, poll_no_pkt, count)
