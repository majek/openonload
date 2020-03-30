/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
**  \brief  TCPDirect Delegated Sends API
*//*
\**************************************************************************/

#ifndef __ZF_DS_H__
#define __ZF_DS_H__

#ifndef __IN_ZF_TOP_H__
# error "Please include zf.h to use TCPDirect."
#endif


/*! \brief Structure used for delegated sends
**
** This structure is used for delegated sends. Field usage varies:
** - in: input
** - out: output
** - internal: internal use only.
*/
struct zf_ds {
  /** in: set to buffer to store headers to */
  void* headers;
  /** in: size of headers buffer */
  int   headers_size;
  /** out: length of headers */
  int   headers_len;

  /** out: max segment size (max payload per packet) */
  int   mss;
  /** out: send window */
  int   send_wnd;
  /** out: congestion window */
  int   cong_wnd;

  /** out: max bytes application can send */
  int   delegated_wnd;

  /** internal */
  int   tcp_seq_offset;  
  /** internal */
  int   ip_len_offset;
  /** internal */
  int   ip_tcp_hdr_len;
  /** internal */
  int   reserved;
};


/*! \brief Return codes for functions in the Delegated Sends API */
enum zf_delegated_send_rc {
  /** Success */
  ZF_DELEGATED_SEND_RC_OK = 0x00,
  /** Insufficient congestion window */
  ZF_DELEGATED_SEND_RC_NOCWIN = 0x01,
  /** Insufficient send window */
  ZF_DELEGATED_SEND_RC_NOWIN = 0x02,
  /** Zocket not in a state to send */
  ZF_DELEGATED_SEND_RC_BAD_SOCKET = 0x83,
  /** headers_size too small (headers_len gives size required) */
  ZF_DELEGATED_SEND_RC_SMALL_HEADER = 0x84,
  /** Zocket has data in send queue */
  ZF_DELEGATED_SEND_RC_SENDQ_BUSY = 0x85,
  /** Remote MAC for peer not known */
  ZF_DELEGATED_SEND_RC_NOARP = 0x86,
};


/*! \brief Mask to test for fatal errors in the Delegated Sends API */
#define ZF_DELEGATED_SEND_RC_FATAL 0x80

/*! \brief Delegate sends to the application
 *
 * \param ts                 TCP zocket
 * \param max_delegated_wnd  Bytes to reserve for future delegated sends
 * \param cong_wnd_override  Minimum congestion window, or zero
 * \param flags              Reserved for future use
 * \param ds                 Structure used for delegated sends
 *
 * \return ZF_DELEGATED_SEND_RC_OK:            Success
 * \return ZF_DELEGATED_SEND_RC_NOCWIN:        Insufficient congestion window
 * \return ZF_DELEGATED_SEND_RC_NOWIN:         Insufficient send window 
 * \return ZF_DELEGATED_SEND_RC_BAD_SOCKET:    Zocket not in a state to send
 * \return ZF_DELEGATED_SEND_RC_SMALL_HEADER:  headers_size too small (headers_len gives size required)
 * \return ZF_DELEGATED_SEND_RC_SENDQ_BUSY:    Zocket has data in send queue
 * \return ZF_DELEGATED_SEND_RC_NOARP:         Remote MAC for peer not known
 *
 * This function delegates sends to the application.
 * It reserves up to @p max_delegated_wnd bytes for future
 * delegated sends, and returns the Ethernet-IP-TCP headers.  The maximum
 * amount of data that the application can send is then returned in
 * ds->delegated_wnd.  Both @p max_delegated_wnd and ds->delegated_wnd are
 * relative to sends already completed.
 *
 * If @p cong_wnd_override is non-zero, it specifies a minimum congestion
 * window.  This call behaves as if the congestion window is the larger of
 * @p cong_wnd_override and the zocket's actual congestion window.
 *
 * Once a send has been completed, call zf_delegated_send_complete() to
 * indicate how many bytes were used, and make further calls to this
 * function to extend the window for delegated sends.
 *
 * If not all the bytes reserved with this call are used then
 * zf_delegated_send_cancel() must be called before further normal sends.
 * A subsequent call to zf_delegated_send_prepare() is safe without calling
 * zf_delegated_send_cancel().
 *
 * When the return code is RC_OK, RC_NOWIN or RC_NOCWIN, the headers
 * and other fields in @p ds are initialised.  This set is indicated
 * by !(rc & ZF_DELEGATED_SEND_RC_FATAL).  When RC_SMALL_HEADER is
 * returned, ds->headers_len is initialised.  In other cases @p ds is
 * not filled in.
 *
 * Note that the delegated window is never reduced by this call, so
 * ds->delegated_wnd may be non-zero even if RC_NOWIN or RC_NOCWIN is
 * returned.
 */
ZF_LIBENTRY enum zf_delegated_send_rc
zf_delegated_send_prepare(struct zft *ts, int max_delegated_wnd,
                          int cong_wnd_override, unsigned flags,
                          struct zf_ds* ds);

                          
/*! \brief Update packet headers with correct data length and PUSH flag 
 *
 * \param ds     Structure used for delegated sends
 * \param bytes  Correct data length
 * \param push   Zero to clear PUSH flag, non-zero to set PUSH flag
 *
 * Update packet headers created by zf_delegated_send_prepare() with
 * correct data length and PUSH flag details.
 *
 * zf_delegated_send_prepare() assumes that the delegated send will be
 * the maximum segment size, and that no PUSH flag will be set in the
 * TCP header.  If this assumption is correct there is no need to call
 * zf_delegated_send_tcp_update().
 */
static inline void
zf_delegated_send_tcp_update(struct zf_ds* ds, int bytes, int push)
{
  uint16_t* ip_len_p;
  uint8_t* tcp_flags_p;

  ip_len_p = (uint16_t*) ((uintptr_t) ds->headers + ds->ip_len_offset);
  *ip_len_p = htons(bytes + ds->ip_tcp_hdr_len);

/** \cond NODOC */
#define TCP_OFFSET_SEQ_TO_FLAGS   9
#define TCP_FLAG_PSH            0x8
/** \endcond */
  tcp_flags_p = (uint8_t*)((uintptr_t) ds->headers + ds->tcp_seq_offset +
                           TCP_OFFSET_SEQ_TO_FLAGS);
  if( push )
    *tcp_flags_p |= TCP_FLAG_PSH;
  else
    *tcp_flags_p &= ~TCP_FLAG_PSH;
#undef TCP_OFFSET_SEQ_TO_FLAGS
#undef TCP_FLAG_PSH
}


/*! \brief Update packet headers to reflect that a packet has been sent
 *
 * \param ds     Structure used for delegated sends
 * \param bytes  Bytes sent
 *
 * Update packet headers created by zf_delegated_send_prepare() to
 * reflect that a packet of length @p bytes has been sent.
 *
 * zf_delegated_send_prepare() reserves a potentially long area for
 * delegated sends.  If these bytes are sent in multiple packets, this
 * function must be used in between each delegated send to update the
 * TCP headers appropriately.
 */
static inline void
zf_delegated_send_tcp_advance(struct zf_ds* ds, int bytes)
{
  uint32_t seq;
  uint32_t* seq_p;

  ds->send_wnd -= bytes;
  ds->cong_wnd -= bytes;
  ds->delegated_wnd -= bytes;

  seq_p = (uint32_t*) ((uintptr_t) ds->headers + ds->tcp_seq_offset);
  seq = ntohl(*seq_p);
  seq += bytes;
  *seq_p = htonl(seq);
}


/*! \brief Notify TCPDirect that some data have been sent via delegated sends
 *
 * \param ts      TCP zocket
 * \param iov     Start of the iovec array describing the packet buffers
 * \param iovlen  Length of the iovec array
 * \param flags   Reserved for future use
 *
 * \return  Number of bytes completed on success (which may be less than the 
            requested number of bytes for partial success)
 * \return  Negative error on failure:\n
 *          -EMSGSIZE: attempt to "complete" more bytes than were "prepared"\n
 *          -EAGAIN: no space on send queue (prepare should already have failed)
 *
 * Notify TCPDirect that some data have been sent via delegated sends.
 * If successful, TCPDirect will handle all further aspects of the TCP
 * protocol (e.g. acknowledgements, retransmissions) for those bytes.
 */
ZF_LIBENTRY int
zf_delegated_send_complete(struct zft *ts, const struct iovec* iov, int iovlen,
                           int flags);


/*! \brief Notify TCPDirect that a reserved set of bytes are no longer required
 *
 * \param ts  TCP zocket
 *
 * \return    0 on success, or negative error on failure
 *
 * Notify TCPDirect that a previously reserved set of bytes (obtained
 * using zf_delegated_send_prepare()) are no longer required.
 *
 * This must be used if the caller has not called
 * zf_delegated_send_complete() for all the bytes reserved.  After
 * successful return, the caller can use other TCPDirect send API
 * calls, or start another delegated send operation with
 * zf_delegated_send_prepare().
 */
ZF_LIBENTRY int
zf_delegated_send_cancel(struct zft *ts);



#endif /* __ZF_DS_H__ */

