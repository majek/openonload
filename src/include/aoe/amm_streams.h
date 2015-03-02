/*
** Copyright 2005-2015  Solarflare Communications Inc.
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
** \author  Mike P Smith
**  \brief  AOE control stream types and definitions
**   \date  2012/03/07
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef AMM_STREAMS_H_
#define AMM_STREAMS_H_

#define AMM_COM_NAME_LEN	128

/* -- Definitions for the control stream */
struct amm_ctrl_read_req {
	uint64_t address_be;
	uint32_t data_len_be;
	uint32_t options_be;
};

struct amm_ctrl_read_resp {
	uint64_t address_be;
	uint32_t data_len_be;
	uint32_t options_be;
	uint8_t  data[];
};

struct amm_ctrl_write_req {
	uint64_t address_be;
	uint32_t data_len_be;
	uint32_t options_be;
	uint8_t  data[];
};

struct amm_ctrl_write_resp {
	uint64_t address_be;
	uint32_t data_len_be;
	uint32_t options_be;
};

struct amm_ctrl_read_map_count_req {
	/* -- Nothing */
};

struct amm_ctrl_read_map_count_resp {
	uint32_t count_be;
};

struct amm_ctrl_read_map_req {
	uint32_t index_be;
};

struct amm_ctrl_read_map_resp {
	uint64_t address_be;
        uint64_t length_be;
        uint64_t license_date_be;
	uint32_t index_be;
	uint32_t options_be;
	uint32_t component_id_be;
	uint32_t reserved_be;
	uint8_t app_name[AMM_COM_NAME_LEN];
};

struct amm_ctrl_reg_notification_req {
	uint32_t mask_be;
};

struct amm_ctrl_reg_notification_resp {
	/* -- Nothing */
};

struct amm_ctrl_unreg_notification_req {
	uint32_t mask_be;
};

struct amm_ctrl_unreg_notification_resp {
	/* -- Nothing */
};

struct amm_ctrl_generic_resp {
	/* -- Nothing */
};

struct amm_ctrl_notification_ind {
	uint32_t notification_be;
	uint32_t data_len_be;
	uint8_t  data[];
};

struct amm_ctrl_lock_req {
	uint64_t address;
	uint32_t length;
	uint8_t  options;
};

struct amm_ctrl_lock_resp {
	uint64_t address;
	uint32_t length;
};

struct amm_ctrl_unlock_req {
	uint64_t address;
	uint32_t length;
};

struct amm_ctrl_unlock_resp {
	uint64_t address;
	uint32_t length;
};

struct amm_header {
	uint32_t op_len_be;
	uint8_t  version;
	uint8_t  op;
	uint8_t  result;
	uint8_t  reserved;
};

#define AMM_VERSION 1

struct amm_stream_control {
	struct amm_header	header;

	union {
		struct amm_ctrl_generic_resp		generic;

		struct amm_ctrl_read_req		read_req;
		struct amm_ctrl_read_resp		read_resp;

		struct amm_ctrl_write_req		write_req;
		struct amm_ctrl_write_resp		write_resp;

		struct amm_ctrl_read_map_count_req	read_map_count_req;
		struct amm_ctrl_read_map_count_resp	read_map_count_resp;

		struct amm_ctrl_read_map_req		read_map_req;
		struct amm_ctrl_read_map_resp		read_map_resp;

		struct amm_ctrl_reg_notification_req	reg_notification_req;
		struct amm_ctrl_reg_notification_resp	reg_notification_resp;

		struct amm_ctrl_unreg_notification_req	unreg_notification_req;
		struct amm_ctrl_unreg_notification_resp	unreg_notification_resp;

		struct amm_ctrl_notification_ind 	notification_ind;

		struct amm_ctrl_lock_req		lock_req;
		struct amm_ctrl_lock_resp		lock_resp;

		struct amm_ctrl_unlock_req		unlock_req;
		struct amm_ctrl_unlock_resp		unlock_resp;
	};
};


/* -- Values for the op field */
#define AMM_OP_RESPONSE_FLAG (1 << 7)

#define AMM_OP_READ_REQUEST			1
#define AMM_OP_WRITE_REQUEST			2
#define AMM_OP_READMAPCOUNT_REQUEST		3
#define AMM_OP_READMAP_REQUEST			4
#define AMM_OP_REGISTERNOTIFICATION_REQUEST	5
#define AMM_OP_UNREGISTERNOTIFICATION_REQUEST	6
#define AMM_OP_NOTIFICATION_IND			7
#define AMM_OP_LOCK_REQUEST			8
#define AMM_OP_UNLOCK_REQUEST			9

#define AMM_OP_READ_RESPONSE			(AMM_OP_READ_REQUEST                   | AMM_OP_RESPONSE_FLAG)
#define AMM_OP_WRITE_RESPONSE			(AMM_OP_WRITE_REQUEST                  | AMM_OP_RESPONSE_FLAG)
#define AMM_OP_READMAPCOUNT_RESPONSE		(AMM_OP_READMAPCOUNT_REQUEST           | AMM_OP_RESPONSE_FLAG)
#define AMM_OP_READMAP_RESPONSE			(AMM_OP_READMAP_REQUEST                | AMM_OP_RESPONSE_FLAG)
#define AMM_OP_REGISTERNOTIFICATION_RESPONSE	(AMM_OP_REGISTERNOTIFICATION_REQUEST   | AMM_OP_RESPONSE_FLAG)
#define AMM_OP_UNREGISTERNOTIFICATION_RESPONSE	(AMM_OP_UNREGISTERNOTIFICATION_REQUEST | AMM_OP_RESPONSE_FLAG)
#define AMM_OP_LOCK_RESPONSE			(AMM_OP_LOCK_REQUEST                   | AMM_OP_RESPONSE_FLAG)
#define AMM_OP_UNLOCK_RESPONSE			(AMM_OP_UNLOCK_REQUEST                 | AMM_OP_RESPONSE_FLAG)


/* -- Values for the result field */
#define AMM_RESULT_SUCCESS	0
#define AMM_RESULT_BAD_ADDR	1
#define AMM_RESULT_BAD_LEN	2
#define AMM_RESULT_HARDWARE_ERR	3
#define AMM_RESULT_RESOURCE_ERR	4
#define AMM_RESULT_BAD_INDEX	5

#ifdef NOT_UPSTREAM
typedef struct amm_ctrl_read_req		amm_ctrl_read_req_t;
typedef struct amm_ctrl_read_resp		amm_ctrl_read_resp_t;

typedef struct amm_ctrl_write_req		amm_ctrl_write_req_t;
typedef struct amm_ctrl_write_resp		amm_ctrl_write_resp_t;

typedef struct amm_ctrl_read_map_count_req	amm_ctrl_read_map_count_req_t;
typedef struct amm_ctrl_read_map_count_resp	amm_ctrl_read_map_count_resp_t;

typedef struct amm_ctrl_read_map_req		amm_ctrl_read_map_req_t;
typedef struct amm_ctrl_read_map_resp		amm_ctrl_read_map_resp_t;

typedef struct amm_ctrl_reg_notification_req	amm_ctrl_reg_notification_req_t;
typedef struct amm_ctrl_reg_notification_resp	amm_ctrl_reg_notification_resp_t;

typedef struct amm_ctrl_unreg_notification_req	amm_ctrl_unreg_notification_req_t;
typedef struct amm_ctrl_unreg_notification_resp	amm_ctrl_unreg_notification_resp_t;

typedef struct amm_ctrl_notification_ind	amm_ctrl_notification_ind_t;

typedef struct amm_ctrl_lock_req		amm_ctrl_lock_req_t;
typedef struct amm_ctrl_lock_resp		amm_ctrl_lock_resp_t;

typedef struct amm_ctrl_unlock_req		amm_ctrl_unlock_req_t;
typedef struct amm_ctrl_unlock_resp		amm_ctrl_unlock_resp_t;

typedef struct amm_header			amm_header_t;
typedef struct amm_stream_control		amm_stream_control_t;

#endif

#endif /* AMM_STREAMS_H_ */
