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

/****************************************************************************
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2012 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef AOE_AOE_H
#define AOE_AOE_H

#include <linux/module.h>
#include <linux/slab.h>
#include <aoe/amm_streams.h>
#include <mcdi_pcol_aoe.h>

#include "aoe_compat.h"
#include "aoe_ioctl.h"

#include <driverlink_api.h>
#include <bitfield.h>

#define AOE_NAME        "sfc_aoe"
#define MAP_SIZE        32

#define FPGA_LOAD_TIMEOUT	8000 /*ms*/

#define AOE_DEFAULT_MTU		1540

#define NDEBUG 1

#define ECHECK(x)       ((x == NULL) ? -1 : x->idx)

#ifndef NDEBUG
#define DPRINTK(fmt, args...) \
	printk(KERN_INFO "%s-(%d): " fmt, __func__, ECHECK(entry) , ## args)
#define EPRINTK(fmt, args...) \
	printk(KERN_ERR "%s-(%d): " fmt, __func__, ECHECK(entry), ## args)
#else
#define DPRINTK(fmt, args...)   do {} while (0)
#define EPRINTK(fmt, args...) \
	printk(KERN_ERR "%s-(%d): " fmt, __func__, ECHECK(entry), ## args)
#endif

#define AOE_DRIVER_VERSION	"4.4.1.1017"

/* Number of Connections that are allowed to be over the 10G
 * inteface */
#define AOE_INBAND_LIMIT	0

struct aoe_mac_stats {
	u64 tx_bytes;
	u64 tx_good_bytes;
	u64 tx_bad_bytes;
	u64 tx_packets;
	u64 tx_bad;
	u64 tx_pause;
	u64 tx_control;
	u64 tx_unicast;
	u64 tx_multicast;
	u64 tx_broadcast;
	u64 tx_lt64;
	u64 tx_64;
	u64 tx_65_to_127;
	u64 tx_128_to_255;
	u64 tx_256_to_511;
	u64 tx_512_to_1023;
	u64 tx_1024_to_15xx;
	u64 tx_15xx_to_jumbo;
	u64 tx_gtjumbo;
	u64 tx_collision;
	u64 tx_single_collision;
	u64 tx_multiple_collision;
	u64 tx_excessive_collision;
	u64 tx_deferred;
	u64 tx_late_collision;
	u64 tx_excessive_deferred;
	u64 tx_non_tcpudp;
	u64 tx_mac_src_error;
	u64 tx_ip_src_error;
	u64 rx_bytes;
	u64 rx_good_bytes;
	u64 rx_bad_bytes;
	u64 rx_packets;
	u64 rx_good;
	u64 rx_bad;
	u64 rx_pause;
	u64 rx_control;
	u64 rx_unicast;
	u64 rx_multicast;
	u64 rx_broadcast;
	u64 rx_lt64;
	u64 rx_64;
	u64 rx_65_to_127;
	u64 rx_128_to_255;
	u64 rx_256_to_511;
	u64 rx_512_to_1023;
	u64 rx_1024_to_15xx;
	u64 rx_15xx_to_jumbo;
	u64 rx_gtjumbo;
	u64 rx_bad_lt64;
	u64 rx_bad_64_to_15xx;
	u64 rx_bad_15xx_to_jumbo;
	u64 rx_bad_gtjumbo;
	u64 rx_overflow;
	u64 rx_missed;
	u64 rx_false_carrier;
	u64 rx_symbol_error;
	u64 rx_align_error;
	u64 rx_length_error;
	u64 rx_internal_error;
	u64 rx_good_lt64;
	u64 rx_char_error_lane0;
	u64 rx_char_error_lane1;
	u64 rx_char_error_lane2;
	u64 rx_char_error_lane3;
	u64 rx_disp_error_lane0;
	u64 rx_disp_error_lane1;
	u64 rx_disp_error_lane2;
	u64 rx_disp_error_lane3;
	u64 rx_match_fault;
};

enum msg_status {
	AOE_SUCCESS = 0,
	AOE_FAILED,
	AOE_TIMEOUT,
};

enum entry_state {
	CLOSED = 0,
	CLOSING,
	OPENED,
	INITIALISED,
	LENGTH_RECVD,
	COMMAND_RECVD,
	SENDING,
	DATA_NEEDED,
	DATA_PENDING,
	DATA_PENDING_DONE,
	DATA_PENDING_FAILED,
};

enum fpga_state {
	FPGA_OFF = 0,
	FPGA_RESET,
	FPGA_ON,
	FPGA_LOADED,
};

struct aoe_parent_dev {
	unsigned int aoe_major;
	struct class *aoe_class;
	struct device *aoe_dev;
};

struct aoe_proxy_msg {
	size_t req_len;
	size_t resp_len;
	size_t real_resp;
	struct aoe_map_entry *parent;
	unsigned int cmd;
	int mcdi_return_code;
	int (*resp_handler)(struct amm_stream_control *req,
			    struct amm_stream_control *resp,
			    struct aoe_proxy_msg *msg);
	int (*cont_handler)(struct amm_stream_control *resp,
			    struct aoe_proxy_msg *msg);
	void (*encode_handler)(struct amm_stream_control *req,
			       struct aoe_proxy_msg *msg,
			       unsigned int len);
	int status;
	void *chunking_data;
	efx_dword_t *request_data;
	efx_dword_t *response_data;
};

struct aoe_user_buffer {
	unsigned int read_offset;
	unsigned int write_offset;
	unsigned int size;
	unsigned int cmd_len;
	uint8_t *data;
};

struct aoe_device;

#define MAP_ENTRY_NAME_LEN	AMM_COM_NAME_LEN

struct aoe_mmap_entry {
	struct kobject map_kobj;
	struct list_head list;
	uint32_t index;
	uint32_t options;
	uint64_t base_addr;
	uint64_t length;
	uint64_t licence_key;
	uint64_t license_date;
	uint64_t app_info;
	uint32_t comp_info;
	char name[MAP_ENTRY_NAME_LEN];
	struct semaphore write_lock;
	unsigned int operators;
	struct aoe_map_entry *entry;
	uint32_t list_idx;
};

struct aoe_mmap_data {
	unsigned int num_entries;
	struct mutex map_lock;
	struct list_head map_list;
	unsigned int ref;
};

struct aoe_remote_clock {
	struct timespec clock;
	struct timespec limit;
};

struct aoe_dma_area {
	struct list_head next;
	void *h_addr;
	dma_addr_t dma_handle;
	struct dma_pool *source;
	uint64_t aoe_addr;
	uint32_t len;
	uint32_t aoe_len;
	uint32_t flags;
	uint32_t id;
	unsigned int ref;
	unsigned int running;
	struct aoe_remote_clock last_fc_time;
	struct timespec last_sys_time;
	uint8_t *stats_buff;
};

struct aoe_user_dma {
	struct list_head list;
	struct aoe_dma_area *info;
};

/* Need to add a lock here for allocation of message id */
struct aoe_map_entry {
	struct aoe_device *aoe_dev;
	struct aoe_port_info *port;			/* Bound port */
	struct file *file_p;                            /* owner */
	enum entry_state state;                         /* state of entry */
	int mcdi_return_code;                           /* MCDI return code */
	bool remove;
	int seqno;                                      /* id that is placed in request */
	unsigned int response_size;			/* Size the response should total */
	int (*completeMessageSend) (struct aoe_proxy_msg *);     /* completion handler */
	int (*startMessageSend) (struct aoe_map_entry *); /* send handler */
	int (*continueMessageSend) (struct aoe_map_entry *);/* Continue if we were waiting for more data */
	wait_queue_head_t poll_queue;                   /* wait queue for polling */
	wait_queue_head_t read_queue;			/* handle read events */
	struct aoe_user_buffer request;			/* Buffer for request */
	struct aoe_user_buffer response;		/* Buffer for response */
	struct aoe_proxy_msg *messages;			/* Messages that are pending */
	unsigned int pending;				/* Pending messages that are on queue */
	struct aoe_mmap_entry *write_map;		/* Pointer to map in use */
	struct mutex close_lock;			/* lock for close down handling */
	struct list_head dma_list;			/* List of aoe_user_dma blocks in use by this fd */
	struct list_head dev_list;			/* List head for aoe_device.fd_list */
	int idx;
};

struct aoe_netdev;

struct aoe_link_params {
	bool valid;
	int16_t vod;
	int16_t preemp_1posttap;
	int16_t preemp_pretap;
	int16_t preemp_2posttap;
	int16_t dc_gain;
	int16_t eq;
};

struct aoe_port_info {
	struct list_head list;
	int ifindex;
	struct efx_dl_device *dl_dev;
	struct aoe_device *aoe_parent;
	struct kobject port_kobj;
	struct aoe_netdev *int_mac;
	struct aoe_netdev *ext_mac;
	unsigned int mtu;
	void (*update)(struct aoe_port_info *port);
	/* Other information could be placed here */
	struct aoe_link_params params;
	int (*vod)(struct aoe_port_info*, char *buf);
	int (*preemp_1stposttap)(struct aoe_port_info*, char *buf);
	int (*preemp_pretap)(struct aoe_port_info*, char *buf);
	int (*preemp_2ndposttap)(struct aoe_port_info*, char *buf);
	int (*dc_gain)(struct aoe_port_info*, char *buf);
	int (*rx_eq)(struct aoe_port_info*, char *buf);
	unsigned char mac_address[6];
	int (*mac_addr)(struct aoe_port_info*, char *buf);
};

#define DIMM_SPD_LEN 256
#define DIMM_SPD_PAGE_LEN 128
#define DIMM_SPD_PARTNO_LBN 128
#define DIMM_SPD_PARTNO_WIDTH 18

struct aoe_dimm_info {
	struct kobject dimm_kobj;
	uint32_t size;
	uint32_t type;
	bool present;
	bool powered;
	bool operational;
	uint32_t voltage;
	uint8_t spd[DIMM_SPD_LEN];
	struct list_head list;
	struct aoe_device *parent;
	unsigned int id;
	int (*ddr_size)(struct aoe_dimm_info*, char *buf);
	int (*ddr_type)(struct aoe_dimm_info*, char *buf);
	int (*ddr_voltage)(struct aoe_dimm_info*, char *buf);
	int (*ddr_status)(struct aoe_dimm_info*, char *buf);
	int (*ddr_partnum)(struct aoe_dimm_info*, char *buf);
	int (*ddr_spd)(struct aoe_dimm_info*, char *buf);
};

struct aoe_state_info {
	struct kobject state_kobj;
	struct aoe_device *parent;
};

struct aoe_send_queue;

enum aoe_work_type_e {
	AOE_WORK_RELOAD=0,
	AOE_WORK_DDR_ECC,
};

struct aoe_reload_work_params_s {
	unsigned int *null_param;
};

struct aoe_ddr_ecc_work_params_s {
	uint8_t bank_id;
};

union aoe_work_params_u {
	struct aoe_reload_work_params_s reload_work_params;
	struct aoe_ddr_ecc_work_params_s ddr_ecc_work_params;
};

struct aoe_work_struct_s {
	struct work_struct event_work;
	enum aoe_work_type_e work_type;
	union aoe_work_params_u work_params;
};

#define MAX_DMA_AREAS	128
struct aoe_device {
	uint32_t board;
	struct pci_dev *pci_dev;
	struct device *dev;
	struct aoe_mmap_data *fpga_map;
	struct list_head internal_mac_list;
	struct list_head external_mac_list;
	struct list_head nic_ports;
	struct list_head fd_list;
	struct list_head dimms;
	struct list_head dma_blocks;
	struct list_head free_dma_blocks;
	struct aoe_state_info *info;
	struct mutex dma_lock;
	struct dma_pool *small_pool;
	struct dma_pool *med_pool;
	struct dma_pool *large_pool;
	unsigned int free_head;
	wait_queue_head_t event_queue;
	struct aoe_work_struct_s aoe_event_work;
	struct workqueue_struct *event_workwq;
	enum fpga_state state;
	struct kobject aoe_kobj;
	int port_ref;
	int fd_ref;
	int dma_block_count;
	struct mutex dev_lock;
	struct aoe_send_queue *queue;
	bool closed;
	struct aoe_map_entry *bind_unique_fd;
	/* Function pointers for mcdi comms */
	int (*fpga_version)(struct aoe_device *, char *);
	int (*cpld_version)(struct aoe_device *, char *);
	int (*board_rev)(struct aoe_device *, char *);
	int (*fc_version)(struct aoe_device *, char *);
	int (*fpga_build_changeset)(struct aoe_device *, char *);
	int (*fpga_services_version)(struct aoe_device *, char *);
	int (*fpga_services_changeset)(struct aoe_device *, char *);
	int (*fpga_bsp_version)(struct aoe_device *, char *);
	int (*peg_power)(struct aoe_device *, char *);
	int (*cpld_good)(struct aoe_device *, char *);
	int (*fpga_good)(struct aoe_device *, char *);
	int (*fpga_power)(struct aoe_device *, char *);
	int (*bad_sodimm)(struct aoe_device *, char *);
	int (*has_byteblaster)(struct aoe_device *, char *);
	int (*fc_running)(struct aoe_device *, char *);
	int (*boot_result)(struct aoe_device *, char *);
};

/* MAC support */
enum aoe_mac_type {
	AOE_MAC_EXT = 0,
	AOE_MAC_INT,
	AOE_MAC_SIM,
};

struct aoe_stats_buffer {
	void *addr;
	dma_addr_t dma_addr;
	unsigned int len;
};

struct aoe_netdev {
	struct list_head list;
	struct aoe_device *aoe_dev;
	struct net_device *netdev;
	struct aoe_stats_buffer stats_buffer;
	struct aoe_mac_stats mac_stats;
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_USE_NETDEV_STATS)
	struct net_device_stats stats;
#endif
	enum aoe_mac_type mac_type;
	int id;
	unsigned int mtu;
};

#define MAX_BANKS_COUNT MC_CMD_FC_IN_DDR_NUM_BANKS

extern const char *dimm_bank_name[MAX_BANKS_COUNT];

/* Utility functions */
static inline int AOE_PHYS_PORT(struct aoe_port_info *port)
{
	return PCI_FUNC(port->dl_dev->pci_dev->devfn);
}

static inline void aoe_dev_inc(struct aoe_device *dev, int *ref)
{
	mutex_lock(&dev->dev_lock);
	(*ref)++;
	mutex_unlock(&dev->dev_lock);
}

#define aoe_dev_inc_ref(_dev, _ref) \
	aoe_dev_inc(_dev, &_dev->_ref)

static inline int aoe_dev_dec(struct aoe_device *dev, int *ref)
{
	int n_ref;
	mutex_lock(&dev->dev_lock);
	(*ref)--;
	n_ref = *ref;
	mutex_unlock(&dev->dev_lock);
	return n_ref;
}

#define aoe_dev_dec_ref(_dev, _ref) \
	aoe_dev_dec(_dev, &_dev->_ref)

static inline void aoe_dev_inc_and_link(struct aoe_device *dev,
					struct list_head *new_elem,
					struct list_head *list,
					int *ref)
{
	mutex_lock(&dev->dev_lock);
	list_add(new_elem, list);
	(*ref)++;
	mutex_unlock(&dev->dev_lock);
}

#define aoe_dev_inc_and_link_ref(_dev, _new_elem, _list, _ref) \
	aoe_dev_inc_and_link(_dev, _new_elem, _list, &_dev->_ref)

static inline int aoe_dev_dec_and_unlink(struct aoe_device *dev,
				         struct list_head *elem,
					 int *ref)
{
	int n_ref;
        mutex_lock(&dev->dev_lock);
        (*ref)--;
        n_ref = *ref;
	list_del(elem);
        mutex_unlock(&dev->dev_lock);
        return n_ref;
}

#define aoe_dev_dec_and_unlink_ref(_dev, _elem, _ref) \
	aoe_dev_dec_and_unlink(_dev, _elem, &_dev->_ref)

void aoe_entry_inc(struct aoe_map_entry *entry);
int aoe_entry_dec(struct aoe_map_entry *entry);

/* Setup and close down */
int aoe_device_setup(void);
void aoe_device_close(void);

/* Interfaces to driverlink */
int aoe_dl_register(void);
void aoe_dl_unregister(void);
int aoe_dl_send_block_wait(struct aoe_device *dev, struct aoe_proxy_msg *msg);

struct aoe_device * aoe_add_device(struct efx_dl_device *dl_dev,
                                   struct efx_dl_aoe_resources *res,
                                   const struct net_device* net_dev);

void aoe_remove_device(struct efx_dl_device *dl_dev);

/* Queue management functions */
int aoe_qu_add_msg(struct aoe_proxy_msg *msg);
int aoe_qu_setup(struct aoe_device *dev, int queue_size);
void aoe_qu_destroy(struct aoe_device *dev);

/* Interface for MCDI */
void setup_mcdi_handlers(struct aoe_map_entry *entry);
void aoe_mcdi_set_funcs(struct aoe_device *dev);

/* Interface for FAST Ethernet */
void setup_inband_handlers(struct aoe_map_entry *entry);

/* buffer allocation */
void aoe_close_entry(struct aoe_map_entry *entry);
int aoe_alloc_entry(struct aoe_map_entry *entry, unsigned int size);
int aoe_copy_to_req_buff(struct aoe_map_entry *entry,
			 const char __user *data, unsigned int len);
int aoe_copy_from_req_buff(struct aoe_map_entry *entry,
			   void *data,
			   unsigned int len);
int aoe_copy_to_resp_buff(struct aoe_map_entry *entry,
			  void *data,
			  unsigned int len);
int aoe_copy_from_resp_buff(struct aoe_map_entry *entry,
			    char __user *data,
			    unsigned int len,
			    unsigned int *rem);
int aoe_reserve_resp_buff(struct aoe_map_entry *entry, unsigned int len);
int aoe_skip_req_buff(struct aoe_map_entry *entry, unsigned int len);
void aoe_reset_buffers(struct aoe_map_entry *entry);
void aoe_async_close(struct aoe_map_entry *entry);

/* memory map support */
int aoe_fetch_map_count(struct aoe_map_entry *entry);
int aoe_fetch_map_instance(struct aoe_map_entry *entry, int32_t index);
int aoe_process_map_count_resp(struct aoe_map_entry *entry, int count);
int aoe_process_map_index_resp(struct aoe_map_entry *entry,
			       struct aoe_mmap_entry *mmap,
			       bool cache);
int aoe_setup_mmaps(struct aoe_device *to_add);
void aoe_destroy_mmaps(struct aoe_device *dev);
int aoe_verify_map_range_lock(struct aoe_map_entry *entry, uint64_t addr, uint32_t len);
void aoe_release_map_lock(struct aoe_map_entry *entry);
void aoe_flush_mmaps(struct aoe_device *dev);

int aoe_netdev_register(struct aoe_device *dev,
			unsigned int int_macs,
			unsigned int ext_macs);
void aoe_netdev_unregister(struct aoe_device *dev);
int aoe_enable_stats(struct aoe_device *aoe_dev);
void aoe_disable_stats(struct aoe_device *aoe_dev);
unsigned int get_aoe_stats_len(void);
int aoe_mcdi_mac_stats(struct aoe_device *dev, dma_addr_t dma_addr,
		       unsigned int dma_len, int enable, int clear,
		       int index, enum aoe_mac_type type);
int aoe_mcdi_update_stats(__le64 *dma_addr, struct aoe_mac_stats *stats);
int aoe_mcdi_set_siena_override(struct aoe_device *dev, bool state);
int aoe_mcdi_link_status_split(struct aoe_device *dev, uint32_t mode);

/* Event support */
bool aoe_handle_mcdi_event(struct aoe_port_info *port, void *event);
int aoe_mcdi_fpga_reload(struct aoe_device *dev, int partition);
int aoe_apply_static_config(struct aoe_device *dev);
void aoe_remove_static_config(struct aoe_device *dev);
void aoe_mcdi_ddr_ecc_status(struct aoe_device *dev,
			     struct aoe_ddr_ecc_work_params_s *params);
/* Sysfs */
int aoe_sysfs_setup(struct device *parent, struct aoe_device *aoe_instance);
void aoe_sysfs_delete(struct aoe_device *aoe_instance);
int aoe_sysfs_add_map(struct aoe_device *aoe_instance, struct aoe_mmap_entry *map);
void aoe_sysfs_del_map(struct aoe_device *aoe_instance, struct aoe_mmap_entry *map);
int aoe_port_sysfs_setup(struct aoe_device *aoe_instance,
                         struct aoe_port_info *port);
void aoe_mcdi_set_port_funcs(struct aoe_port_info *port);
void aoe_mcdi_set_ddr_funcs(struct aoe_dimm_info *dimm);

/* FPGA information queries */
struct aoe_dev_info {
	uint32_t cpld_idcode;
	uint32_t cpld_version;
	uint32_t fpga_idcode;
	uint32_t fpga_major;
	uint32_t fpga_minor;
	uint32_t fpga_micro;
	uint32_t fpga_build;
	uint32_t fpga_compid;
	uint32_t fpga_type;
	uint32_t fpga_state;
	uint32_t fpga_image;
	uint32_t fc_version[2];
	uint32_t board_rev;
	uint32_t fpga_build_revision;
	bool     fpga_build_type;
	uint32_t fpga_build_changeset[2];
	uint32_t fpga_bsp_version;
	bool	 peg_power;
	bool	 cpld_good;
	bool	 fpga_good;
	bool	 fpga_power;
	bool	 bad_sodimm;
	bool	 has_byteblaster;
	bool	 fc_running;
	uint32_t boot_result;
	/* Other information from the mcdi command can be added
 	 * here as and when it is needed */
};

/* state checks */
static inline bool aoe_data_ready(struct aoe_map_entry *entry)
{
        return (entry->state >= SENDING);
}

static inline bool aoe_data_result_pending(struct aoe_map_entry *entry)
{
	return (entry->state >= DATA_PENDING);
}

static inline bool aoe_data_running(struct aoe_map_entry *entry)
{
        return ((entry->state >= SENDING) && (entry->state < DATA_PENDING));
}

static inline bool aoe_fpga_up(struct aoe_device *dev)
{
        return (dev->state >= FPGA_ON);
}

/* Ioctl */

long aoe_control_ioctl(struct aoe_map_entry *entry, u16 aoe_cmd,
		       struct aoe_ioctl __user *user_data);
int aoe_fd_port_bind(struct aoe_map_entry *entry, int ifindex, uint32_t flags, int *board, int *port);
int aoe_get_num_boards(void);
int aoe_get_num_ports(int board_id, int *num_ports);
int aoe_get_ifindex(int board_id, int port_id, int *ifindex);
int aoe_get_portid(int ifindex, int *board_id, int *port_id);

/* AOE stats support */
int aoe_setup_stats_entry(struct aoe_map_entry *entry,
			  struct aoe_add_dma *req);
int aoe_remove_stats_entry(struct aoe_map_entry *entry,
			   struct aoe_del_dma *req);
int aoe_remove_stats_entries(struct aoe_map_entry *entry);
int aoe_copy_stats_entry(struct aoe_map_entry *entry,
			 struct aoe_read_dma *req);
int aoe_enable_stats_entry(struct aoe_map_entry *entry,
			   struct aoe_enable_dma *req);
int aoe_disable_stats_entries(struct aoe_map_entry *entry);
int aoe_mcdi_timed_read(struct aoe_device *dev,
			struct aoe_dma_area *dma,
			uint16_t op_data,
			uint16_t op_data_offset,
			uint32_t interval,
			bool set);
int aoe_mcdi_clear_timed_read(struct aoe_device *dev,
			      struct aoe_dma_area *Area);
int aoe_mcdi_get_time(struct aoe_device *dev,
		      struct aoe_remote_clock *rem);

int aoe_stats_device_setup(struct aoe_device *aoe_dev);
void aoe_stats_device_destroy(struct aoe_device *aoe_dev);

/* MTU */
int aoe_mcdi_set_mtu(struct aoe_port_info *port, uint32_t aoe_mtu);

/* FD handling */
struct aoe_map_entry* aoe_find_free(void);
void aoe_release_entry(struct aoe_map_entry *entry);


#endif /* AOE_AOE_H */
