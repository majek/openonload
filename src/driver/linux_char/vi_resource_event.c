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

#include <ci/efrm/vi_resource_manager.h>
#include <ci/efrm/efrm_nic.h>
#include <ci/efrm/efrm_client.h>
#include <ci/driver/efab/hardware.h>
#include <ci/driver/internal.h>
#include <ci/efrm/driver_private.h> /* FIXME for efrm_rm_table */
#include "char_internal.h"


/* The waittable plugin for efrm_vi */
typedef struct eventq_wait_data_s {
  ci_waitable_t    evq_waitable;
  unsigned         evq_wait_current;
  unsigned         evq_wait_request;

  struct efrm_vi   *evq_virs;
} eventq_wait_data_t;

#define efrm_vi_manager \
  ((struct vi_resource_manager *)efrm_rm_table[EFRM_RESOURCE_VI])

static int
eventq_wait_ctor(struct efrm_vi *evq_virs, eventq_wait_data_t **evdata_out)
{
  eventq_wait_data_t *evdata;
  
  ci_assert(evq_virs);
  evdata = kmalloc(sizeof(eventq_wait_data_t), GFP_KERNEL);
  if (evdata == NULL)
    return -ENOMEM;

  ci_waitable_ctor(&evdata->evq_waitable);
  evdata->evq_wait_current = -1;
  evdata->evq_wait_request = -1;
  evdata->evq_virs = evq_virs;

  *evdata_out = evdata;
  return 0;
}

static void
eventq_wait_dtor(eventq_wait_data_t *evdata)
{
  ci_assert(evdata);
  ci_waitable_dtor(&evdata->evq_waitable);
  kfree(evdata);
}

/* This callback is executed in the context of waker */
static void eventq_wait_all(void *arg, int is_timeout, struct efhw_nic *nic)
{
  eventq_wait_data_t *evdata = (eventq_wait_data_t *)arg;

  ci_assert(evdata);
  if (is_timeout) 
    return;
  ci_waitable_wakeup_all(&evdata->evq_waitable);
}


/* This callback is executed in the context of waiter */
ci_inline int
eventq_wait__on_wakeup(ci_waiter_t* waiter, void* opaque_evdata,
                       void* opaque_nic, int rc,
                       ci_waitable_timeout_t timeout)
{
  eventq_wait_data_t *evdata = (eventq_wait_data_t *)opaque_evdata;
  struct efrm_vi* virs = evdata->evq_virs;
  struct efhw_nic* nic = (struct efhw_nic*) opaque_nic;
  unsigned instance;
  struct efrm_nic_per_vi *cb_info;
  unsigned next_i;

  ci_assert(evdata);
  ci_assert(virs);
  ci_assert(efrm_vi_manager);
  instance = virs->rs.rs_instance;
  cb_info = &efrm_nic(nic)->vis[instance];

  next_i = evdata->evq_wait_request;
  if ( rc == 0 && evdata->evq_wait_current != next_i ) {
    int bit;
    /* Post another request and go back to sleep. */
    bit = test_and_set_bit(VI_RESOURCE_EVQ_STATE_WAKEUP_PENDING,
                           &cb_info->state);
    if (bit) {
      /* This indicates that another process is attempting to do a
       * wait. */
      rc = -EBUSY;
    } else {
      ci_waiter_prepare_continue_to_wait(waiter, &evdata->evq_waitable);
      rc = CI_WAITER_CONTINUE_TO_WAIT;

      evdata->evq_wait_current = next_i;
      efhw_nic_wakeup_request(nic, next_i, instance);
    }
  }

  if ( rc != CI_WAITER_CONTINUE_TO_WAIT )
    ci_waiter_post(waiter, &evdata->evq_waitable);

  return rc;
}


int
efab_vi_rm_eventq_wait(struct efrm_vi* virs, unsigned current_ptr,
                       struct ci_timeval_s* timeout_tv
                       CI_BLOCKING_CTX_ARG(ci_blocking_ctx_t bc))
{
  /* We write our current read pointer to the hardware, which compares it
  ** with the write pointer.  If they match, it sets the wakeup bit.
  ** Otherwise it sends us a wakeup event straight-away.
  */
  unsigned mask;
  unsigned next_i;
  ci_waiter_t waiter;
  ci_waitable_timeout_t timeout;
  struct efhw_nic* nic;
  struct efrm_nic_per_vi *cb_info;
  eventq_wait_data_t *evdata;
  int rc, instance, bit;

  ci_assert(virs);
  EFRM_RESOURCE_ASSERT_VALID(&virs->rs, 0);

  if ( virs->q[EFHW_EVQ].capacity == 0 ) {
    EFCH_ERR("%s: ERROR: no on this VI", __FUNCTION__);
    return -EINVAL;
  }

  nic = efrm_client_get_nic(virs->rs.rs_client);

  rc = eventq_wait_ctor(virs, &evdata);
  if (rc < 0)
    return rc;

  mask = virs->q[EFHW_EVQ].capacity - 1;
  next_i = (current_ptr / sizeof(efhw_event_t)) & mask;

  ci_waitable_init_timeout(&timeout, timeout_tv);

  ci_assert(efrm_vi_manager);
  instance = virs->rs.rs_instance;
  cb_info = &efrm_nic(nic)->vis[instance];

  rc = efrm_eventq_register_callback(virs, eventq_wait_all, evdata);
  if (rc < 0)
    goto clear_evdata;

  /* Put ourselves on the wait queue to avoid races. */
  rc = ci_waiter_exclusive_pre(&waiter, &evdata->evq_waitable
                               CI_BLOCKING_CTX_ARG(bc));
  if (rc < 0)
    goto clear_callback;

  bit = test_and_set_bit(VI_RESOURCE_EVQ_STATE_WAKEUP_PENDING, &cb_info->state);
  if (!bit) {
    evdata->evq_wait_current = next_i;
    evdata->evq_wait_request = next_i;
    /* Ask hardware to set wakeup bit / or wake us straight away. */
    efhw_nic_wakeup_request(nic, next_i, virs->rs.rs_instance);
  } else {
    /* There's a pending wakeup.  Just go to sleep.  When the wakeup
     * occurs, we'll check to see whether it's the one we wanted.  */
    if ( evdata->evq_wait_current != next_i )
      EFCH_TRACE("%s: resuming wakeup: evq_wait_current=%d next_i=%d",
                 __FUNCTION__, evdata->evq_wait_current, next_i);
    evdata->evq_wait_request = next_i;
  }

  rc = ci_waiter_wait(&waiter, &evdata->evq_waitable, &timeout,
                      (void*)evdata, (void*)nic, eventq_wait__on_wakeup);

clear_callback:
  efrm_eventq_kill_callback(virs);
clear_evdata:
  eventq_wait_dtor(evdata);
  return rc;
}


