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
** \author  Martin Porter 
**  \brief  Work queue implementation for kernel code 
**   \date  Nov 2004
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_driver_efab */
#include <ci/driver/efab/workqueue.h>
#include <ci/driver/efab/debug.h>


/*--------------------------------------------------------------------
 *!
 *
 *--------------------------------------------------------------------*/

/* internal functions */
static void * ci_workqueue_thread(void * context);

/*--------------------------------------------------------------------
 *!
 *
 *--------------------------------------------------------------------*/

static void
ci_workqueue_empty(ci_workqueue_t * wqueue) 
{
  ci_irqlock_state_t lock_flags;
  ci_dllink * link;
  ci_workitem_t * work_item;

  CI_WORKQ_STAT_INC_ITER(wqueue);

  ci_irqlock_lock(&wqueue->lock, &lock_flags);
  while ( ci_dllist_not_empty(&wqueue->list) ) {

    link = ci_dllist_pop(&wqueue->list);
    /* mark the work item as NOT in the list */
    ci_dllink_mark_free(link);
    work_item = CI_CONTAINER(ci_workitem_t, link, link);
#if CI_CFG_WORK_QUEUE_DIAGNOSTICS
    /* record information on what we've called but not yet heard back from */
    memcpy(wqueue->file, work_item->file, CI_CFG_WORK_QUEUE_MAX_FILELEN);
    wqueue->line = work_item->line;
#endif
    CI_WORKQ_STAT_WORKING(wqueue);
    ci_irqlock_unlock(&wqueue->lock, &lock_flags);
    DEBUGVERB( ci_log("%s: about to call work item", __FUNCTION__) );
    work_item = CI_CONTAINER(ci_workitem_t, link, link);

    work_item->routine( work_item->context );

    ci_irqlock_lock(&wqueue->lock, &lock_flags);
    CI_WORKQ_STAT_DONE(wqueue);

#if CI_CFG_WORK_QUEUE_DIAGNOSTICS
    /* no call in progress */
    wqueue->file[0] = 0;
#endif
  }
  ci_irqlock_unlock(&wqueue->lock, &lock_flags);
}


/*--------------------------------------------------------------------
 *!
 * We add this to the work queue to cause the worker thread to windup
 *
 *--------------------------------------------------------------------*/

static void
ci_workqueue_selfdestruct(ci_workqueue_t * wqueue)
{
  DEBUGWQ( ci_log("%s: ", __FUNCTION__) );
  ci_assert(wqueue->state == CI_WQ_DYING);
  wqueue->state = CI_WQ_DEAD;
}

/*--------------------------------------------------------------------
 *!
 * Work queue constructor
 *
 *--------------------------------------------------------------------*/

int 
ci_workqueue_ctor(ci_workqueue_t * wqueue)
{
  int rc;
  DEBUGWQ( ci_log("%s: ", __FUNCTION__) );

  memset(&wqueue->stats, 0, sizeof(wqueue->stats));
  ci_waitq_ctor(&wqueue->worker_wq);
  ci_irqlock_ctor(&wqueue->lock);
  ci_dllist_init(&wqueue->list);

  wqueue->state = CI_WQ_ALIVE;

#if CI_CFG_WORK_QUEUE_DIAGNOSTICS
  wqueue->file[0] = 0;
  wqueue->line = 0;
#endif

  rc = cithread_create(&wqueue->thread, ci_workqueue_thread, wqueue,
                       "onload-wqueue");
  if (rc < 0) {
    /* stop events being added to this queue */
    wqueue->state = CI_WQ_DEAD;
  }
  return rc;
}

/*--------------------------------------------------------------------
 *!
 * Work queue destructor
 *
 *--------------------------------------------------------------------*/

void 
ci_workqueue_dtor(ci_workqueue_t * wqueue)
{
  ci_irqlock_state_t lock_flags;
  ci_workitem_t workitem;

  DEBUGWQ( ci_log("%s: starting", __FUNCTION__) );

  ci_workitem_init(&workitem,
                  (CI_WITEM_ROUTINE)(ci_workqueue_selfdestruct),
                   wqueue);
  /* 
  ** send an event to the work queue to kill itself
  **   - also mark the queue so no further events can be added
  */
  ci_irqlock_lock(&wqueue->lock, &lock_flags);
  wqueue->state = CI_WQ_DYING;
  ci_dllist_push_tail(&wqueue->list, &workitem.link);
  ci_irqlock_unlock(&wqueue->lock, &lock_flags);

  /* wake up the worker thread */
  ci_waitq_wakeup(&wqueue->worker_wq);

  DEBUGWQ( ci_log("%s: waiting for thread to die", __FUNCTION__) );
  cithread_join(wqueue->thread);
  DEBUGWQ( ci_log("%s: thread hopefully dead", __FUNCTION__) );

  ci_assert( ci_dllist_is_empty(&wqueue->list) );

  ci_waitq_dtor(&wqueue->worker_wq);
  ci_irqlock_dtor(&wqueue->lock);
}


/*--------------------------------------------------------------------
 *!
 * This is the thread that services the work queue 
 *
 *--------------------------------------------------------------------*/
 
static void *
ci_workqueue_thread(void * context)
{
  ci_waitq_waiter_t waiter;
  ci_workqueue_t * wqueue = context;

  DEBUGWQ( ci_log("%s: running", __FUNCTION__) );

  /*
  ** Handle race at start-of-day. Two potential issues:
  **  - we call the dtor immediately after the ctor because of a start of 
  **    day failure. The dtor is then racing against the thread starting
  **  - some start of day code posts a work item before the thread is running
  ** In the both these cases we can wakeup the wake queue before we've
  ** got around to sleeping in this thread. Therefore empty queue and check 
  ** state before the initial sleep
  */
  ci_workqueue_empty(wqueue);
  while (CI_WQ_DEAD != wqueue->state) {
  
    ci_waitq_waiter_pre(&waiter, &wqueue->worker_wq);
    if ( ci_dllist_is_empty(&wqueue->list) ) {
      DEBUGVERB( ci_log("%s: waiting", __FUNCTION__));
      ci_waitq_waiter_wait(&waiter, &wqueue->worker_wq, 0);
    }
    ci_waitq_waiter_post(&waiter, &wqueue->worker_wq);
    
    DEBUGVERB( ci_log("%s: woke up", __FUNCTION__));
    ci_workqueue_empty(wqueue);
  } 

  DEBUGWQ( ci_log("%s: dying", __FUNCTION__));
  return 0;
}


/*--------------------------------------------------------------------
 *!
 * External API to add a work item to the work queue
 *
 * \param wqueue        Work queue to add to
 * \param workitem      Work item with "routine" and "context" fields 
 *                      populated
 *
 * \return              standard return codes
 *
 *--------------------------------------------------------------------*/

int
_ci_workqueue_add(ci_workqueue_t * wqueue, ci_workitem_t * workitem)
{
  ci_irqlock_state_t lock_flags;
  int rc;

  ci_assert(CI_WQ_DEAD != wqueue->state);

  ci_irqlock_lock(&wqueue->lock, &lock_flags);
  if (CI_WQ_ALIVE == wqueue->state)  {

    if ( ci_dllink_is_free(&workitem->link) ) {
      DEBUGVERB( ci_log("%s: added work item", __FUNCTION__) );
      rc = 0;
      ci_dllist_push_tail(&wqueue->list, &workitem->link);
      CI_WORKQ_STAT_ENQUEUE(wqueue);
    }
    else {
      DEBUGVERB( ci_log("%s: work item already queued", __FUNCTION__) );
      rc = -EALREADY;
    }
  }
  else {
    ci_log("%s: failed - thread dying", __FUNCTION__);
    rc = -EBUSY;
  }
  ci_irqlock_unlock(&wqueue->lock, &lock_flags);  

  /* wake up the worker thread */
  if (0 == rc)
    ci_waitq_wakeup(&wqueue->worker_wq);

#if CI_CFG_WORK_QUEUE_DIAGNOSTICS
  if (rc == -EALREADY)
    ci_workqueue_dump(wqueue);
#endif

  return rc;
}


/*--------------------------------------------------------------------
 *!
 * We add this to the work queue when flushing the work queue
 *  - it runs in the context of the work queue thread AFTER all items 
 *    in the queue the caller wnated to syncronise against
 *
 *--------------------------------------------------------------------*/

static void
ci_workqueue_selfflush(ci_waitq_t * wakeq)
{
  DEBUGWQ( ci_log("%s: starting", __FUNCTION__) );
  /* just wake up ci_workqueue_flush so it can complete */
  ci_waitq_wakeup(wakeq);
}

/*--------------------------------------------------------------------
 *!
 * Dump the work queue 
 *
 * \param wqueue        Work queue to display
 *
 *--------------------------------------------------------------------*/

#if CI_CFG_WORK_QUEUE_DIAGNOSTICS
void
ci_workqueue_dump(ci_workqueue_t * wqueue)
{
  ci_irqlock_state_t lock_flags;
  ci_workitem_t     * workitem;

  ci_irqlock_lock(&wqueue->lock, &lock_flags);

  ci_log("%s: ---------------", __FUNCTION__);
  if (wqueue->file[0] != 0)
    ci_log("%s: %d - work item not yet returned", 
            wqueue->file, wqueue->line);

  CI_DLLIST_FOR_EACH2(ci_workitem_t, workitem, link, &wqueue->list)
    ci_log("%s: %d - queued", workitem->file, workitem->line);

  ci_irqlock_unlock(&wqueue->lock, &lock_flags);  
}
#endif

/*--------------------------------------------------------------------
 *!
 * External API to flush the work queue 
 *    - waits for any work items pending queued prior to 
 *      the call of this function to run
 *
 * \param wqueue        Work queue to flush
 *
 * \return              standard return codes
 *
 *--------------------------------------------------------------------*/


int
ci_workqueue_flush(ci_workqueue_t * wqueue)
{
  ci_waitq_t        wakeq;
  ci_waitq_waiter_t waiter;
  ci_workitem_t     workitem;
  ci_irqlock_state_t lock_flags;
  ci_timeval_t       tv;
  ci_waitq_timeout_t timeout;
  int rc, remove;

  DEBUGWQ( ci_log("%s: starting", __FUNCTION__) );

  /* 5 second wait - if takes longer then someone has blocked the work queue */
  tv.tv_sec = 5;
  tv.tv_usec = 0;

  /* add ourself to the wake queue */
  ci_waitq_ctor(&wakeq);
  ci_waitq_waiter_pre(&waiter, &wakeq);
  ci_waitq_init_timeout(&timeout, &tv);

  /* get work queue to wake up this wake queue when it runs 
  ** our workitem (which will only run once all pending items in 
  ** the queue have run)
  */
  ci_workitem_init(&workitem,
                  (CI_WITEM_ROUTINE)(ci_workqueue_selfflush),
                   &wakeq);
  rc = ci_workqueue_add(wqueue, &workitem);

  if (rc == 0) {
    ci_waitq_waiter_timedwait(&waiter, &wakeq, 0, &timeout);

    /* if signalled then we can no longer wait
        - this shouldn't really happen but if someone control-C 
          a driver unload ....
       for now all we can do is to remove work item

     */
    if ( ci_waitq_waiter_timedout(&timeout)  ||
         ci_waitq_waiter_signalled(&waiter, &wakeq) )
    {
      if (ci_waitq_waiter_signalled(&waiter, &wakeq) ) {
        DEBUGERR(ci_log("%s: signalled - abandoning wait", __FUNCTION__));
      } 
      else {
        DEBUGERR(ci_log("%s: timedout", __FUNCTION__));
      }
      ci_irqlock_lock(&wqueue->lock, &lock_flags);
      /* if still in the list */
      remove = !ci_dllink_is_free(&workitem.link);
      if (remove) {
        ci_dllist_remove(&workitem.link);
        ci_dllink_mark_free(&workitem.link);
        wqueue->stats.backlog--;
      }
      ci_irqlock_unlock(&wqueue->lock, &lock_flags);
      if (remove)
        DEBUGERR(ci_log("%s:   --> removed flush event", __FUNCTION__));
      /* return error to callee */
      rc = -EINTR;
    }          
  }

  ci_waitq_waiter_post(&waiter, &wakeq);
  ci_waitq_dtor(&wakeq);
  return rc;
}
/*--------------------------------------------------------------------
 *!
 *
 *--------------------------------------------------------------------*/

