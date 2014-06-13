/*
** Copyright 2005-2014  Solarflare Communications Inc.
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
** \author  mwp
**  \brief  Driver work queues
**   \date  2004/11/05
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab */

#ifndef __CI_DRIVER_EFAB_WORKQUEUE_H__
#define __CI_DRIVER_EFAB_WORKQUEUE_H__

#include <ci/driver/internal.h>

#ifndef __ci_driver__
#error workqueues are only intended for driver use
#endif


#define CI_CFG_WORK_QUEUE_DIAGNOSTICS	0
#define CI_CFG_WORK_QUEUE_MAX_FILELEN	64


/*--------------------------------------------------------------------
 *
 * Stats for the workqueue
 *
 *--------------------------------------------------------------------*/

typedef struct {
  
  int working;		/* set if the workqueue is executing a work item */
  int iter;		/* counts number of iterations of work thread */
  int started;		/* counts number of work items started */
  int backlog;		/* workqueue length */
  
} ci_workqueue_stat_t;

#define CI_WORKQ_STAT_INC_ITER(wqueue) \
     do { (wqueue)->stats.iter++; } while(0);

#define CI_WORKQ_STAT_WORKING(wqueue) \
     do { (wqueue)->stats.working = 1; (wqueue)->stats.started++; } while(0);

#define CI_WORKQ_STAT_DONE(wqueue) \
     do { (wqueue)->stats.working = 0; (wqueue)->stats.backlog--; } while(0);

#define CI_WORKQ_STAT_ENQUEUE(wqueue) \
     do { (wqueue)->stats.backlog++; } while(0);


/*--------------------------------------------------------------------
 *
 *
 *--------------------------------------------------------------------*/

typedef void (* CI_WITEM_ROUTINE)(void *);

typedef struct ci_workitem_s
{
  /* function to call with context */
  CI_WITEM_ROUTINE  routine;
  void *            context;

  /* these can be stored in a list */
  ci_dllink         link;

#if CI_CFG_WORK_QUEUE_DIAGNOSTICS
  /* file and line information */
  char file[CI_CFG_WORK_QUEUE_MAX_FILELEN];
  int  line;
#endif
} ci_workitem_t;


/* workitem arg is a place holder to make mapping to Linux API easier */
#define CI_WORKITEM_INITIALISER(workitem, routine, context) \
  { (routine), (context), CI_DLLINK_INITIALISER(0,0) }
#define CI_WORKITEM_SET_CONTEXT(_workitem, _context) \
     do { (_workitem)->context = _context; } while(0);
#define CI_WORKITEM_GET_CONTEXT(workitem) ((workitem)->context)
#define CI_WORKITEM_GET_ROUTINE(workitem) ((workitem)->routine)


typedef struct ci_workqueue_s
{
  /* work queue thread */
  cithread_t thread;

  /*! stats block for the workqueue */
  ci_workqueue_stat_t stats;
  
  /*! use this to wake up the work queue */
  ci_waitq_t      worker_wq;

 /*! thread synchronisation */
  ci_irqlock_t    lock;
  /*! list of work items  */
  ci_dllist       list;

#define CI_WQ_ALIVE     0
#define CI_WQ_DYING     1
#define CI_WQ_DEAD      2
  /*! we set this when we are dying to stop new work items being scheduled */
  volatile int    state;

#if CI_CFG_WORK_QUEUE_DIAGNOSTICS
  /* record information on what we've called but noit yet heard back from */
  char file[CI_CFG_WORK_QUEUE_MAX_FILELEN];
  int  line;
#endif

} ci_workqueue_t;


/*--------------------------------------------------------------------
 *!
 *
 *--------------------------------------------------------------------*/


extern int ci_workqueue_ctor(ci_workqueue_t * wqueue, const char *name);
extern void ci_workqueue_dtor(ci_workqueue_t * wqueue);

ci_inline void
ci_workitem_init(ci_workitem_t * workitem,
                 CI_WITEM_ROUTINE routine, 
                 void * context) 
{
  workitem->routine = routine;
  workitem->context = context;
  ci_dllink_mark_free(&workitem->link);
#if CI_CFG_WORK_QUEUE_DIAGNOSTICS
  file[0] = 0;
  line = 0;
#endif
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

extern int
_ci_workqueue_add(ci_workqueue_t * wqueue, ci_workitem_t * workitem);



/* option to store file and line nuymber of user in work items */
#if CI_CFG_WORK_QUEUE_DIAGNOSTICS
ci_inline int 
_ci_dbg_workqueue_add(ci_workqueue_t * wqueue, 
                      ci_workitem_t * workitem,
                      char * file,
                      int line)
{
  strncpy(workitem->file, file, CI_CFG_WORK_QUEUE_MAX_FILELEN);
  workitem->file[CI_CFG_WORK_QUEUE_MAX_FILELEN-1] = 0;
  workitem->line = line;
  _ci_workqueue_add(wqueue, workitem);
}
#define ci_workqueue_add(wq, wi)    _ci_dbg_workqueue_add(wq, wi, __FILE__, __LINE__)

#else
#define ci_workqueue_add(wq, wi)    _ci_workqueue_add(wq, wi)
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

extern int
ci_workqueue_flush(ci_workqueue_t * wqueue);

/*--------------------------------------------------------------------
 *!
 * Dump the work queue 
 *
 * \param wqueue        Work queue to display
 *
 *--------------------------------------------------------------------*/

#if CI_CFG_WORK_QUEUE_DIAGNOSTICS
extern void
ci_workqueue_dump(ci_workqueue_t * wqueue);
#endif

/*--------------------------------------------------------------------
 *
 *
 *--------------------------------------------------------------------*/

#endif  /* __CI_DRIVER_EFAB_WORKQUEUE_H__ */

/*! \cidoxg_end */
