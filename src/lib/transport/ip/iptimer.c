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
** <L5_PRIVATE L5_SOURCE>
** \author  ctk
**  \brief  User level IP timers. 
**   \date  2004/01/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
  
#include "ip_internal.h"
#ifndef __KERNEL__
# include <limits.h>
#endif


#define SAMPLE(n) (n)

#define LPF "IPTIMER "

#define DUMP_TIMER_SUPPORT 1

# define DETAILED_CHECK_TIMERS(ni)


#define LINK2TIMER(lnk)				\
  CI_CONTAINER(ci_ip_timer, link, (lnk))

#define ADDR2TIMER(ni, id)					\
  LINK2TIMER((ci_ni_dllist_link*) CI_NETIF_PTR((ni), (id)))


#if CI_CFG_IP_TIMER_DEBUG

void ci_ip_timer_debug(ci_netif* netif, int timer_id, int param) {
  LOG_ITV(log( LPF "netif=%lx  timer_id=%u  param=%x  now=%u",
	       (unsigned long)netif, timer_id, param, 
	       ci_ip_time_now(netif)));  
}

/* hook in your own function to call when an IP debug timer expires */
void (*ci_ip_timer_debug_fn)(ci_netif*, int, int) = ci_ip_timer_debug;

#endif


/*
** A priority list of timers is maintained using a hierarchical timer
** wheel. See scheme 7 of "Hashed and Hierarchical Timing Wheels:
** Efficient Data Structures for Implementing a Timer Facility" Feb
** '96, Varghese and Lauck.
*/

/* gives a bucket no for a given wheelno */
#define BUCKETNO(wheelno, abs)                          \
        (((abs) >> ((wheelno)*CI_IPTIME_BUCKETBITS)) & CI_IPTIME_BUCKETMASK)

/* get the bucket for a given wheelno and abs */
#define BUCKET(netif, wheelno, abs)                     \
        (&(IPTIMER_STATE((netif))->warray[(wheelno)*CI_IPTIME_BUCKETS + BUCKETNO((wheelno), (abs))]))

#define WHEEL2_MASK         (CI_IPTIME_BUCKETMASK << (CI_IPTIME_BUCKETBITS*3))
#define WHEEL1_MASK         (WHEEL2_MASK + \
                            (CI_IPTIME_BUCKETMASK << (CI_IPTIME_BUCKETBITS*2)))
#define WHEEL0_MASK         (WHEEL1_MASK + \
                            (CI_IPTIME_BUCKETMASK << (CI_IPTIME_BUCKETBITS*1)))


#ifndef __KERNEL__

void ci_ip_timer_state_init_ul(ci_netif *ni)
{
  ci_ip_timer_state* ipts = IPTIMER_STATE(ni);

  ni->ci_ip_time_tick2ms = 
    (double)(1u<<ipts->ci_ip_time_frc2tick)/((double)ipts->khz);
}

#endif


#ifdef __KERNEL__ 

static int shift_for_gran(ci_uint32 G, unsigned khz) 
{ 
  unsigned tmp;
  unsigned shft;

  /*
  ** For granularity G (in us) wish to find the least n such that:
  **   khz*G/1000 < 2^n
  ** this gives use the number of bits to shift right in order to get 
  ** convert from the free running CPU counter to our representation
  ** of ticks.
  **
  ** This should be possible (i.e. no 32bit integer arithmetic
  ** under/overflow) for CPUs clocked between 1Mhz to 10 Ghz at a
  ** granularity of 1us through 100ms.
  */
  
  /* attempt to cut down on integer arithmetic problems, if we ever
  ** want really fine grained timers (<1ms) on a 1MHz machine (: */
  if( G < 1000 ) {
    tmp = (khz/1000)*G;
  } else {
    tmp = khz*(G/1000);
  }

  /* calculate scaling factor for CPU ticks to our ticks */
  shft = 0;
  while( tmp >= (1u << shft) ) {
    shft++; 
    if(shft == CI_IP_TIME_MAX_FRCSHIFT) break;
  }
  return shft;
}


/* initialise the iptimer scheduler */
void ci_ip_timer_state_init(ci_netif* netif, unsigned cpu_khz)
{
  ci_ip_timer_state* ipts = IPTIMER_STATE(netif);
  int i;

  /* initialise the cycle to tick constants */
  ipts->khz = cpu_khz;
  ipts->ci_ip_time_frc2tick = shift_for_gran(CI_IP_TIME_APP_GRANULARITY, ipts->khz);
  ipts->ci_ip_time_frc2us = shift_for_gran(1, ipts->khz);
  ci_ip_time_initial_sync(ipts);
  ipts->sched_ticks = ci_ip_time_now(netif);

  /* set module specific time constants dependent on frc2tick */
  ci_tcp_timer_init(netif);

  ci_ni_dllist_init(netif, &ipts->fire_list,
		    oo_ptr_to_statep(netif, &ipts->fire_list),
                    "fire");
  
  /* Initialise the wheel lists. */
  for( i=0; i < CI_IPTIME_WHEELSIZE; i++)
    ci_ni_dllist_init(netif, &ipts->warray[i],
		      oo_ptr_to_statep(netif, &ipts->warray[i]),
                      "timw");
}
#endif /* __KERNEL */


/* insert a non-pending timer into the scheduler */
void __ci_ip_timer_set(ci_netif *netif, ci_ip_timer *ts, ci_iptime_t t)
{
  ci_ni_dllist_t* bucket;
  int w;
  ci_iptime_t stime = IPTIMER_STATE(netif)->sched_ticks;

  ci_assert(TIME_GT(t, stime));
  /* this is absolute time */
  ts->time = t;

  /* Previous error in this code was to choose wheel based on time delta 
   * before timer fires (ts->time - stime). This is bogus as the timer wheels
   * work like a clock and we need to find wheel based on the absolute time
   */

  /* insert in wheel 0 if the top 3 wheels have the same time */
  if ((stime & WHEEL0_MASK) == (t & WHEEL0_MASK))
    w = 0;
  /* else, insert in wheel 1 if the top 2 wheels have the same time */
  else if ((stime & WHEEL1_MASK) == (t & WHEEL1_MASK))
    w = 1;
  /* else, insert in wheel 2 if the top wheel has the same time */
  else if ((stime & WHEEL2_MASK) == (t & WHEEL2_MASK))
    w = 2;
  else
    w = 3;

  bucket = BUCKET(netif, w, t);

  LOG_ITV(log("%s: delta=0x%x (t=0x%x-s=0x%x), w=0x%x, b=0x%x", 
         __FUNCTION__, 
         ts->time-stime, ts->time, stime, 
         w, BUCKETNO(w, ts->time)));

  /* append onto the correct bucket 
  **
  ** NB this might not be stable because a later insert with a
  ** smaller relative time will be before an earlier insert with a
  ** larger relative time. Oh well doesn't really matter
  */
  ci_ni_dllist_push_tail(netif, bucket, &ts->link);

  ci_assert(ci_ip_timer_is_link_valid(netif, ts));
  DETAILED_CHECK_TIMERS(netif);
}


/* take the bucket corresponding to time t in the given wheel and 
** reinsert them back into the wheel (i.e. into wheelno -1)
*/
static void ci_ip_timer_cascadewheel(ci_netif* netif, int wheelno, 
				     ci_iptime_t stime)
{
  ci_ip_timer* ts;
  ci_ni_dllist_t* bucket;
  oo_p curid, buckid;

  ci_assert(wheelno > 0 && wheelno < CI_IPTIME_WHEELS);
  /* check time is on the boundary expected by the wheel number passed in */
  ci_assert( (stime & ((unsigned)(-1) << (CI_IPTIME_BUCKETBITS*wheelno))) == stime );

  /* bucket to empty */
  bucket = BUCKET(netif, wheelno, stime);
  buckid = ci_ni_dllist_link_addr(netif, &bucket->l);
  curid = bucket->l.next;

  LOG_ITV(log(LN_FMT "cascading wheel=%u sched_ticks=0x%x bucket=%i",
	      LN_PRI_ARGS(netif), wheelno, stime, BUCKETNO(wheelno, stime)));

  /* ditch the timers in this dll, pointers held in curid and buckid */
  ci_ni_dllist_init(netif, bucket,
                    ci_ni_dllist_link_addr(netif, &bucket->l), "timw");

  while( ! OO_P_EQ(curid, buckid) ) {
    ts = ADDR2TIMER(netif, curid);
    
    /* get next in linked list */
    curid = ts->link.next;

#ifndef NDEBUG
    {
      /* if inserting in wheel 0 - top 3 wheels must have the same time */
      if (wheelno == 1)
        ci_assert( (stime & WHEEL0_MASK) == (ts->time & WHEEL0_MASK) );
      /* else, if inserting in wheel 1 - top 2 wheels must have the same time */
      else if (wheelno == 2)
        ci_assert( (stime & WHEEL1_MASK) == (ts->time & WHEEL1_MASK) );
      /* else, if inserting in wheel 2 - the top wheel must have the same time */
      else {
        ci_assert(wheelno == 3);
        ci_assert( (stime & WHEEL2_MASK) == (ts->time & WHEEL2_MASK) );
      }
    }    
#endif

    /* insert ts into wheel below */
    bucket = BUCKET(netif, wheelno-1, ts->time);

    /* append onto the correct bucket 
    **
    ** NB this might not be stable because a later insert with a
    ** smaller relative time will be before an earlier insert with a
    ** larger relative time. Oh well doesn't really matter
    */
    ci_ni_dllist_push_tail(netif, bucket, &ts->link);
    ci_assert(ci_ip_timer_is_link_valid(netif, ts));
  }
}

/* unpick the ci_ip_timer structure to actually do the callback */ 
static void ci_ip_timer_docallback(ci_netif *netif, ci_ip_timer* ts)
{
  ci_assert( TIME_LE(ts->time, ci_ip_time_now(netif)) );
  ci_assert( ts->time == IPTIMER_STATE(netif)->sched_ticks );

  switch(ts->fn){
  case CI_IP_TIMER_TCP_RTO:
    CHECK_TS(netif, SP_TO_TCP(netif, ts->param1));
    ci_tcp_timeout_rto(netif, SP_TO_TCP(netif, ts->param1));
    break;
  case CI_IP_TIMER_TCP_DELACK:
    CHECK_TS(netif, SP_TO_TCP(netif, ts->param1));
    ci_tcp_timeout_delack(netif, SP_TO_TCP(netif, ts->param1));
    break;
  case CI_IP_TIMER_TCP_ZWIN:
    CHECK_TS(netif, SP_TO_TCP(netif, ts->param1));
    ci_tcp_timeout_zwin(netif, SP_TO_TCP(netif, ts->param1));
    break;
  case CI_IP_TIMER_TCP_KALIVE:
    CHECK_TS(netif, SP_TO_TCP(netif, ts->param1));
    ci_tcp_timeout_kalive(netif, SP_TO_TCP(netif, ts->param1));
    break;
  case CI_IP_TIMER_TCP_LISTEN:
    ci_tcp_timeout_listen(netif, SP_TO_TCP_LISTEN(netif, ts->param1));    
    break;
  case CI_IP_TIMER_TCP_CORK:
    ci_tcp_timeout_cork(netif, SP_TO_TCP(netif, ts->param1));
    break;
  case CI_IP_TIMER_NETIF_TIMEOUT:
    ci_netif_timeout_state(netif);
    break;
  case CI_IP_TIMER_PMTU_DISCOVER:
    ci_pmtu_timeout_pmtu(netif, SP_TO_TCP(netif, ts->param1));
    break;
  case CI_IP_TIMER_PMTU_DISCOVER_2:
    ci_pmtu_timeout_pmtu_2(netif, SP_TO_UDP(netif, ts->param1));
    break;
#if CI_CFG_TAIL_DROP_PROBE
  case CI_IP_TIMER_TCP_TAIL_DROP:
    ci_tcp_timeout_taildrop(netif, SP_TO_TCP(netif, ts->param1));
    break;
#endif
#if CI_CFG_TCP_SOCK_STATS
  case CI_IP_TIMER_TCP_STATS:
	ci_tcp_stats_action(netif, SP_TO_TCP(netif, ts->param1), 
                        CI_IP_STATS_FLUSH, 
                        CI_IP_STATS_OUTPUT_NONE, NULL, NULL );
    break;
#endif
#if CI_CFG_SUPPORT_STATS_COLLECTION
  case CI_IP_TIMER_NETIF_STATS:
    ci_netif_stats_action(netif, CI_IP_STATS_FLUSH,
                          CI_IP_STATS_OUTPUT_NONE, NULL, NULL );
    break;
#endif
#if CI_CFG_IP_TIMER_DEBUG
  case CI_IP_TIMER_DEBUG_HOOK:
    ci_ip_timer_debug_fn(netif, ts->link.addr, ts->param1);
    break;
#endif
  default:
    LOG_U(log( LPF "unknown timer callback code:%x param1:%d",
	       ts->fn, OO_SP_FMT(ts->param1)));    
    CI_DEBUG(ci_fail_stop_fn());
  }  
}

/* run any pending timers */
void ci_ip_timer_poll(ci_netif *netif) {
  ci_ip_timer_state* ipts = IPTIMER_STATE(netif); 
  ci_iptime_t* stime = &ipts->sched_ticks;
  ci_ip_timer* ts;
  ci_iptime_t rtime;
  ci_ni_dllist_link* link;

  /* The caller is expected to ensure that the current time is sufficiently
  ** up-to-date.
  */
  rtime = ci_ip_time_now(netif);
  /* check for sanity i.e. time always goes forwards */
  ci_assert( TIME_GE(rtime, *stime) );

  /* bug chasing Bug 2855 - check the temp list used is OK before we start */
  ci_assert( ci_ni_dllist_is_valid(netif, &ipts->fire_list.l) );
  ci_assert( ci_ni_dllist_is_empty(netif, &ipts->fire_list));

  while( TIME_LT(*stime, rtime) ) {

    DETAILED_CHECK_TIMERS(netif);

    /* advance the schedulers view of time */
    (*stime)++;

    /* cascade through wheels if reached end of current wheel */
    if(BUCKETNO(0, *stime) == 0) {
      if(BUCKETNO(1, *stime) == 0) {
	if(BUCKETNO(2, *stime) == 0) {
	  ci_ip_timer_cascadewheel(netif, 3, *stime);
	}
	ci_ip_timer_cascadewheel(netif, 2, *stime);
      }
      ci_ip_timer_cascadewheel(netif, 1, *stime);
    }


    /* Bug 1828: We need to be creaful here ... because:
        - ci_ip_timer_docallback can set/clear timers
        - the timers being set/cleared may not necessarily be the ones firing
        - however, they could be in this bucket
       In summary, need to ensure the ni_dllist stays valid at all times so 
       safe to call. Slightly complicated by the case that its not possible to
       hold indirected linked lists on the stack */
    ci_assert( ci_ni_dllist_is_valid(netif, &ipts->fire_list.l));
    ci_assert( ci_ni_dllist_is_empty(netif, &ipts->fire_list));

    /* run timers in the current bucket */
    ci_ni_dllist_rehome( netif,
                         &ipts->fire_list,
                         &ipts->warray[BUCKETNO(0, *stime)] );
    DETAILED_CHECK_TIMERS(netif);

    while( (link = ci_ni_dllist_try_pop(netif, &ipts->fire_list)) ) {

      ts = LINK2TIMER(link);

      ci_assert_equal(ts->time, *stime);

      /* ensure time marked as NOT pending */
      ci_ni_dllist_self_link(netif, &ts->link);

      /* callback safe to set/clear this or other timers */
      ci_ip_timer_docallback(netif, ts);
    }
    ci_assert( ci_ni_dllist_is_valid(netif, &ipts->fire_list.l) );
    ci_assert( ci_ni_dllist_is_empty(netif, &ipts->fire_list));

    DETAILED_CHECK_TIMERS(netif);
  }
  
  ci_assert( ci_ni_dllist_is_valid(netif, &ipts->fire_list.l) );
  ci_assert( ci_ni_dllist_is_empty(netif, &ipts->fire_list));
}


#ifndef NDEBUG

void ci_ip_timer_state_assert_valid(ci_netif* ni, const char* file, int line)
{
  ci_ip_timer_state* ipts;
  ci_ip_timer* ts;
  ci_ni_dllist_t* bucket;
  ci_ni_dllist_link* l;
  ci_iptime_t stime, wheel_base, max_time, min_time;
  int a1, a2, a3, w, b, bit_shift;

  /* shifting a 32 bit integer left or right 32 bits has undefined results 
   * (i.e. not 0 which is required). Therefore I now use an array of mask 
   * values 
   */
  unsigned wheel_mask[CI_IPTIME_WHEELS] = 
                { WHEEL0_MASK, WHEEL1_MASK, WHEEL2_MASK, 0 };

  ipts = IPTIMER_STATE(ni);
  stime = ipts->sched_ticks;
  
  /* for each wheel */
  for(w=0; w < CI_IPTIME_WHEELS; w++) {

    /* base time of wheel */
    wheel_base = stime & wheel_mask[w];
    /* for each bucket in wheel */
    for (b=0; b < CI_IPTIME_BUCKETS; b++) {

      /* max and min relative times for this bucket */
      bit_shift = CI_IPTIME_BUCKETBITS*w;
      min_time = wheel_base + (b << bit_shift);
      max_time = min_time   + (1 << bit_shift);

      bucket = &ipts->warray[w*CI_IPTIME_BUCKETS + b];

      /* check list looks valid */
      if ( ci_ni_dllist_start(ni, bucket) == ci_ni_dllist_end(ni, bucket) ) {
        ci_assert( ci_ni_dllist_is_empty(ni, bucket) );
      }

      /* check buckets that should be empty are! */
      a3 = TIME_GT(min_time, stime) || ci_ni_dllist_is_empty(ni, bucket);

      /* run through timers in bucket */
      for (l = ci_ni_dllist_start(ni, bucket);
           l != ci_ni_dllist_end(ni, bucket);
           ci_ni_dllist_iter(ni, l) ) {

        ci_ni_dllist_link_assert_valid(ni, l);

        /* get timer */  
        ts = LINK2TIMER(l);

        /* must be in the future */
        a1 = TIME_GT(ts->time, stime);
        /* must be within time range of bucket */
        a2 = TIME_LT(ts->time, max_time) && TIME_GE(ts->time, min_time);

        /* if any of the checks fail then print out timer details */
        if (!a1 || !a2 || !a3) {
          ci_log("%s: [w=0x%x/b=0x%x] stime=0x%x", __FUNCTION__, w, b, stime);
          ci_log("    --> t=0x%x, min=0x%x, max=0x%x", ts->time, min_time, max_time);
          ci_log("    [%s line=%d]", file, line);
        }
        /* stop if assertion failed */
        ci_assert(a1 && a2 && a3);
      }
    }
  }
}

#endif

#ifdef DUMP_TIMER_SUPPORT 
static char *
ci_ip_timer_dump(ci_ip_timer* ts)
{
  char * timer_name;
  static char unknown_timer[20];

  switch (ts->fn) {

    #undef MAKECASE
    #define MAKECASE(id, name) case id: timer_name = name; break;

    MAKECASE(CI_IP_TIMER_TCP_RTO,      "rto")
    MAKECASE(CI_IP_TIMER_TCP_DELACK,   "delack")
    MAKECASE(CI_IP_TIMER_TCP_ZWIN,     "zwin")
    MAKECASE(CI_IP_TIMER_TCP_KALIVE,   "kalive")
    MAKECASE(CI_IP_TIMER_TCP_LISTEN,   "listen")
    MAKECASE(CI_IP_TIMER_TCP_CORK,     "cork")
    MAKECASE(CI_IP_TIMER_NETIF_TIMEOUT, "netif")
    MAKECASE(CI_IP_TIMER_PMTU_DISCOVER, "pmtu")
#if CI_CFG_SUPPORT_STATS_COLLECTION
    MAKECASE(CI_IP_TIMER_TCP_STATS,     "tcp-stats")
    MAKECASE(CI_IP_TIMER_NETIF_STATS,   "ni-stats")
#endif
#if CI_CFG_TAIL_DROP_PROBE
    MAKECASE(CI_IP_TIMER_TCP_TAIL_DROP, "taildrop")
#endif
#if CI_CFG_IP_TIMER_DEBUG
    MAKECASE(CI_IP_TIMER_DEBUG_HOOK,     "debug")
#endif
    default:
        sprintf(unknown_timer, "unk=%d", ts->fn);
        timer_name = unknown_timer;
        break;
    #undef MAKECASE
  }  
  return timer_name;
}


void ci_ip_timer_state_dump(ci_netif* ni)
{
  ci_ip_timer_state* ipts;
  ci_ip_timer* ts;
  ci_ni_dllist_t* bucket;
  ci_ni_dllist_link* l;
  ci_iptime_t stime, wheel_base, max_time, min_time;
  int w, b, bit_shift;

  /* shifting a 32 bit integer left or right 32 bits has undefined results 
   * (i.e. not 0 which is required). Therefore I now use an array of mask 
   * values 
   */
  unsigned wheel_mask[CI_IPTIME_WHEELS] = 
                { WHEEL0_MASK, WHEEL1_MASK, WHEEL2_MASK, 0 };

  ipts = IPTIMER_STATE(ni);
  stime = ipts->sched_ticks;

  ci_log("%s: time is 0x%x", __FUNCTION__, stime);
  /* for each wheel */
  for(w=0; w < CI_IPTIME_WHEELS; w++) {

    /* base time of wheel */
    wheel_base = stime & wheel_mask[w];
    /* for each bucket in wheel */
    for (b=0; b < CI_IPTIME_BUCKETS; b++) {

      /* max and min relative times for this bucket */
      bit_shift = CI_IPTIME_BUCKETBITS*w;
      min_time = wheel_base + (b << bit_shift);
      max_time = min_time   + (1 << bit_shift);

      bucket = &ipts->warray[w*CI_IPTIME_BUCKETS + b];

      /* check buckets that should be empty are! */
      if ( TIME_LE(min_time, stime) && !ci_ni_dllist_is_empty(ni, bucket) )
        ci_log("w:%d, b:%d, [0x%x->0x%x] - bucket should be empty",  
                w, b, min_time, max_time);

      /* run through timers in bucket */
      for (l = ci_ni_dllist_start(ni, bucket);
           l != ci_ni_dllist_end(ni, bucket);
           ci_ni_dllist_iter(ni, l) ) {

        /* get timer */  
        ts = LINK2TIMER(l);

        ci_log(" ts = 0x%x %s  w:%d, b:%d, [0x%x->0x%x]",
               ts->time, ci_ip_timer_dump(ts), w, b, min_time, max_time);
        if ( TIME_LE(ts->time, stime) )
          ci_log("    ERROR: timer before current time");
        if ( !(TIME_LT(ts->time, max_time) && TIME_GE(ts->time, min_time)) )
          ci_log("    ERROR: timer in wrong bucket");
      }
    }
  }
  ci_log("----------------------");
}
#endif


/*! \cidoxg_end */
