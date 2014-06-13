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

/*
** Copyright 2005-2014  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are
** met:
**
** * Redistributions of source code must retain the above copyright notice,
**   this list of conditions and the following disclaimer.
**
** * Redistributions in binary form must reproduce the above copyright
**   notice, this list of conditions and the following disclaimer in the
**   documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
** IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
** TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
** PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
** HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
** TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
** PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
** LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
** NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


/* efrss
 *
 * Forward packets between two interfaces without modification, spreading
 * the load over multiple VIs and threads.
 *
 * 2011 Solarflare Communications Inc.
 * Author: David Riddoch
 * Date: 2011/04/14
 */

#define _GNU_SOURCE

#include "efvi_sfw.h"

#include <sched.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>
#include <string.h>


#define LOGE(x)  do{ x; }while(0)         /* errors */
#define LOGW(x)  do{ x; }while(0)         /* warnings */
#define LOGS(x)  do{ x; }while(0)         /* setup */
#define LOGI(x)  do{}while(0)             /* info */


struct global;


enum thread_state {
  thread_new,
  thread_initialising,
  thread_running,
  thread_finished,
};


struct thread {
  struct global*    global;
  int               id;
  pthread_t         pthread_id;
  cpu_set_t         cpus;
  enum thread_state state;
  struct vi**       vis;
  int               vis_n;
  struct vi**       fwd_map;
  int               n_rx;
};


struct global {
  int                threads_n;
  struct thread**    threads;
  int                net_ifs_max;
  int                net_ifs_n;
  struct net_if** net_ifs;
  pthread_mutex_t    mutex;
  pthread_cond_t     condvar;
};

/**********************************************************************/

static void handle_rx(struct thread* thread, struct vi* vi,
                      int pkt_buf_i, int len)
{
  struct pkt_buf* pkt_buf;
  struct vi* send_vi;
  int rc;

  LOGI(fprintf(stderr, "[%d,%s] INFO: received pkt=%d len=%d\n",
               thread->id, vi->interface, pkt_buf_i, len));

  pkt_buf = pkt_buf_from_id(vi, pkt_buf_i);
  send_vi = thread->fwd_map[vi->id];
  rc = vi_send(send_vi, pkt_buf, RX_PKT_OFF(vi), len);
  if( rc != 0 ) {
    assert(rc == -EAGAIN);
    /* TXQ is full.  A real app might consider implementing an overflow
     * queue in software.  We simply choose not to send.
     */
    LOGW(fprintf(stderr, "[%d,%s] WARNING: dropped send\n",
                 thread->id, send_vi->net_if->name));
  }
  pkt_buf_release(pkt_buf);
  ++thread->n_rx;
}


static void handle_rx_discard(struct thread* thread, struct vi* vi,
                              int pkt_buf_i, int discard_type)
{
  struct pkt_buf* pkt_buf;

  LOGE(fprintf(stderr, "[%d,%s] ERROR: discard type=%d\n",
               thread->id, vi->net_if->name, discard_type));

  pkt_buf = pkt_buf_from_id(vi, pkt_buf_i);
  pkt_buf_release(pkt_buf);
}


static void complete_tx(struct thread* thread, int vi_i, int pkt_buf_i)
{
  struct pkt_buf* pkt_buf;
  assert(vi_i < thread->vis_n);
  pkt_buf = pkt_buf_from_id(thread->vis[vi_i], pkt_buf_i);
  pkt_buf_release(pkt_buf);
}


static void thread_set_state(struct thread* thread, enum thread_state state)
{
  TEST(pthread_mutex_lock(&thread->global->mutex) == 0);
  thread->state = state;
  TEST(pthread_mutex_unlock(&thread->global->mutex) == 0);
  pthread_cond_broadcast(&thread->global->condvar);
}


static void thread_main_loop(struct thread* thread)
{
  ef_request_id ids[EF_VI_TRANSMIT_BATCH];
  ef_event evs[16];
  struct vi* vi;
  int i, j, n, n_ev, vi_i = 0;

  thread_set_state(thread, thread_running);

  while( thread->state == thread_running ) {
    vi = thread->vis[vi_i];
    vi_i = (vi_i + 1) % thread->vis_n;

    n_ev = ef_eventq_poll(&vi->vi, evs, sizeof(evs) / sizeof(evs[0]));
    if( n_ev <= 0 )
      continue;

    for( i = 0; i < n_ev; ++i ) {
      switch( EF_EVENT_TYPE(evs[i]) ) {
      case EF_EVENT_TYPE_RX:
        /* This code does not handle jumbos. */
        assert(EF_EVENT_RX_SOP(evs[i]) != 0);
        assert(EF_EVENT_RX_CONT(evs[i]) == 0);
        handle_rx(thread, vi, EF_EVENT_RX_RQ_ID(evs[i]),
                  EF_EVENT_RX_BYTES(evs[i]));
        break;
      case EF_EVENT_TYPE_TX:
        n = ef_vi_transmit_unbundle(&vi->vi, &evs[i], ids);
        for( j = 0; j < n; ++j )
          complete_tx(thread, TX_RQ_ID_VI(ids[j]), TX_RQ_ID_PB(ids[j]));
        break;
      case EF_EVENT_TYPE_RX_DISCARD:
        handle_rx_discard(thread, vi, EF_EVENT_RX_DISCARD_RQ_ID(evs[i]),
                          EF_EVENT_RX_DISCARD_TYPE(evs[i]));
        break;
      default:
        LOGE(fprintf(stderr, "[%d] ERROR: unexpected event type=%d\n",
                     thread->id, (int) EF_EVENT_TYPE(evs[i])));
        break;
      }
    }
    vi_refill_rx_ring(vi);
  }

  thread_set_state(thread, thread_finished);
}


void* thread_fn(void* arg)
{
  struct thread* thread = arg;
  struct global* global = thread->global;
  int i, j;

  assert(thread->state == thread_new);
  thread_set_state(thread, thread_initialising);

  TEST(sched_setaffinity(0, sizeof(thread->cpus), &thread->cpus) == 0);

  /* Allocate a VI for each interface. */
  assert(thread->vis_n == 0);
  for( i = 0; i < global->net_ifs_n; ++i ) {
    thread->vis[i] = vi_alloc_from_set(i, global->net_ifs[i], thread->id);
    ++thread->vis_n;
    LOGS(fprintf(stderr, "[%d] vi[%d]=%d\n", thread->id, i,
                 ef_vi_instance(&thread->vis[i]->vi)));
  }

  /* Map each VIs packet pool into the other interfaces' protection domains
   * so that we can use packet buffers from one VI's pool with other
   * interfaces.
   */
  for( i = 0; i < global->net_ifs_n; ++i )
    for( j = 0; j < thread->vis_n; ++j )
      if( thread->vis[j]->net_if != global->net_ifs[i] )
        net_if_map_vi_pool(global->net_ifs[i], thread->vis[j]);

  for( i = 0; i < thread->vis_n; ++i )
    thread->fwd_map[i] = thread->vis[(i + 1) % thread->vis_n];

  thread_main_loop(thread);

  return NULL;
}


static struct thread* thread_alloc(struct global* global, int id)
{
  struct thread* thread;
  thread = calloc(1, sizeof(*thread));
  thread->global = global;
  thread->id = id;
  CPU_ZERO(&thread->cpus);
  thread->state = thread_new;
  thread->vis = calloc(global->net_ifs_max, sizeof(thread->vis[0]));
  thread->fwd_map = calloc(global->net_ifs_max, sizeof(thread->fwd_map[0]));
  return thread;
}

/**********************************************************************/

static struct global* global_alloc(int n_threads, int n_net_ifs)
{
  struct global* global = calloc(1, sizeof(*global));
  global->threads_n = n_threads;
  global->threads = calloc(global->threads_n, sizeof(global->threads[0]));

  global->net_ifs_max = n_net_ifs;
  global->net_ifs_n = 0;
  global->net_ifs = calloc(global->net_ifs_max,
                              sizeof(global->net_ifs[0]));

  TEST(pthread_mutex_init(&global->mutex, NULL) == 0);
  TEST(pthread_cond_init(&global->condvar, NULL) == 0);

  return global;
}


static void global_add_net_if(struct global* global,
                                 struct net_if* net_if)
{
  TEST(global->net_ifs_n < global->net_ifs_max);
  global->net_ifs[global->net_ifs_n++] = net_if;
}

/**********************************************************************/

static void monitor(struct global* global)
{
  /* Print approx packet rate for each thread every second. */

  struct timeval start, end;
  int* prev = calloc(global->threads_n, sizeof(int));
  int* now = calloc(global->threads_n, sizeof(int));
  int i, ms, pkt_rate;
  char line[global->threads_n * 10];
  char* p;

  for( i = 0; i < global->threads_n; ++i )
    prev[i] = global->threads[i]->n_rx;
  gettimeofday(&start, NULL);

  while( 1 ) {
    sleep(1);
    for( i = 0; i < global->threads_n; ++i )
      now[i] = global->threads[i]->n_rx;
    gettimeofday(&end, NULL);
    ms = (end.tv_sec - start.tv_sec) * 1000;
    ms += (end.tv_usec - start.tv_usec) / 1000;
    p = line;
    for( i = 0; i < global->threads_n; ++i ) {
      pkt_rate = (int) ((int64_t) (now[i] - prev[i]) * 1000 / ms);
      p += sprintf(p, "%s%d", i ? "\t":"", pkt_rate);
      prev[i] = now[i];
    }
    start = end;
    printf("%s\n", line);
    fflush(stdout);
  }
}


static void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  efrss <num-threads> <# of intfs> <intf0> ... <intf(n-1)> "
          "<filter-spec>...\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "filter-spec:\n");
  fprintf(stderr, "  {udp|tcp}:[vid=<vlan>,]<local-host>:<local-port>"
          "[,<remote-host>:<remote-port>]\n");
  fprintf(stderr, "  eth:[vid=<vlan>,]<local-mac>\n");
  fprintf(stderr, "  {unicast-all,multicast-all}:[vid=<vlan>]\n");
  exit(1);
}


int main(int argc, char* argv[])
{
  struct global* global;
  int n_threads;
  int n_intfs;
  int i, j;

  if( argc < 4 )
    usage();
  ++argv;
  --argc;

  n_threads = atoi(argv[0]);
  ++argv;
  --argc;
  n_intfs = atoi(argv[0]);
  ++argv;
  --argc;
  global = global_alloc(n_threads, n_intfs);

  /* Allocate per-interface state. */
  for( i = 0; i < n_intfs; ++i )
    global_add_net_if(global, net_if_alloc(i, argv[i], global->threads_n));
  argv += n_intfs;
  argc -= n_intfs;

  /* Allocate per-thread state and start worker threads. */
  for( i = 0; i < global->threads_n; ++i ) {
    struct thread* thread = thread_alloc(global, i);
    global->threads[i] = thread;
    CPU_SET(i, &thread->cpus);
    TEST(pthread_create(&thread->pthread_id, NULL, thread_fn, thread) == 0);
  }

  /* Wait for threads to initialise.  Not strictly necessary, but increases
   * chances that we'll not get any drops when we install the filters.  (If
   * we install filter before VIs are ready, packets will be dropped).
   */
  TEST(pthread_mutex_lock(&global->mutex) == 0);
  for( i = 0; i < global->threads_n; ++i )
    while( global->threads[i]->state != thread_running )
      pthread_cond_wait(&global->condvar, &global->mutex);
  TEST(pthread_mutex_unlock(&global->mutex) == 0);

  /* Add filters as per cmdline args. */
  for( i = 0; i < global->net_ifs_n; ++i ) {
    struct net_if* net_if = global->net_ifs[i];
    ef_filter_spec fs;
    for( j = 0; j < argc; ++j ) {
      if( filter_parse(&fs, argv[j]) ) {
        LOGE(fprintf(stderr, "ERROR: Bad filter spec '%s'\n", argv[j]));
        exit(1);
      }
      TRY(ef_vi_set_filter_add(&net_if->vi_set, net_if->dh, &fs, NULL));
    }
  }

  monitor(global);

  return 0;
}
