/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/*
 * This sample application opens a TCP listening socket, accepts
 * connections and receives and sends data.  On each connection it sends
 * the same amount of data as it receives (but the data sent is not the
 * data received -- it is just zeroes).
 *
 * It demonstrates the following features:
 *
 *  - Using a single TCPDirect stack in multiple threads.
 *  - Managing a TCP listening socket and multiple accepted connections.
 *  - Using a muxer to manage multiple zockets.
 *
 * Note that in general sharing objects such as TCPDirect stacks between
 * threads (particularly between CPU cores) reduces efficiency and
 * increases latency because of the costs of synchronising shared data
 * between caches.  In most cases you'll get best performance if a
 * TCPDirect stack is used in only one thread.
 *
 * However, there are many existing applications where strict
 * stack-per-thread is hard to achieve.  This sample has a threading model
 * that is common in real applications: An I/O thread which is used to
 * accept new connections and handle all received data, and a thread per
 * connection that is used for sends.
 */

#include <zf/zf.h>
#include "zf_utils.h"

#include <unistd.h>
#include <stdbool.h>
#include <stdarg.h>
#include <pthread.h>


struct app {
  pthread_mutex_t      lock;
  struct zf_stack*     stack;
  struct zf_muxer_set* muxer;
  struct zftl*         listener;
};


struct connection {
  struct app*       app;
  struct zft*       zocket;
  volatile size_t   bytes_in;
  volatile bool     closed;
};


static bool cfg_quiet = false;


static void usage_msg(FILE* f)
{
  fprintf(f, "usage:\n");
  fprintf(f, "  zftcpmtpong [options] <local_host:port>\n");
  fprintf(f, "\n");
  fprintf(f, "options:\n");
  fprintf(f, "  -h       Print this usage message\n");
  fprintf(f, "  -q       Quiet -- do not emit progress messages\n");
}


static void usage_err(void)
{
  usage_msg(stderr);
  exit(1);
}


static void vlog(const char* fmt, ...)
{
  if( ! cfg_quiet ) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
  }
}


static ssize_t locked_zft_send(pthread_mutex_t* lock,
                               struct zft* tcp, const void* buf,
                               size_t len, int flags)
{
  struct iovec iov = { .iov_base = (void*) buf, .iov_len = len };
  pthread_mutex_lock(lock);
  ssize_t rc = zft_send(tcp, &iov, 1, flags);
  pthread_mutex_unlock(lock);
  return rc;
}


static void* worker_thread(void* arg)
{
  struct connection* c = arg;
  struct app* app = c->app;
  struct zft* zocket = c->zocket;
  size_t bytes_in, bytes_out = 0;

  char buf[1024];
  memset(buf, 0, sizeof(buf));

  vlog("worker: starting\n");

  while( 1 ) {
    /* Note that this thread responds to received data very quickly, and so
     * it is likely to contend with the lock held by the IO thread.  In
     * real applications that have work to do send calls are much less
     * likely to contend with the IO thread in practice.
     */
    if( bytes_out != (bytes_in = c->bytes_in) ) {
      size_t n = bytes_in - bytes_out;
      if( n > sizeof(buf) )
        n = sizeof(buf);
      ssize_t rc = locked_zft_send(&app->lock, zocket, buf, n, 0);
      vlog("worker: backlog=%zu send=%zu rc=%zd\n",
           bytes_in - bytes_out, n, rc);
      if( rc > 0 ) {
        bytes_out += rc;
      }
      else {
        vlog("worker: ERROR: send returned %zd\n", rc);
        bytes_out = bytes_in;
      }
    }

    if( c->closed && bytes_out == c->bytes_in )
      break;
  }

  vlog("worker: freeing connection\n");
  ZF_TRY(zft_free(c->zocket));
  free(c);

  return NULL;
}


static void handle_connection_readable(struct connection* c)
{
  struct {
    /* The iovec used by zft_msg must be immediately afterwards */
    struct zft_msg msg;
    struct iovec iov[1];
  } rd = { { .iovcnt = 1 } };
  zft_zc_recv(c->zocket, &rd.msg, 0);
  vlog("iothread: zft_zc_recv => iovcnt=%d len=%zu\n",
       rd.msg.iovcnt, rd.iov[0].iov_len);
  if( rd.msg.iovcnt ) {
    int rc = zft_zc_recv_done(c->zocket, &rd.msg);
    if( rd.iov[0].iov_len ) {
      c->bytes_in += rd.iov[0].iov_len;
    }
    else {
      vlog("iothread: got EOF rc=%d\n", rc);
      ZF_TRY(zf_muxer_del(zft_to_waitable(c->zocket)));
      c->closed = true;
    }
  }
}


static void accept_connection(struct app* app)
{
  vlog("iothread: accepting new connection\n");
  struct connection* c = calloc(1, sizeof(*c));
  c->app = app;
  ZF_TRY(zftl_accept(app->listener, &c->zocket));
  struct epoll_event ev = { .events = EPOLLIN, .data.ptr = c };
  ZF_TRY(zf_muxer_add(app->muxer, zft_to_waitable(c->zocket), &ev));
  pthread_t tid;
  ZF_TEST(pthread_create(&tid, NULL, worker_thread, c) == 0);
  ZF_TEST(pthread_detach(tid) == 0);
}


int main(int argc, char* argv[])
{
  int c;
  while( (c = getopt(argc, argv, "hq")) != -1 )
    switch( c ) {
    case 'h':
      usage_msg(stdout);
      exit(0);
    case 'q':
      cfg_quiet = true;
      break;
    case '?':
      exit(1);
    default:
      ZF_TEST(0);
    }

  argc -= optind;
  argv += optind;
  if( argc != 1 )
    usage_err();

  struct addrinfo* ai;
  if( getaddrinfo_hostport(argv[0], NULL, &ai) != 0 ) {
    fprintf(stderr, "ERROR: failed to lookup address '%s'\n", argv[0]);
    exit(2);
  }

  struct app the_app, *app = &the_app;

  ZF_TEST(pthread_mutex_init(&app->lock, NULL) == 0);
  ZF_TRY(zf_init());
  struct zf_attr* attr;
  ZF_TRY(zf_attr_alloc(&attr));
  ZF_TRY(zf_stack_alloc(attr, &app->stack));
  ZF_TRY(zf_muxer_alloc(app->stack, &app->muxer));

  ZF_TRY(zftl_listen(app->stack, ai->ai_addr, ai->ai_addrlen,
                     attr, &app->listener));
  struct epoll_event event = { .events = EPOLLIN,
                               .data = { .ptr = app->listener } };
  ZF_TRY(zf_muxer_add(app->muxer, zftl_to_waitable(app->listener), &event));

  while( 1 ) {
    /* Only attempt to grab the lock when there is work to do.  (We don't
     * want to hold the lock otherwise, as that would interfere with other
     * threads).
     */
    if( zf_stack_has_pending_work(app->stack) &&
        pthread_mutex_trylock(&app->lock) == 0 ) {
      struct epoll_event evs[8];
      const int max_evs = sizeof(evs) / sizeof(evs[0]);

      int n_ev = zf_muxer_wait(app->muxer, evs, max_evs, 0);
      if( n_ev )
        vlog("iothread: zf_muxer_wait => %d\n", n_ev);

      for( int i = 0; i < n_ev; ++i )
        if( evs[i].data.ptr == app->listener )
          accept_connection(app);
        else
          handle_connection_readable(evs[i].data.ptr);

      pthread_mutex_unlock(&app->lock);
    }
  }

  return 0;
}
