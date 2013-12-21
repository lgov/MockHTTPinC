/* Copyright 2013 Lieven Govaerts
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <apr_thread_proc.h>
#include <apr_strings.h>

#include "MockHTTP.h"
#include "MockHTTP_private.h"

/* Copied from serf.  */
#if defined(APR_VERSION_AT_LEAST) && defined(WIN32)
#if APR_VERSION_AT_LEAST(1,4,0)
#define BROKEN_WSAPOLL
#endif
#endif

struct servCtx_t {
    apr_pool_t *pool;
    const char *hostname;
    apr_port_t port;
    apr_pollset_t *pollset;
    apr_socket_t *skt;
};

typedef struct clientCtx_t {
    apr_socket_t *skt;
} clientCtx_t;

static apr_status_t setupTCPServer(servCtx_t *ctx, bool blocking);

void * APR_THREAD_FUNC start_thread(apr_thread_t *tid, void *baton)
{
    servCtx_t *ctx = baton;

    setupTCPServer(ctx, YES);

    while (1) {
        _mhRunServerLoop(ctx);
    }

    return NULL;
}

static apr_status_t cleanupServer(void *baton)
{
    servCtx_t *ctx = baton;

    /*    apr_thread_exit(tid, APR_SUCCESS);*/
    if (ctx->pollset)
        apr_pollset_destroy(ctx->pollset);

    return APR_SUCCESS;
}

static apr_status_t setupTCPServer(servCtx_t *ctx, bool blocking)
{
    apr_sockaddr_t *serv_addr;
    apr_pool_t *pool = ctx->pool;
    apr_status_t status;

    STATUSERR(apr_sockaddr_info_get(&serv_addr, ctx->hostname,
                                    APR_UNSPEC, ctx->port, 0,
                                    pool));

    /* Create server socket */
    /* Note: this call requires APR v1.0.0 or higher */
    STATUSERR(apr_socket_create(&ctx->skt, serv_addr->family,
                                SOCK_STREAM, 0, pool));

    STATUSERR(apr_socket_opt_set(ctx->skt, APR_SO_NONBLOCK, 1));
    STATUSERR(apr_socket_timeout_set(ctx->skt, 0));
    STATUSERR(apr_socket_opt_set(ctx->skt, APR_SO_REUSEADDR, 1));

    STATUSERR(apr_socket_bind(ctx->skt, serv_addr));

    /* Listen for clients */
    STATUSERR(apr_socket_listen(ctx->skt, SOMAXCONN));

    /* Create a new pollset, avoid broken WSAPoll implemenation on Windows. */
#ifdef BROKEN_WSAPOLL
    STATUSERR(apr_pollset_create_ex(&ctx->pollset, 32, pool, 0,
                                    APR_POLLSET_SELECT));
#else
    STATUSERR(apr_pollset_create(&ctx->pollset, 32, pool, 0));
#endif

    {
        apr_pollfd_t pfd = { 0 };

        pfd.desc_type = APR_POLL_SOCKET;
        pfd.desc.s = ctx->skt;
        pfd.reqevents = APR_POLLIN;

        STATUSERR(apr_pollset_add(ctx->pollset, &pfd));
    }

    return APR_SUCCESS;
}

servCtx_t *
_mhInitTestServer(MockHTTP *mh, const char *hostname,apr_port_t port)
{
    apr_thread_t *thread;
    apr_pool_t *pool = mh->pool;

    servCtx_t *ctx = apr_pcalloc(pool, sizeof(servCtx_t));
    ctx->pool = pool;
    ctx->hostname = apr_pstrdup(pool, hostname);
    ctx->port = port;

    apr_pool_cleanup_register(pool, ctx,
                              cleanupServer,
                              apr_pool_cleanup_null);

    if (1) { /* second thread */
        /* Setup a non-blocking TCP server in a separate thread */
        apr_thread_create(&thread, NULL, start_thread, ctx, mh->pool);
    } else {
        /* Setup a non-blocking TCP server */
        setupTCPServer(ctx, NO);
    }

    return ctx;
}

static apr_status_t readRequest(clientCtx_t *cctx)
{
    char buf[8192];
    apr_size_t len = 8192;
    apr_status_t status;

    status = apr_socket_recv(cctx->skt, buf, &len);

    return status;
}

apr_status_t _mhRunServerLoop(servCtx_t *ctx)
{
    apr_int32_t num;
    const apr_pollfd_t *desc;
    apr_status_t status;

    STATUSERR(apr_pollset_poll(ctx->pollset, APR_USEC_PER_SEC >> 1,
                               &num, &desc));
    while (num--) {
        if (desc->desc.s == ctx->skt) {
            apr_socket_t *cskt;
            apr_pollfd_t pfd = { 0 };
            clientCtx_t *cctx = apr_pcalloc(ctx->pool, sizeof(clientCtx_t));

            STATUSERR(apr_socket_accept(&cskt, ctx->skt, ctx->pool));
            cctx->skt = cskt;

            STATUSERR(apr_socket_opt_set(cskt, APR_SO_NONBLOCK, 1));
            STATUSERR(apr_socket_timeout_set(cskt, 0));

            pfd.desc_type = APR_POLL_SOCKET;
            pfd.desc.s = cskt;
            pfd.reqevents = APR_POLLIN | APR_POLLOUT;
            pfd.client_data = cctx;

            STATUSERR(apr_pollset_add(ctx->pollset, &pfd));
        } else {
            /* one of the client sockets */
            clientCtx_t *cctx = desc->client_data;
            
            readRequest(cctx);
        }
    }

    return APR_SUCCESS;
}
