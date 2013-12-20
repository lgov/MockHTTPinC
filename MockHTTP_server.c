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

typedef struct servCtx_t {
    apr_pool_t *pool;
    const char *hostname;
    apr_port_t port;
} servCtx_t;

static apr_status_t setupTCPServer(servCtx_t *ctx, bool blocking);

void * APR_THREAD_FUNC start_thread(apr_thread_t *tid, void *baton)
{
    servCtx_t *ctx = baton;

    setupTCPServer(ctx, YES);

    return NULL;
}

static apr_status_t cleanupServer(void *baton)
{

    /*    apr_thread_exit(tid, APR_SUCCESS);*/

    return APR_SUCCESS;
}

static apr_status_t setupTCPServer(servCtx_t *ctx, bool blocking)
{
    apr_status_t status;
    apr_socket_t *serv_sock;
    apr_sockaddr_t *serv_addr;

    apr_pool_t *pool = ctx->pool;

    STATUSERR(apr_sockaddr_info_get(&serv_addr, ctx->hostname,
                                    APR_UNSPEC, ctx->port, 0,
                                    pool));

    /* Create server socket */
    /* Note: this call requires APR v1.0.0 or higher */
    STATUSERR(apr_socket_create(&serv_sock, serv_addr->family,
                                SOCK_STREAM, 0, pool));

    if (blocking == NO)
        apr_socket_opt_set(serv_sock, APR_SO_NONBLOCK, 1);

    STATUSERR(apr_socket_timeout_set(serv_sock, 0));
    STATUSERR(apr_socket_opt_set(serv_sock, APR_SO_REUSEADDR, 1));

    STATUSERR(apr_socket_bind(serv_sock, serv_addr));

    /* Listen for clients */
    STATUSERR(apr_socket_listen(serv_sock, SOMAXCONN));

    return APR_SUCCESS;
}

void _mhInitTestServer(MockHTTP *mh, const char *hostname, apr_port_t port)
{
    apr_thread_t *thread;
    apr_pool_t *pool = mh->pool;

    servCtx_t *ctx = apr_palloc(pool, sizeof(servCtx_t));
    ctx->pool = pool;
    ctx->hostname = apr_pstrdup(pool, hostname);
    ctx->port = port;

    apr_pool_cleanup_register(pool, ctx,
                              cleanupServer,
                              apr_pool_cleanup_null);

    if (1) { /* second thread */
        apr_thread_create(&thread, NULL, start_thread, ctx, mh->pool);
    } else {
        setupTCPServer(ctx, NO);
    }

}
