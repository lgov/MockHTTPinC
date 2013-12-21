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
#include <stdlib.h>

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

#define BUFSIZE 32768
typedef struct clientCtx_t {
    apr_pool_t *pool;
    apr_socket_t *skt;
    char buf[BUFSIZE];
    apr_size_t buflen;
    apr_size_t bufrem;
    mhRequest_t *req;
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

    /* TODO: second thread doesn't work. */
    if (0) { /* second thread */
        /* Setup a non-blocking TCP server in a separate thread */
        apr_thread_create(&thread, NULL, start_thread, ctx, mh->pool);
    } else {
        /* Setup a non-blocking TCP server */
        setupTCPServer(ctx, NO);
    }

    return ctx;
}

/******************************************************************************/
/* Parse a request structure from incoming data                               */
/******************************************************************************/

static void readLine(clientCtx_t *cctx, const char **buf, apr_size_t *len)
{
    const char *ptr = cctx->buf;

    *len = 0;
    while (*ptr && ptr - cctx->buf < cctx->buflen) {
        if (*ptr == '\r' && *(ptr+1) == '\n') {
            *buf = cctx->buf;
            *len = ptr - cctx->buf + 2;
            break;
        }
        ptr++;
    }
}

/* New request data was made available, read status line/hdrs/body (chunks) */
static apr_status_t processData(clientCtx_t *cctx)
{
    const char *buf;
    apr_size_t len;
    apr_status_t status = APR_SUCCESS;

    if (cctx->req == NULL) {
        cctx->req = apr_pcalloc(cctx->pool, sizeof(mhRequest_t));
        cctx->req->hdrs = apr_hash_make(cctx->pool);
    }

    switch(cctx->req->readState) {
        case 0: /* status line */
        {
            const char *start, *ptr, *version;

            readLine(cctx, &buf, &len);
            if (!len) return APR_EAGAIN;

            start = ptr = buf;
            while (*ptr != ' ' && *ptr != '\r') ptr++;
            cctx->req->method = apr_pmemdup(cctx->pool, start, ptr-start);

            ptr++; start = ptr;
            while (*ptr != ' ' && *ptr != '\r') ptr++;
            cctx->req->url = apr_pmemdup(cctx->pool, start, ptr-start);

            ptr++; start = ptr;
            while (*ptr != ' ' && *ptr != '\r') ptr++;
            version = apr_pmemdup(cctx->pool, start, ptr-start);
            cctx->req->version = (version[5] - '0') * 100 +
            version[7] - '0';

            cctx->req->readState++;
            break;
        }
        case 1: /* headers */
        {
            readLine(cctx, &buf, &len);
            if (!len) return APR_EAGAIN;

            if (len > 2) {
                const char *start = buf, *ptr = buf;
                const char *hdr, *val;
                while (*ptr != ':' && *ptr != '\r') ptr++;
                hdr = apr_pmemdup(cctx->pool, start, ptr-start);

                ptr++; while (*ptr == ' ') ptr++; start = ptr;
                while (*ptr != '\r') ptr++;
                val = apr_pmemdup(cctx->pool, start, ptr-start);

                apr_hash_set(cctx->req->hdrs, hdr, APR_HASH_KEY_STRING, val);
            } else {
                cctx->req->readState++;
            }
            break;
        }
        case 2: /* body */
        {
            const char *clstr;
            long cl;
            clstr = apr_hash_get(cctx->req->hdrs, "Content-Length",
                                 APR_HASH_KEY_STRING);
            /* TODO: chunked */
            cl = atol(clstr);

            if (cctx->req->body == NULL) {
                cctx->req->body = apr_palloc(cctx->pool, cl);
            }

            len = cctx->buflen;
            memcpy(cctx->req->body + cctx->req->bodyLen, cctx->buf, len);
            cctx->req->bodyLen += len;

            if (cctx->req->bodyLen >= cl)
                cctx->req->readState++;
            else
                status = APR_EAGAIN;

            break;
        }
        case 3: /* finished */
        {
            len = 0;
            printf("request received: %s\n", cctx->req->method);
            /* TODO: queue request */
            cctx->req = NULL;
        }
    }

    if (len) {
        cctx->buflen -= len; /* eat line */
        cctx->bufrem += len;
        memcpy(cctx->buf, cctx->buf+len, cctx->buflen);
    }

    if (*cctx->buf == '\0')
        return APR_EOF;

    return APR_SUCCESS;
}

static apr_status_t readRequest(clientCtx_t *cctx)
{
    apr_status_t status;
    apr_size_t len;

    len = cctx->bufrem;
    if (len == 0) return APR_EGENERAL; /* should clear buffer */

    status = apr_socket_recv(cctx->skt, cctx->buf + cctx->buflen, &len);
    if (len) {
        printf("recvd: %.*s\n", (unsigned int)len, cctx->buf + cctx->buflen);

        cctx->buflen += len;
        cctx->bufrem -= len;

        while (processData(cctx) == APR_SUCCESS);
    }

    return status;
}


/******************************************************************************/
/* Process socket events                                                      */
/******************************************************************************/
apr_status_t _mhRunServerLoop(servCtx_t *ctx)
{
    apr_int32_t num;
    const apr_pollfd_t *desc;
    apr_status_t status;

    printf(".\n");

    STATUSERR(apr_pollset_poll(ctx->pollset, APR_USEC_PER_SEC >> 1,
                               &num, &desc));
    while (num--) {
        if (desc->desc.s == ctx->skt) {
            apr_socket_t *cskt;
            apr_pollfd_t pfd = { 0 };

            clientCtx_t *cctx = apr_pcalloc(ctx->pool, sizeof(clientCtx_t));

            STATUSERR(apr_socket_accept(&cskt, ctx->skt, ctx->pool));

            STATUSERR(apr_socket_opt_set(cskt, APR_SO_NONBLOCK, 1));
            STATUSERR(apr_socket_timeout_set(cskt, 0));

            pfd.desc_type = APR_POLL_SOCKET;
            pfd.desc.s = cskt;
            pfd.reqevents = APR_POLLIN;
            pfd.client_data = cctx;

            STATUSERR(apr_pollset_add(ctx->pollset, &pfd));

            cctx->pool = ctx->pool;
            cctx->skt = cskt;
            cctx->buflen = 0;
            cctx->bufrem = BUFSIZE;
        } else {
            /* one of the client sockets */
            clientCtx_t *cctx = desc->client_data;
            
            if (desc->rtnevents & APR_POLLIN) {
                printf("/");
                readRequest(cctx);
            } else if (desc->rtnevents & APR_POLLOUT) {
                printf("|");
            }
        }
    }

    return APR_SUCCESS;
}
