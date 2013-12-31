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

#include <apr.h>
#include <apr_pools.h>
#include <apr_poll.h>
#include <apr_uri.h>
#include <apr_strings.h>

#include "tests.h"
#include "MockHTTP_private.h"

struct clientCtx_t {
    apr_pool_t *pool;
    apr_socket_t *skt;
};

static apr_status_t connectToTCPServer(clientCtx_t *ctx, const char *url)
{
    apr_sockaddr_t *address;
    apr_uri_t uri;
    apr_status_t status;

    const char *hostname = "localhost";
    apr_port_t port = 30080;

    STATUSERR(apr_uri_parse(ctx->pool, url, &uri));

    STATUSERR(apr_sockaddr_info_get(&address,
                                    hostname,
                                    APR_UNSPEC,
                                    port,
                                    0,
                                    ctx->pool));

    STATUSERR(apr_socket_create(&ctx->skt,
                                address->family,
                                SOCK_STREAM,
                                APR_PROTO_TCP,
                                ctx->pool));

/*    STATUSERR(apr_socket_opt_set(ctx->skt, APR_SO_NONBLOCK, 1));*/
    STATUSERR(apr_socket_timeout_set(ctx->skt, 1000));

    status = apr_socket_connect(ctx->skt, address);
    if (status != APR_SUCCESS && !APR_STATUS_IS_EINPROGRESS(status))
        return status;

    return APR_SUCCESS;
}

clientCtx_t *initClient(MockHTTP *mh)
{
    clientCtx_t *ctx = apr_palloc(mh->pool, sizeof(clientCtx_t));
    ctx->pool = mh->pool;
    ctx->skt = NULL;

    return ctx;
}

static void _sendRequest(clientCtx_t *ctx, const char *method, const char *url,
                         apr_hash_t *hdrs, const char *body)
{
    const char *line;
    const char *hdrstr;
    apr_uri_t uri;
    apr_size_t len;
    apr_status_t status;

    if (!ctx->skt) {
        status = connectToTCPServer(ctx, url);
        if (status)
            return;
    }

    apr_uri_parse(ctx->pool, url, &uri);

    /* request line */
    line = apr_psprintf(ctx->pool, "%s %s HTTP/1.1\r\n", method, uri.path);

    /* headers */
    {
        apr_hash_index_t *hi;
        void *val;
        const void *key;
        apr_ssize_t klen;

        hdrstr = "";
        for (hi = apr_hash_first(ctx->pool, hdrs); hi; hi = apr_hash_next(hi)) {
            apr_hash_this(hi, &key, &klen, &val);

            hdrstr = apr_psprintf(ctx->pool, "%s%s: %s\r\n", hdrstr,
                                (const char *) key, (const char *)val);
        }
    }

    line = apr_psprintf(ctx->pool, "%s%s\r\n%s",
                        line, hdrstr, body);
    len = strlen(line);

    status = apr_socket_send(ctx->skt, line, &len);
}


void sendChunkedRequest(clientCtx_t *ctx, const char *method, const char *url,
                        apr_hash_t *hdrs, ...)
{
    va_list argp;
    const char *body = "";

    apr_hash_set(hdrs, "Transfer-Encoding", APR_HASH_KEY_STRING, "chunked");

    va_start(argp, hdrs);
    while (1) {
        const char *chunk;
        apr_size_t len;

        chunk = va_arg(argp, const char *);
        if (chunk == NULL) break;

        len = strlen(chunk);
        body = apr_psprintf(ctx->pool, "%s%" APR_UINT64_T_HEX_FMT "\r\n%s\r\n",
                            body, (apr_uint64_t)len, chunk);
    }
    body = apr_psprintf(ctx->pool, "%s0\r\n\r\n", body);
    va_end(argp);

    _sendRequest(ctx, method, url, hdrs, body);
}

void sendRequest(clientCtx_t *ctx, const char *method, const char *url,
                 apr_hash_t *hdrs, const char *body)
{
    apr_size_t len;

    len = strlen(body);
    apr_hash_set(hdrs, "Content-Length", APR_HASH_KEY_STRING,
                 apr_itoa(ctx->pool, len));

    _sendRequest(ctx, method, url, hdrs, body);
}

static apr_status_t receiveData(clientCtx_t *ctx, char *buf,
                                apr_size_t *len)
{
    apr_status_t status;

    STATUSREADERR(apr_socket_recv(ctx->skt, buf, len));

    return status;
}

apr_status_t receiveResponse(clientCtx_t *ctx, char **buf,
                             apr_size_t *len)
{
    apr_size_t bufsize = 4096;
    apr_status_t status;

    *buf = apr_palloc(ctx->pool, bufsize);
    *len = bufsize;

    status = receiveData(ctx, *buf, len);

    printf("response: %.*s", (int)*len, *buf);

    return status;
}

