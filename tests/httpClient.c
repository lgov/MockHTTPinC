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
#if 0
    /* Set the socket to be non-blocking */
    status = apr_socket_timeout_set(ctx->skt, 0);
    if (status != APR_SUCCESS)
        return status;
#endif

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

void sendRequest(clientCtx_t *ctx, const char *method, const char *url,
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
    line = apr_psprintf(ctx->pool, "%s %s HTTP/1.1\r\n",
                        method, uri.path);

    /* body */
    if (1) { /* not chunked */
        len = strlen(body);
        apr_hash_set(hdrs, "Content-Length", APR_HASH_KEY_STRING,
                     apr_itoa(ctx->pool, len));

    }

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

static apr_status_t receiveData(clientCtx_t *ctx, char *buf, apr_size_t *len)
{
    apr_status_t status;

    status = apr_socket_recv(ctx->skt, buf, len);

    return status;
}


void receiveResponse(clientCtx_t *ctx)
{
    char buf[8192];
    apr_size_t len = 8192;
    apr_status_t status;

    status = receiveData(ctx, buf, &len);

}
