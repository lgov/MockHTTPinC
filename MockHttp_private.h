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

#ifndef MockHTTP_private_H
#define MockHTTP_private_H

#include <apr_pools.h>
#include <apr_hash.h>
#include <apr_queue.h>
#include <apr_tables.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Simple macro to return from function when status != 0
   expects 'apr_status_t status;' declaration. */
#define STATUSERR(x) if ((status = (x))) return status;

#define READ_ERROR(status) ((status) \
                                && !APR_STATUS_IS_EOF(status) \
                                && !APR_STATUS_IS_EAGAIN(status))

#define STATUSREADERR(x) if (((status = (x)) && READ_ERROR(status)))\
                            return status;

typedef short int bool;
static const bool YES = 1;
static const bool NO = 0;

typedef bool (*matchfunc_t)(const mhMatchingPattern_t *mp,
                           const mhRequest_t *req);
typedef struct servCtx_t servCtx_t;

struct MockHTTP {
    apr_pool_t *pool;
    apr_array_header_t *reqMatchers;
    apr_array_header_t *reqsReceived;
    servCtx_t *servCtx;
    apr_queue_t *reqQueue; /* Thread safe FIFO queue. */
};

struct mhRequest_t {
    const char *method;
    const char *url;
    apr_hash_t *hdrs;
    int version;
    char *body;
    apr_size_t bodyLen;
    bool chunked;
    int readState;
};

struct mhResponse_t {
    apr_pool_t *pool;

    unsigned int code;
    const char *body;
    bool chunked;
    apr_hash_t *hdrs;
    apr_array_header_t *builders;
};

struct mhRequestMatcher_t {
    apr_pool_t *pool;

    const char *method;
    apr_array_header_t *matchers;
};

struct mhMatchingPattern_t {
    const void *baton;
    matchfunc_t matcher;
};

typedef void (* respbuilderfunc_t)(mhResponse_t *resp, void *baton);

struct mhRespBuilder_t {
    const void *baton;
    respbuilderfunc_t builder;
};

/* Initialize a mhRequest_t object. */
mhRequest_t *_mhRequestInit(MockHTTP *mh);
mhResponse_t *_mhMatchRequest(MockHTTP *mh, mhRequest_t *req);

bool _mhRequestMatcherMatch(const mhRequestMatcher_t *rm,
                            const mhRequest_t *req);

/* Test servers */
servCtx_t *_mhInitTestServer(MockHTTP *mh, const char *hostname,
                             apr_port_t port, apr_queue_t *reqQueue);
apr_status_t _mhRunServerLoop(servCtx_t *ctx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHTTP_private_H */
