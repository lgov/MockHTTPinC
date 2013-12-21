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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Simple macro to return from function when status != 0
   expects 'apr_status_t status;' declaration. */
#define STATUSERR(x) if ((status = (x))) return status;

typedef int (*matchfunc_t)(const mhMatchingPattern_t *mp,
                           const mhRequest_t *req);
typedef struct block_t block_t;
typedef struct linkedlist_t linkedlist_t;
typedef struct servCtx_t servCtx_t;

typedef short int bool;
static const bool YES = 1;
static const bool NO = 0;

struct MockHTTP {
    apr_pool_t *pool;
    linkedlist_t *reqs;
    servCtx_t *servCtx;
};

struct mhMatchingPattern_t {
    const void *baton;
    matchfunc_t matcher;
};

struct mhRequest_t {
    const char *method;
    const char *url;
    apr_hash_t *hdrs;
    int version;
    char *body;
    apr_size_t bodyLen;
    int readState;
};

struct mhResponse_t {
    apr_pool_t *pool;

    unsigned int status;
    const char *body;
    bool chunked;
    linkedlist_t *hdrs;
};

struct mhRequestMatcher_t {
    apr_pool_t *pool;

    const char *method;
    linkedlist_t *matchers;
};

/* Initialize a mhRequest_t object. */
mhRequest_t *_mhRequestInit(MockHTTP *mh);
mhResponse_t *_mhMatchRequest(MockHTTP *mh, mhRequest_t *req);

bool _mhRequestMatcherMatch(const mhRequestMatcher_t *rm, mhRequest_t *req);

/* Test servers */
servCtx_t *_mhInitTestServer(MockHTTP *mh, const char *hostname,
                             apr_port_t port);
apr_status_t _mhRunServerLoop(servCtx_t *ctx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHTTP_private_H */
