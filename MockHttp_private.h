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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef int (*matchfunc_t)(const mhMatchingPattern_t *mp,
                           const mhRequest_t *req);
typedef struct block_t block_t;
typedef struct pool_t pool_t;
typedef struct linkedlist_t linkedlist_t;

typedef short int bool;
static const bool YES = 1;
static const bool NO = 0;

struct MockHTTP {
    pool_t *pool;
    linkedlist_t *reqs;
};

struct mhMatchingPattern_t {
    const void *baton;
    matchfunc_t matcher;
};

struct mhRequest_t {
    const char *method;
    const char *url;
};

struct mhResponse_t {
    pool_t *pool;

    unsigned int status;
    const char *body;
    linkedlist_t *hdrs;
};

struct mhRequestMatcher_t {
    pool_t *pool;

    const char *method;
    linkedlist_t *matchers;
};

/* Initialize a mhRequest_t object. */
mhRequest_t *_mhRequestInit(MockHTTP *mh);
mhResponse_t *_mhMatchRequest(MockHTTP *mh, mhRequest_t *req);

bool _mhRequestMatcherMatch(const mhRequestMatcher_t *rm, mhRequest_t *req);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHTTP_private_H */
