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

#include "MockHTTP.h"
#include "MockHTTP_private.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <apr_strings.h>

static const int DefaultSrvPort =   30080;
static const int DefaultProxyPort = 38080;

/******************************************************************************/
/* Linked list                                                                */
/******************************************************************************/
typedef struct llnode_t llnode_t;
typedef llnode_t lliter_t;

struct llnode_t {
    const void *ptr1;
    const void *ptr2;
    llnode_t *next;
};

struct linkedlist_t {
    apr_pool_t *pool;
    llnode_t *first;
    llnode_t *last;
};

static linkedlist_t *linkedlist_init(apr_pool_t *pool)
{
    linkedlist_t *l = apr_palloc(pool, sizeof(linkedlist_t));
    l->pool = pool;
    l->first = l->last = NULL;
    return l;
}

static void ll_add(linkedlist_t *l, const void *ptr1, const void *ptr2)
{
    llnode_t *n = apr_palloc(l->pool, sizeof(struct llnode_t));
    n->ptr1 = ptr1;
    n->ptr2 = ptr2;
    n->next = NULL;
    if (l->first == NULL)
        l->first = l->last = n;
    else {
        l->last->next = n;
        l->last = l->last->next;
    }
}

static lliter_t *ll_iter(linkedlist_t *l)
{
    return l->first;
}

static bool ll_hasnext(lliter_t *iter)
{
    if (iter)
        return YES;
    return NO;
}

static void ll_next(lliter_t **itptr, const void **ptr1, const void **ptr2)
{
    lliter_t *iter = *itptr;
    *itptr = (*itptr)->next;

    if (iter) {
        if (ptr1) *ptr1 = iter->ptr1;
        if (ptr2) *ptr2 = iter->ptr2;
    } else {
        *ptr1 = *ptr2 = NULL;
    }
}

/* Define a MockHTTP context */
MockHTTP *mhInit()
{
    apr_pool_t *pool;
    MockHTTP *mh;

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&pool, NULL);
    mh = apr_palloc(pool, sizeof(struct MockHTTP));
    mh->pool = pool;
    mh->reqs = linkedlist_init(pool);
    apr_queue_create(&mh->reqQueue, 5, pool);
    mh->reqsReceived = apr_array_make(pool, 5, sizeof(mhRequest_t *));

    mh->servCtx = _mhInitTestServer(mh, "localhost", DefaultSrvPort,
                                    mh->reqQueue);

    return mh;
}

void mhCleanup(MockHTTP *mh)
{
    if (!mh)
        return;

    /* The MockHTTP * is also allocated from mh->pool, so this will destroy
       the MockHTTP structure and all its allocated memory. */
    apr_pool_destroy(mh->pool);

    /* mh ptr is now invalid */
}

void mhRunServerLoop(MockHTTP *mh)
{
    mhRequest_t *req;
    void *data;

    _mhRunServerLoop(mh->servCtx);
    if (apr_queue_trypop(mh->reqQueue, &data) == APR_SUCCESS) {
        req = data;
        *((mhRequest_t **)apr_array_push(mh->reqsReceived)) = req;
        printf("reaquest added to incoming queue: %s\n", req->method);
    }
}

mhResponse_t *_mhMatchRequest(MockHTTP *mh, mhRequest_t *req)
{
    mhResponse_t *resp;
    lliter_t *iter;

    iter = ll_iter(mh->reqs);
    while (ll_hasnext(iter)) {
        const mhRequestMatcher_t *rm;

        ll_next(&iter, (const void **)&rm, (const void **)&resp);
        if (_mhRequestMatcherMatch(rm, req) == YES)
            return resp;
    }
    return NULL;
}

/* Define expectations*/

void mhPushReqResp(MockHTTP *mh, mhRequestMatcher_t *rm, mhResponse_t *resp)
{
    ll_add(mh->reqs, rm, resp);
}

mhRequest_t *_mhRequestInit(MockHTTP *mh)
{
    mhRequest_t *req = apr_palloc(mh->pool, sizeof(mhRequest_t));

    return req;
}

/******************************************************************************/
/* Requests matchers: define criteria to match different aspects of a HTTP    */
/* request received by the MockHTTP server.                                   */
/******************************************************************************/
static int url_matcher(const mhMatchingPattern_t *mp, const mhRequest_t *req)
{
    const char *expected = mp->baton;

    /* Explicitly asked to test the URL, so ensure all strings are set */
    if (expected == NULL || req->url == NULL)
        return NO;

    if (strcmp(expected, req->url) == 0)
        return YES;

    return NO;
}

mhMatchingPattern_t *
mhMatchURLEqualTo(MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = apr_palloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = url_matcher;

    return mp;
}

static int strcicmp(const char *a, const char *b)
{
    for (;; a++, b++) {
        int d;
        if (!*a) {
            if (!*b)
                return 0;
            return -1;
        } else if (!*b) {
            return 1;
        }
        d = tolower(*a) - tolower(*b);
        if (d != 0)
            return d;
    }
}

static int method_matcher(const mhMatchingPattern_t *mp, const mhRequest_t *req)
{
    const char *expected = mp->baton;

    if (strcicmp(expected, req->method) == 0)
        return YES;

    return NO;
}

mhMatchingPattern_t *
mhMatchMethodEqualTo(MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = apr_palloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = method_matcher;

    return mp;
}

static mhRequestMatcher_t *
createRequestMatcher(MockHTTP *mh, const char *method)
{
    apr_pool_t *pool = mh->pool;

    mhRequestMatcher_t *rm = apr_palloc(pool, sizeof(mhRequestMatcher_t));
    rm->pool = pool;
    rm->method = apr_pstrdup(pool, method);
    rm->matchers = linkedlist_init(pool);

    return rm;
}

mhRequestMatcher_t *mhGetRequest(MockHTTP *mh, ...)
{
    va_list argp;

    mhRequestMatcher_t *rm = createRequestMatcher(mh, "GET");

    va_start(argp, mh);
    while (1) {
        mhMatchingPattern_t *mp;
        mp = va_arg(argp, mhMatchingPattern_t *);
        if (mp == NULL) break;
        ll_add(rm->matchers, mp, NULL);
    }
    va_end(argp);

    return rm;
}

bool _mhRequestMatcherMatch(const mhRequestMatcher_t *rm, mhRequest_t *req)
{
    lliter_t *iter;

    if (strcicmp(rm->method, req->method) != 0) {
        return NO;
    }

    iter = ll_iter(rm->matchers);
    while (ll_hasnext(iter)) {
        const mhMatchingPattern_t *mp;

        ll_next(&iter, (const void **)&mp, NULL);
        if (mp->matcher(mp, req) == YES)
            return YES;
    }

    return NO;
}

/******************************************************************************/
/* Response                                                                   */
/******************************************************************************/
mhResponse_t *mhResponse(MockHTTP *mh, ...)
{
    apr_pool_t *pool = mh->pool;
    va_list argp;

    mhResponse_t *resp = apr_palloc(pool, sizeof(mhResponse_t));
    resp->pool = pool;
    resp->status = 200;
    resp->body = "";
    resp->hdrs = linkedlist_init(pool);
    resp->builders = linkedlist_init(pool);

    va_start(argp, mh);
    while (1) {
        mhRespBuilder_t *rb;
        rb = va_arg(argp, mhRespBuilder_t *);
        if (rb == NULL) break;
        ll_add(resp->builders, rb, NULL);
    }
    va_end(argp);

    return resp;
}

typedef struct RespBuilderHelper_t {
    int status;
    const char *body;
    const char *header;
    const char *value;
    bool chunked;
} RespBuilderHelper_t;

static void respStatusSetter(mhResponse_t *resp, void *baton)
{
    RespBuilderHelper_t *rbh = baton;
    resp->status = rbh->status;
}

mhRespBuilder_t *mhRespSetStatus(MockHTTP *mh, unsigned int status)
{
    apr_pool_t *pool = mh->pool;
    mhRespBuilder_t *rb;

    RespBuilderHelper_t *rbh = apr_palloc(pool, sizeof(RespBuilderHelper_t));
    rbh->status = status;

    rb = apr_palloc(pool, sizeof(mhRespBuilder_t));
    rb->baton = rbh;
    rb->builder = respStatusSetter;
    return rb;
}

static void respBodySetter(mhResponse_t *resp, void *baton)
{
    RespBuilderHelper_t *rbh = baton;
    resp->body = rbh->body;
}

mhRespBuilder_t * mhRespSetBody(MockHTTP *mh, const char *body)
{
    apr_pool_t *pool = mh->pool;
    mhRespBuilder_t *rb;

    RespBuilderHelper_t *rbh = apr_palloc(pool, sizeof(RespBuilderHelper_t));
    rbh->body = apr_pstrdup(pool, body);
    rbh->chunked = NO;

    rb = apr_palloc(pool, sizeof(mhRespBuilder_t));
    rb->baton = rbh;
    rb->builder = respBodySetter;
    return rb;
}

mhRespBuilder_t * mhRespSetChunkedBody(MockHTTP *mh, const char *body)
{
    apr_pool_t *pool = mh->pool;
    mhRespBuilder_t *rb;

    RespBuilderHelper_t *rbh = apr_palloc(pool, sizeof(RespBuilderHelper_t));
    rbh->body = apr_pstrdup(pool, body);
    rbh->chunked = YES;

    rb = apr_palloc(pool, sizeof(mhRespBuilder_t));
    rb->baton = rbh;
    rb->builder = respBodySetter;
    return rb;
}

static void respHeaderSetter(mhResponse_t *resp, void *baton)
{
    RespBuilderHelper_t *rbh = baton;
    ll_add(resp->hdrs, rbh->header, rbh->value);
}

mhRespBuilder_t *
mhRespAddHeader(MockHTTP *mh, const char *header, const char *value)
{
    apr_pool_t *pool = mh->pool;
    mhRespBuilder_t *rb;

    RespBuilderHelper_t *rbh = apr_palloc(pool, sizeof(RespBuilderHelper_t));
    rbh->header = apr_pstrdup(pool, header);
    rbh->value = apr_pstrdup(pool, value);

    rb = apr_palloc(pool, sizeof(mhRespBuilder_t));
    rb->baton = rbh;
    rb->builder = respHeaderSetter;
    return rb;
}

/******************************************************************************/
/* Verify results                                                             */
/******************************************************************************/
int mhVerifyRequestReceived(MockHTTP *mh, mhRequestMatcher_t *rm)
{
    int i;

    for (i = 0; i < mh->reqsReceived->nelts; i++)
    {
        mhRequest_t *req = APR_ARRAY_IDX(mh->reqsReceived, i, mhRequest_t *);
        if (_mhRequestMatcherMatch(rm, req) == YES)
            return YES;
    }

    return NO;
}