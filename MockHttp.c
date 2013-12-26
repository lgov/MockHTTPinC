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
#include <apr_lib.h>

static const int DefaultSrvPort =   30080;
static const int DefaultProxyPort = 38080;

typedef struct ReqMatcherRespPair_t {
    mhRequestMatcher_t *rm;
    mhResponse_t *resp;
} ReqMatcherRespPair_t;

/* private functions */
static const char *toLower(apr_pool_t *pool, const char *str)
{
    char *lstr, *l;
    const char *u;

    lstr = apr_palloc(pool, strlen(str) + 1);
    for (u = str, l = lstr; *u != 0; u++, l++)
        *l = (char)apr_tolower(*u);
    *l = '\0';

    return lstr;
}

const char *
getHeader(apr_pool_t *pool, apr_hash_t *hdrs, const char *hdr)
{
    const char *lhdr = toLower(pool, hdr);
    return apr_hash_get(hdrs, lhdr, APR_HASH_KEY_STRING);
}

void setHeader(apr_pool_t *pool, apr_hash_t *hdrs,
               const char *hdr, const char *val)
{
    const char *lhdr = toLower(pool, hdr);

    apr_hash_set(hdrs, lhdr, APR_HASH_KEY_STRING, val);
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
    mh->reqMatchers = apr_array_make(pool, 5, sizeof(ReqMatcherRespPair_t *));;
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
    while (apr_queue_trypop(mh->reqQueue, &data) == APR_SUCCESS) {
        req = data;
        *((mhRequest_t **)apr_array_push(mh->reqsReceived)) = req;
        printf("request added to incoming queue: %s\n", req->method);
    }
}

mhResponse_t *_mhMatchRequest(MockHTTP *mh, mhRequest_t *req)
{
    int i;

    for (i = 0 ; i < mh->reqMatchers->nelts; i++) {
        const ReqMatcherRespPair_t *pair;

        pair = APR_ARRAY_IDX(mh->reqMatchers, i, ReqMatcherRespPair_t *);

        if (_mhRequestMatcherMatch(pair->rm, req) == YES)
            return pair->resp;
    }
    return NULL;
}

/* Define expectations*/

void mhPushRequest(MockHTTP *mh, mhRequestMatcher_t *rm)
{
    ReqMatcherRespPair_t *pair;
    pair = apr_palloc(mh->pool, sizeof(ReqMatcherRespPair_t *));
    pair->rm = rm;
    pair->resp = NULL;
    *((ReqMatcherRespPair_t **)apr_array_push(mh->reqMatchers)) = pair;
}

void mhSetRespForReq(MockHTTP *mh, mhRequestMatcher_t *rm, mhResponse_t *resp)
{
    int i;

    for (i = 0 ; i < mh->reqMatchers->nelts; i++) {
        ReqMatcherRespPair_t *pair;

        pair = APR_ARRAY_IDX(mh->reqMatchers, i, ReqMatcherRespPair_t *);

        if (rm == pair->rm) {
            pair->resp = resp;
            break;
        }
    }
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
static bool str_matcher(const mhMatchingPattern_t *mp, const char *actual)
{
    const char *expected = mp->baton;

    if (expected && actual && strcmp(expected, actual) == 0)
        return YES;

    return NO;
}

static bool url_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                        const mhRequest_t *req)
{
    return str_matcher(mp, req->url);
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

static bool body_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                         const mhRequest_t *req)
{
    /* ignore chunked or not chunked */
    if (req->chunked == YES)
        return str_matcher(mp, req->body);
    else
        return str_matcher(mp, req->body);
}

mhMatchingPattern_t *
mhMatchBodyEqualTo(MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = apr_palloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = body_matcher;

    return mp;
}

static bool
body_notchunked_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                        const mhRequest_t *req)
{
    if (req->chunked == YES)
        return NO;
    return str_matcher(mp, req->body);
}

mhMatchingPattern_t *
mhMatchBodyNotChunkedEqualTo(MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = apr_palloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = body_notchunked_matcher;

    return mp;
}

static bool
chunked_body_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                     const mhRequest_t *req)
{
    apr_size_t curpos = 0;
    const char *expected = mp->baton;
    int i;

    if (req->chunked == NO)
        return NO;

    for (i = 0 ; i < req->chunks->nelts; i++) {
        const char *ptr, *actual;

        ptr = expected + curpos;
        actual = APR_ARRAY_IDX(req->chunks, i, const char *);
        if (strncmp(ptr, actual, strlen(actual)) != 0)
            return NO;
        curpos += strlen(actual);
    }

    return YES;
}

mhMatchingPattern_t *
mhMatchChunkedBodyEqualTo(MockHTTP *mh, const char *expected)
{
    apr_pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = apr_palloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = chunked_body_matcher;

    return mp;
}
static bool chunked_body_chunks_matcher(apr_pool_t *pool,
                                        const mhMatchingPattern_t *mp,
                                        const mhRequest_t *req)
{
    const apr_array_header_t *chunks;
    int i;

    if (req->chunked == NO)
        return NO;

    chunks = mp->baton;
    if (chunks->nelts != req->chunks->nelts)
        return NO;

    for (i = 0 ; i < chunks->nelts; i++) {
        const char *expected, *actual;

        expected = APR_ARRAY_IDX(chunks, i, const char *);
        actual = APR_ARRAY_IDX(req->chunks, i, const char *);
        if (strcmp(expected, actual) != 0)
            return NO;
    }

    return YES;
}

mhMatchingPattern_t *
mhMatchChunkedBodyChunksEqualTo(MockHTTP *mh, ...)
{
    apr_pool_t *pool = mh->pool;
    apr_array_header_t *chunks;
    va_list argp;

    chunks = apr_array_make(pool, 5, sizeof(const char *));
    va_start(argp, mh);
    while (1) {
        const char *chunk = va_arg(argp, const char *);
        if (chunk == NULL) break;
        *((const char **)apr_array_push(chunks)) = chunk;
    }
    va_end(argp);

    mhMatchingPattern_t *mp = apr_palloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = chunks;
    mp->matcher = chunked_body_chunks_matcher;

    return mp;
}

static bool
header_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
               const mhRequest_t *req)
{
    const char *actual = getHeader(mp, req->hdrs, mp->baton2);
    return str_matcher(mp, actual);
}

mhMatchingPattern_t *
mhMatchHeaderEqualTo(MockHTTP *mh, const char *hdr, const char *value)
{
    apr_pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = apr_palloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, value);
    mp->baton2 = apr_pstrdup(pool, hdr);
    mp->matcher = header_matcher;

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

static bool method_matcher(apr_pool_t *pool, const mhMatchingPattern_t *mp,
                           const mhRequest_t *req)
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
constructRequestMatcher(MockHTTP *mh, const char *method, va_list argp)
{
    apr_pool_t *pool = mh->pool;

    mhRequestMatcher_t *rm = apr_palloc(pool, sizeof(mhRequestMatcher_t));
    rm->pool = pool;
    rm->method = apr_pstrdup(pool, method);
    rm->matchers = apr_array_make(pool, 5, sizeof(mhMatchingPattern_t *));

    while (1) {
        mhMatchingPattern_t *mp;
        mp = va_arg(argp, mhMatchingPattern_t *);
        if (mp == NULL) break;
        *((mhMatchingPattern_t **)apr_array_push(rm->matchers)) = mp;
    }
    return rm;
}

mhRequestMatcher_t *mhGetRequest(MockHTTP *mh, ...)
{
    va_list argp;
    mhRequestMatcher_t *rm;

    va_start(argp, mh);
    rm = constructRequestMatcher(mh, "GET", argp);
    va_end(argp);

    return rm;
}

mhRequestMatcher_t *mhPostRequest(MockHTTP *mh, ...)
{
    va_list argp;
    mhRequestMatcher_t *rm;

    va_start(argp, mh);
    rm = constructRequestMatcher(mh, "POST", argp);
    va_end(argp);

    return rm;
}

bool
_mhRequestMatcherMatch(const mhRequestMatcher_t *rm, const mhRequest_t *req)
{
    int i;
    apr_pool_t *match_pool;

    if (strcicmp(rm->method, req->method) != 0) {
        return NO;
    }

    apr_pool_create(&match_pool, rm->pool);

    for (i = 0 ; i < rm->matchers->nelts; i++) {
        const mhMatchingPattern_t *mp;

        mp = APR_ARRAY_IDX(rm->matchers, i, mhMatchingPattern_t *);
        if (mp->matcher(match_pool, mp, req) == NO)
            return NO;
    }
    apr_pool_destroy(match_pool);

    return YES;
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
    resp->code = 200;
    resp->body = "";
    resp->hdrs = apr_hash_make(pool);
    resp->builders = apr_array_make(pool, 5, sizeof(mhRespBuilder_t *));

    va_start(argp, mh);
    while (1) {
        mhRespBuilder_t *rb;
        rb = va_arg(argp, mhRespBuilder_t *);
        if (rb == NULL) break;
        *((mhRespBuilder_t **)apr_array_push(resp->builders)) = rb;
    }
    va_end(argp);

    return resp;
}

typedef struct RespBuilderHelper_t {
    int code;
    const char *body;
    const char *header;
    const char *value;
    bool chunked;
} RespBuilderHelper_t;

static void respCodeSetter(mhResponse_t *resp, void *baton)
{
    RespBuilderHelper_t *rbh = baton;
    resp->code = rbh->code;
}

mhRespBuilder_t *mhRespSetCode(MockHTTP *mh, unsigned int code)
{
    apr_pool_t *pool = mh->pool;
    mhRespBuilder_t *rb;

    RespBuilderHelper_t *rbh = apr_palloc(pool, sizeof(RespBuilderHelper_t));
    rbh->code = code;

    rb = apr_palloc(pool, sizeof(mhRespBuilder_t));
    rb->baton = rbh;
    rb->builder = respCodeSetter;
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
    apr_hash_set(resp->hdrs, rbh->header, APR_HASH_KEY_STRING, rbh->value);
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

int mhVerifyAllRequestsReceived(MockHTTP *mh)
{
    int i;

    for (i = 0; i < mh->reqsReceived->nelts; i++)
    {
        mhRequest_t *req = APR_ARRAY_IDX(mh->reqsReceived, i, mhRequest_t *);
        int j;
        bool matched = NO;

        for (j = 0 ; j < mh->reqMatchers->nelts; j++) {
            const ReqMatcherRespPair_t *pair;

            pair = APR_ARRAY_IDX(mh->reqMatchers, i, ReqMatcherRespPair_t *);

            if (_mhRequestMatcherMatch(pair->rm, req) == YES) {
                matched = YES;
                break;
            }
        }

        if (matched == NO)
            return NO;
    }
    return YES;
}

int mhVerifyAllRequestsReceivedInOrder(MockHTTP *mh)
{
    int i;

    if (mh->reqsReceived->nelts != mh->reqMatchers->nelts)
        return NO;

    for (i = 0; i < mh->reqsReceived->nelts; i++)
    {
        const ReqMatcherRespPair_t *pair;
        const mhRequest_t *req;

        pair = APR_ARRAY_IDX(mh->reqMatchers, i, ReqMatcherRespPair_t *);
        req  = APR_ARRAY_IDX(mh->reqsReceived, i, mhRequest_t *);

        if (_mhRequestMatcherMatch(pair->rm, req) == NO) {
            return NO;
        }
    }
    return YES;
}
