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

    _mhInitTestServer(mh, "localhost", DefaultSrvPort);

    return mh;
}

void mhCleanup(MockHTTP *mh)
{
    if (!mh)
        return;

    /* The MockHTTP* is also allocated from mh->pool, so this will destroy
       the MockHTTP structure and all its allocated memory. */
    apr_pool_destroy(mh->pool);

    /* mh ptr is now invalid */
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
mhMatchURLEqualTo(mhRequestMatcher_t *rm, const char *expected)
{
    apr_pool_t *pool = rm->pool;

    mhMatchingPattern_t *mp = apr_palloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = url_matcher;

    ll_add(rm->matchers, mp, NULL);

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
mhMatchMethodEqualTo(mhRequestMatcher_t *rm, const char *expected)
{
    apr_pool_t *pool = rm->pool;

    mhMatchingPattern_t *mp = apr_palloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = apr_pstrdup(pool, expected);
    mp->matcher = method_matcher;

    ll_add(rm->matchers, mp, NULL);

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

mhRequestMatcher_t *mhGetRequest(MockHTTP *mh)
{
    return createRequestMatcher(mh, "GET");
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
mhResponse_t *mhResponse(MockHTTP *mh)
{
    apr_pool_t *pool = mh->pool;

    mhResponse_t *resp = apr_palloc(pool, sizeof(mhResponse_t));
    resp->pool = pool;
    resp->status = 200;
    resp->body = "";
    resp->hdrs = linkedlist_init(pool);

    return resp;
}

void mhRespSetStatus(mhResponse_t *resp, unsigned int status)
{
    resp->status = status;
}

void mhRespSetBody(mhResponse_t *resp, const char *body)
{
    apr_pool_t *pool = resp->pool;

    resp->body = apr_pstrdup(pool, body);
    resp->chunked = NO;
}

void mhRespSetChunkedBody(mhResponse_t *resp, const char *body)
{
    apr_pool_t *pool = resp->pool;

    resp->body = apr_pstrdup(pool, body);
    resp->chunked = YES;
}

void mhRespAddHeader(mhResponse_t *resp, const char *header, const char *value)
{
    ll_add(resp->hdrs, header, value);
}
