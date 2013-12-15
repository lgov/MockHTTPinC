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

/******************************************************************************/
/* Memory management                                                          */
/******************************************************************************/

/* node in a linked list of allocated memory blocks */
struct block_t {
    void *ptr;
    block_t *next;
};

struct pool_t {
    block_t *first;
    block_t *last;
};

/* Allocate a block memory from the pool */
static void *pool_malloc(pool_t *pool, size_t nr_of_bytes)
{
    block_t *block = malloc(sizeof(block_t));
    block->ptr = malloc(nr_of_bytes);
    block->next = NULL;

    /* Store the block in the pool-managed linked list so we can clean it
       up later when we destroy the pool. */
    if (!pool->first) {
        pool->first = pool->last = block;
    } else {
        pool->last->next = block;
        pool->last = pool->last->next;
    }

    return block->ptr;
}

static pool_t *pool_create()
{
    return calloc(1, sizeof(pool_t));
}

static void pool_destroy(pool_t *pool)
{
    block_t *block;

    if (!pool)
        return;

    /* traverse the linked list of memory blocks and cleanup */
    block = pool->first;
    while (block) {
        block_t *this = block;
        block = block->next;
        free(this->ptr);
        free(this);
    }

    free(pool);
}

static char *pool_strdup(pool_t *pool, const char *str)
{
    size_t len = strlen(str);
    char *tgt = pool_malloc(pool, len);
    memcpy(tgt, str, len);

    return tgt;
}

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
    pool_t *pool;
    llnode_t *first;
    llnode_t *last;
};

static linkedlist_t *linkedlist_init(pool_t *pool)
{
    linkedlist_t *l = pool_malloc(pool, sizeof(linkedlist_t));
    l->pool = pool;
    l->first = l->last = NULL;
    return l;
}

static void ll_add(linkedlist_t *l, const void *ptr1, const void *ptr2)
{
    llnode_t *n = pool_malloc(l->pool, sizeof(struct llnode_t));
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
    pool_t *pool = pool_create();

    MockHTTP *mh = pool_malloc(pool, sizeof(struct MockHTTP));
    mh->pool = pool;
    mh->reqs = linkedlist_init(pool);

    return mh;
}

void mhCleanup(MockHTTP *mh)
{
    if (!mh)
        return;

    /* The MockHTTP* is also allocated from mh->pool, so this will destroy
       the MockHTTP structure and all its allocated memory. */
    pool_destroy(mh->pool);

    /* mh ptr is now invalid */
}

/* Define expectations*/

void mhPushReqResp(MockHTTP *mh, mhRequestMatcher_t *rm, mhResponse_t *resp)
{
    ll_add(mh->reqs, rm, resp);
}

mhRequest_t *_mhRequestInit(MockHTTP *mh)
{
    mhRequest_t *req = pool_malloc(mh->pool, sizeof(mhRequest_t));

    return req;
}

/******************************************************************************/
/* Requests matchers: define criteria to match different aspects of a HTTP    */
/* request received by the MockHTTP server.                                   */
/******************************************************************************/
static int url_matcher(const mhMatchingPattern_t *mp, const mhRequest_t *req)
{
    const char *expected = mp->baton;

    if (strcmp(expected, req->url) == 0)
        return YES;

    return NO;
}

mhMatchingPattern_t *
mhMatchURLEqualTo(mhRequestMatcher_t *rm, const char *expected)
{
    pool_t *pool = rm->pool;

    mhMatchingPattern_t *mp = pool_malloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = pool_strdup(pool, expected);
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
    pool_t *pool = rm->pool;

    mhMatchingPattern_t *mp = pool_malloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = pool_strdup(pool, expected);
    mp->matcher = method_matcher;

    ll_add(rm->matchers, mp, NULL);

    return mp;
}

static mhRequestMatcher_t *
createRequestMatcher(MockHTTP *mh, const char *method)
{
    pool_t *pool = mh->pool;

    mhRequestMatcher_t *rm = pool_malloc(pool, sizeof(mhRequestMatcher_t));
    rm->pool = pool;
    rm->method = pool_strdup(pool, method);
    rm->matchers = linkedlist_init(pool);

    return rm;
}

mhRequestMatcher_t *mhGetRequest(MockHTTP *mh)
{
    return createRequestMatcher(mh, "GET");
}

bool _mhMatchRequest(mhRequestMatcher_t *rm, mhRequest_t *req)
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
    pool_t *pool = mh->pool;

    mhResponse_t *resp = pool_malloc(pool, sizeof(mhResponse_t));
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
    pool_t *pool = resp->pool;

    resp->body = pool_strdup(pool, body);
}

void mhRespAddHeader(mhResponse_t *resp, const char *header, const char *value)
{
    ll_add(resp->hdrs, header, value);
}
