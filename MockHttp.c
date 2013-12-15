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

typedef struct block_t block_t;
typedef struct pool_t pool_t;

struct MockHTTP {
    pool_t *pool;
};

/********************************/
/* Memory management            */
/********************************/

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
        pool->last = block;
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

/* Define a MockHTTP context */
MockHTTP *mhInit()
{
    pool_t *pool = pool_create();

    MockHTTP *mh = pool_malloc(pool, sizeof(struct MockHTTP));
    mh->pool = pool;

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
void mhGiven(mhMapping_t *m)
{

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
static int url_matcher(mhMatchingPattern_t *mp, mhRequest_t *req)
{
    const char *expected = mp->baton;

    if (strcmp(expected, req->url) == 0)
        return YES;

    return NO;
}

mhMatchingPattern_t *mhURLEqualTo(MockHTTP *mh, const char *expected)
{
    pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = pool_malloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = pool_strdup(pool, expected);
    mp->matcher = url_matcher;

    return mp;
}

static int strcicmp(const char *a, const char *b)
{
    for (;; a++, b++) {
        if (!*a) {
            if (!*b)
                return 0;
            return -1;
        } else if (!*b) {
            return 1;
        }
        int d = tolower(*a) - tolower(*b);
        if (d != 0)
            return d;
    }
}

static int method_matcher(mhMatchingPattern_t *mp, mhRequest_t *req)
{
    const char *expected = mp->baton;

    if (strcicmp(expected, req->method) == 0)
        return YES;

    return NO;
}

mhMatchingPattern_t *mhMethodEqualTo(MockHTTP *mh, const char *expected)
{
    pool_t *pool = mh->pool;

    mhMatchingPattern_t *mp = pool_malloc(pool, sizeof(mhMatchingPattern_t));
    mp->baton = pool_strdup(pool, expected);
    mp->matcher = method_matcher;

    return mp;
}
