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

#include "MockHttp.h"
#include "MockHttp_private.h"

#include <stdlib.h>
#include <string.h>

typedef struct block_t block_t;
typedef struct pool_t pool_t;

struct MockHttp {
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

/* Define a MockHttp context */
MockHttp *mhInit()
{
    pool_t *pool = pool_create();

    MockHttp *mh = pool_malloc(pool, sizeof(struct MockHttp));
    mh->pool = pool;

    return mh;
}

void mhCleanup(MockHttp *mh)
{
    if (!mh)
        return;

    /* The MockHttp * is also allocated from mh->pool, so this will destroy
       the MockHttp structure and all its allocated memory. */
    pool_destroy(mh->pool);
    mh->pool = NULL;
}

/* Define expectations*/



/*  */

int url_matcher(MatchingPattern_t *mp, Request_t *req)
{
    const char *expected = mp->baton;

    if (strcmp(expected, req->url) == 0)
        return YES;

    return NO;
}

MatchingPattern_t *mhURLEqualTo(MockHttp *mh, const char *expected)
{
    pool_t *pool = mh->pool;

    MatchingPattern_t *mp = pool_malloc(pool, sizeof(MatchingPattern_t));
    /* TODO: strdup */
    mp->baton = expected;
    mp->matcher = url_matcher;
    return mp;
}
