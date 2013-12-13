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

#include "ext/pocore_stripped.h"

struct MockHttp {
    pc_pool_t *pool;
};

/* Define a mock server */
MockHttp *mhInit()
{
    pc_context_t *ctx = pc_context_create();
    pc_pool_t *pool = pc_pool_root(ctx);

    MockHttp *mh = pc_alloc(pool, sizeof(struct MockHttp));

}

/* Define expectations*/



/*  */
struct MatchingPattern {

};

MatchingPattern * URLEqualTo(const char *expected)
{


}
