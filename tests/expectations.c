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

/* Include here to test some internals */
#include "MockHttp_private.h"

#define CTEST_MAIN
#include "ctest.h"

CTEST_DATA(expectations) {
    MockHttp *mh;
};

/* CTest note: the test struct is available in setup/teardown/run
   functions as 'data'. */
CTEST_SETUP(expectations)
{
    MockHttp *mh = mhInit();

    data->mh = mh;
}

CTEST_TEARDOWN(expectations)
{
    mhCleanup(data->mh);
}

CTEST2(expectations, test_mock_init)
{
    MockHttp *mh = data->mh;
    ASSERT_NOT_NULL(mh);
}

CTEST2(expectations, test_urlmatcher)
{
    MockHttp *mh = data->mh;
    mhMatchingPattern_t *mp;
    mhRequest_t *req;

    mp = mhURLEqualTo(mh, "/index.html");
    ASSERT_NOT_NULL(mp);

    req = _mhRequestInit(mh);
    req->url = "/index.html";
    ASSERT_EQUAL(mp->matcher(mp, req), YES);
}

CTEST2(expectations, test_methodmatcher)
{
    MockHttp *mh = data->mh;
    mhMatchingPattern_t *mp;
    mhRequest_t *req;

    mp = mhMethodEqualTo(mh, "get");
    ASSERT_NOT_NULL(mp);

    req = _mhRequestInit(mh);
    req->method = "get";
    ASSERT_EQUAL(mp->matcher(mp, req), YES);
}

int main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
