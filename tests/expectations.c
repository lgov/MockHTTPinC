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

/* Include here to test some internals */
#include "MockHTTP_private.h"

#define CTEST_MAIN
#include "ctest.h"

CTEST_DATA(expectations) {
    MockHTTP *mh;
};

/* CTest note: the test struct is available in setup/teardown/run
   functions as 'data'. */
CTEST_SETUP(expectations)
{
    MockHTTP *mh = mhInit();

    data->mh = mh;
}

CTEST_TEARDOWN(expectations)
{
    mhCleanup(data->mh);
}

CTEST2(expectations, test_mock_init)
{
    MockHTTP *mh = data->mh;
    ASSERT_NOT_NULL(mh);
}

CTEST2(expectations, test_urlmatcher)
{
    MockHTTP *mh = data->mh;
    mhRequestMatcher_t *rm;
    mhMatchingPattern_t *mp;
    mhRequest_t *req;

    rm = mhGetRequest(mh);
    mp = mhMatchURLEqualTo(rm, "/index.html");
    ASSERT_NOT_NULL(mp);

    /* Create a fake request and check that the matcher works */
    req = _mhRequestInit(mh);
    req->url = "/index.html";
    ASSERT_EQUAL(mp->matcher(mp, req), YES);
}

CTEST2(expectations, test_methodmatcher)
{
    MockHTTP *mh = data->mh;
    mhRequestMatcher_t *rm;
    mhMatchingPattern_t *mp;
    mhRequest_t *req;

    rm = mhGetRequest(mh);
    mp = mhMatchMethodEqualTo(rm, "get");
    ASSERT_NOT_NULL(mp);

    /* Create a fake request and check that the matcher works */
    req = _mhRequestInit(mh);
    req->method = "get";
    ASSERT_EQUAL(mp->matcher(mp, req), YES);
}

CTEST2(expectations, test_matchrequest)
{
    MockHTTP *mh = data->mh;
    mhRequestMatcher_t *rm;
    mhRequest_t *req;

    rm = mhGetRequest(mh);
    mhMatchURLEqualTo(rm, "/index.html");

    /* Create a fake request and check that the matcher works */
    req = _mhRequestInit(mh);
    req->method = "get";
    req->url = "/index.html";
    ASSERT_EQUAL(_mhRequestMatcherMatch(rm, req), YES);

    /* Create a fake request and check that it doesn't match */
    req = _mhRequestInit(mh);
    req->method = "get";
    req->url = "/notexisting.html";
    ASSERT_EQUAL(_mhRequestMatcherMatch(rm, req), NO);
}

CTEST2(expectations, test_basic_reqmatch_response)
{
    MockHTTP *mh = data->mh;
    mhResponse_t *resp;
    mhRequest_t *req;

    /*
     GIVEN(mh)
       GET_REQUEST
         URL_EQUALTO("/index.html")
       RESPOND
         WITH_STATUS(200)
         WITH_HEADER("Connection", "Close")
         WITH_BODY("blabla")
     SUBMIT_GIVEN
     */

    /* GIVEN(mh) */
    {
        MockHTTP *__mh = mh;
        mhRequestMatcher_t *__rm;
        mhResponse_t *__resp;

        /* GET_REQUEST */
        __rm = mhGetRequest(__mh);
        ASSERT_NOT_NULL(__rm);

        /*     URL_EQUALTO("/index.html") */
        mhMatchURLEqualTo(__rm, "/index.html");

        /* RESPOND */
        __resp = mhResponse(__mh);

        /*     WITH_STATUS(200) */
        mhRespSetStatus(__resp, 200);

        /*     WITH_HEADER("Connection", "Close") */
        mhRespAddHeader(__resp, "Connection", "Close");

        /*     WITH_BODY("blabla") */
        mhRespSetBody(__resp, "blabla");

    /* SUBMIT_GIVEN */
        mhPushReqResp(__mh, __rm, __resp);
    }

    req = _mhRequestInit(mh);
    req->method = "get";
    req->url = "/index.html";
    resp = _mhMatchRequest(mh, req);
    ASSERT_NOT_NULL(resp);
}

CTEST2(expectations, test_basic_reqmatch_response_with_macros)
{
    MockHTTP *mh = data->mh;
    mhResponse_t *resp;
    mhRequest_t *req;

     mhGIVEN(mh)
       mhGET_REQUEST
         mhURL_EQUALTO("/index.html")
       mhRESPOND
         mhWITH_STATUS(200)
         mhWITH_HEADER("Connection", "Close")
         mhWITH_BODY("blabla")
     mhSUBMIT_GIVEN

    req = _mhRequestInit(mh);
    req->method = "get";
    req->url = "/index.html";
    resp = _mhMatchRequest(mh, req);
    ASSERT_NOT_NULL(resp);
}

int main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
