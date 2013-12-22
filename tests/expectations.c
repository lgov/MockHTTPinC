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

#include <apr.h>
#include <apr_hash.h>

#include "MockHTTP.h"

/* Include here to test some internals */
#include "MockHTTP_private.h"

#include "tests.h"
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

#if 1
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
    mp = mhMatchURLEqualTo(mh, "/index.html");
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

    mp = mhMatchMethodEqualTo(mh, "get");
    rm = mhGetRequest(mh, mp, NULL);
    ASSERT_NOT_NULL(rm);

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

    rm = mhGetRequest(mh, mhMatchURLEqualTo(mh, "/index.html"), NULL);

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

    /* Given(mh) */
    {
        MockHTTP *__mh = mh;
        mhRequestMatcher_t *__rm;
        mhResponse_t *__resp;

        /* GetRequest */
        __rm = mhGetRequest(__mh,
                            /*     URLEqualTo("/index.html") */
                            mhMatchURLEqualTo(__mh, "/index.html"),
                            NULL);
        ASSERT_NOT_NULL(__rm);

        ;

        /* Respond */
        __resp = mhResponse(__mh,
                            /*     WithStatus(200) */
                            mhRespSetStatus(__mh, 200),
                            /*     WithHeader("Connection", "Close") */
                            mhRespAddHeader(__mh, "Connection", "Close"),
                            /*     WithBody("blabla") */
                            mhRespSetBody(__mh, "blabla"),
                            NULL);
        ASSERT_NOT_NULL(__resp);

    /* SubmitGiven */
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

    Given(mh)
      GetRequest(
        URLEqualTo("/index.html"))
      Respond(
        WithStatus(200),
        WithHeader("Connection", "Close"),
        WithBody("blabla"))
    SubmitGiven

    /* verify that the request was received */
    req = _mhRequestInit(mh);
    req->method = "get";
    req->url = "/index.html";
    resp = _mhMatchRequest(mh, req);
    ASSERT_NOT_NULL(resp);
}

CTEST2(expectations, test_one_request_received)
{
    MockHTTP *mh = data->mh;

    Given(mh)
      GetRequest(
        URLEqualTo("/index.html"))
      Respond(
        WithStatus(200),
        WithHeader("Connection", "Close"),
        WithBody("blabla"))
    SubmitGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "GET", "/index.html", hdrs, "1");
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    /* Verify(mh) */
    {
        MockHTTP *__mh = mh;

        /* GetRequestReceivedFor */
        /*     URLEqualTo("/index.html") */
        ASSERT_TRUE(mhVerifyRequestReceived(__mh,
                        mhGetRequestReceivedFor(__mh,
                                mhMatchURLEqualTo(__mh, "/index.html")
                                                ))
                    );
        /* SubmitVerify */
    }

    /* Now with the macro's */
    Verify(mh)
        ASSERT_TRUE(GetRequestReceivedFor(
                        URLEqualTo("/index.html")));
    SubmitVerify
}
#endif

CTEST2(expectations, test_match_method)
{
    MockHTTP *mh = data->mh;

    Given(mh)
        GetRequest(
                   URLEqualTo("/index.html"))
    SubmitGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "POST", "/index.html", hdrs, "1");
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    Verify(mh)
        ASSERT_FALSE(GetRequestReceivedFor(
                         URLEqualTo("/index.html")));
        ASSERT_TRUE(PostRequestReceivedFor(
                         URLEqualTo("/index.html")));
    SubmitVerify
}

#if 0
CTEST2(expectations, test_one_request_response)
{
    MockHTTP *mh = data->mh;
    mhResponse_t *resp;
    mhRequest_t *req;

    Given(mh)
      GetRequest
        URLEqualTo("/index.html")
      Respond
        WithStatus(200)
        WithHeader("Connection", "Close")
        WithBody("blabla")
    SubmitGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "GET", "/index.html", hdrs, "1");
        while (1) {
            mhRunServerLoop(mh);
        }
        receiveResponse(ctx);
    }

    req = _mhRequestInit(mh);
    req->method = "get";
    req->url = "/index.html";
    resp = _mhMatchRequest(mh, req);
    ASSERT_NOT_NULL(resp);
}
#endif

int main(int argc, const char *argv[])
{
    return ctest_main(argc, argv);
}
