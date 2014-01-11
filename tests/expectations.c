/* Copyright 2014 Lieven Govaerts
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
#include "CuTest/CuTest.h"


void *testSetupNoServer(void *dummy)
{
    return NULL;
}

void *testSetupWithHTTPServer(void *dummy)
{
    MockHTTP *mh;

    InitMockHTTP(mh)
      WithHTTPserver(WithPort(30080))
    EndInit

    return mh;
}

void *testTeardown(void *baton)
{
    MockHTTP *mh = baton;

    mhCleanup(mh);

    return NULL;
}

static void test_mock_init(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    CuAssertPtrNotNull(tc, mh);
}

static void test_urlmatcher(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    mhRequestMatcher_t *rm;
    mhMatchingPattern_t *mp;
    mhRequest_t *req;

    rm = mhGivenRequest(mh, "GET");
    mp = mhMatchURLEqualTo(mh, "/index.html");
    CuAssertPtrNotNull(tc, mp);

    /* Create a fake request and check that the matcher works */
    req = _mhRequestInit(mh);
    req->url = "/index.html";
    CuAssertIntEquals(tc, mp->matcher(mh->pool, mp, req), YES);
}

static void test_methodmatcher(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    mhRequestMatcher_t *rm;
    mhMatchingPattern_t *mp;
    mhRequest_t *req;

    mp = mhMatchMethodEqualTo(mh, "get");
    rm = mhGivenRequest(mh, "GET", mp, NULL);
    CuAssertPtrNotNull(tc, rm);

    /* Create a fake request and check that the matcher works */
    req = _mhRequestInit(mh);
    req->method = "get";
    CuAssertIntEquals(tc, mp->matcher(mh->pool, mp, req), YES);
}

static void test_matchrequest(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    mhRequestMatcher_t *rm;
    mhRequest_t *req;

    rm = mhGivenRequest(mh, "GET", mhMatchURLEqualTo(mh, "/index.html"), NULL);

    /* Create a fake request and check that the matcher works */
    req = _mhRequestInit(mh);
    req->method = "get";
    req->url = "/index.html";
    CuAssertIntEquals(tc, _mhRequestMatcherMatch(rm, req), YES);

    /* Create a fake request and check that it doesn't match */
    req = _mhRequestInit(mh);
    req->method = "get";
    req->url = "/notexisting.html";
    CuAssertIntEquals(tc, _mhRequestMatcherMatch(rm, req), NO);
}

static void test_basic_reqmatch_response(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    mhResponse_t *resp;
    mhRequest_t *req;

    /* Given(mh) */
    {
        MockHTTP *__mh = mh;
        mhRequestMatcher_t *__rm;
        mhResponse_t *__resp;

        /* GETRequest */
        __rm = mhGivenRequest(__mh, "GET",
                             /*     URLEqualTo("/index.html") */
                             mhMatchURLEqualTo(__mh, "/index.html"),
                             NULL);
        mhPushRequest(__mh, __rm);
        CuAssertPtrNotNull(tc, __rm);

        ;

        /* Respond */
        __resp = mhResponse(__mh,
                            /*     WithCode(200) */
                            mhRespSetCode(__mh, 200),
                            /*     WithHeader("Connection", "Close") */
                            mhRespAddHeader(__mh, "Connection", "Close"),
                            /*     WithBody("blabla") */
                            mhRespSetBody(__mh, "blabla"),
                            NULL);
        mhSetRespForReq(__mh, __rm, __resp);
        CuAssertPtrNotNull(tc, __resp);

    /* EndGiven */
    }

    req = _mhRequestInit(mh);
    req->method = "get";
    req->url = "/index.html";
    CuAssertIntEquals(tc, YES, _mhMatchRequest(mh, req, &resp));
    CuAssertPtrNotNull(tc, resp);
}

static void test_basic_reqmatch_response_with_macros(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    mhResponse_t *resp;
    mhRequest_t *req;

    Given(mh)
      GETRequest(
        URLEqualTo("/index.html"))
      Respond(
        WithCode(200),
        WithHeader("Connection", "Close"),
        WithBody("blabla"))
    EndGiven

    /* verify that the request was received */
    req = _mhRequestInit(mh);
    req->method = "get";
    req->url = "/index.html";
    CuAssertIntEquals(tc, YES, _mhMatchRequest(mh, req, &resp));
    CuAssertPtrNotNull(tc, resp);
}

static void test_one_request_received(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(
        URLEqualTo("/index.html"))
    EndGiven

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

        /* GETRequestReceivedFor */
        /*     URLEqualTo("/index.html") */
        CuAssertTrue(tc,
                     mhVerifyRequestReceived(__mh,
                        mhGivenRequest(__mh, "GET",
                                       mhMatchURLEqualTo(__mh, "/index.html"),
                                       NULL)));
        /* EndVerify */
    }

    /* Now with the macro's */
    Verify(mh)
        CuAssertTrue(tc, GETRequestReceivedFor(
                        URLEqualTo("/index.html")));
    EndVerify
}

static void test_match_method(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "POST", "/index.html", hdrs, "1");
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    Verify(mh)
        CuAssertTrue(tc, !GETRequestReceivedFor(
                          URLEqualTo("/index.html")));
        CuAssertTrue(tc, POSTRequestReceivedFor(
                         URLEqualTo("/index.html")));
    EndVerify
}

static void test_verify_all_reqs_received(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(
        URLEqualTo("/index.html"))
    EndGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "GET", "/index.html", hdrs, "1");
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    Verify(mh)
        CuAssertTrue(tc, VerifyAllRequestsReceived);
    EndVerify
}

static void test_verify_all_reqs_received_inverse(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(
        URLEqualTo("/index.html"))
      POSTRequest(
        URLEqualTo("/index2.html"))
    EndGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "GET", "/noindex.html", hdrs, "1");
        sendRequest(ctx, "OPTIONS", "/index.html", hdrs, "2");
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    Verify(mh)
        CuAssertTrue(tc, !VerifyAllRequestsReceived);
    EndVerify
}

static void test_verify_all_reqs_received_in_order(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(
        URLEqualTo("/index.html"))
      POSTRequest(
        URLEqualTo("/index2.html"))
    EndGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "GET", "/index.html", hdrs, "1");
        sendRequest(ctx, "POST", "/index2.html", hdrs, "1");
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    Verify(mh)
        CuAssert(tc, ErrorMessage, VerifyAllRequestsReceivedInOrder);
    EndVerify
}

static void test_verify_all_reqs_received_in_order_more(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(URLEqualTo("/index1.html"))
      POSTRequest(URLEqualTo("/index2.html"))
      GETRequest(URLEqualTo("/index3.html"))
      POSTRequest(URLEqualTo("/index4.html"))
      GETRequest(URLEqualTo("/index5.html"))
      POSTRequest(URLEqualTo("/index6.html"))
      GETRequest(URLEqualTo("/index7.html"))
      POSTRequest(URLEqualTo("/index8.html"))
    EndGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "GET", "/index1.html", hdrs, "1");
        mhRunServerLoop(mh);
        sendRequest(ctx, "POST", "/index2.html", hdrs, "2");
        mhRunServerLoop(mh);
        sendRequest(ctx, "GET", "/index3.html", hdrs, "3");
        mhRunServerLoop(mh);
        sendRequest(ctx, "POST", "/index4.html", hdrs, "4");
        mhRunServerLoop(mh);
        sendRequest(ctx, "GET", "/index5.html", hdrs, "5");
        mhRunServerLoop(mh);
        sendRequest(ctx, "POST", "/index6.html", hdrs, "6");
        mhRunServerLoop(mh);
        sendRequest(ctx, "GET", "/index7.html", hdrs, "7");
        mhRunServerLoop(mh);
        sendRequest(ctx, "POST", "/index8.html", hdrs, "8");
        mhRunServerLoop(mh);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllRequestsReceivedInOrder);
    EndVerify
}

static void test_verify_req_chunked_body(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(
        URLEqualTo("/index1.html"),
        ChunkedBodyEqualTo("1"))
      GETRequest(
        URLEqualTo("/index2.html"),
        ChunkedBodyChunksEqualTo("chunk1", "chunk2"))
    EndGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendChunkedRequest(ctx, "GET", "/index1.html", hdrs, "1", NULL);
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
        sendChunkedRequest(ctx, "GET", "/index2.html", hdrs, "chunk1",
                           "chunk2", NULL);
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllRequestsReceived);
    EndVerify
}

static void test_verify_req_chunked_body_fails(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(
        URLEqualTo("/index.html"),
          ChunkedBodyChunksEqualTo("chunk1", "chunk2"))
    EndGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendChunkedRequest(ctx, "GET", "/index.html", hdrs, "chunk1",
                           "chunk2", "chunk3", NULL);
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    Verify(mh)
      CuAssertTrue(tc, !VerifyAllRequestsReceived);
    EndVerify

    Given(mh)
      GETRequest(
        URLEqualTo("/index2.html"),
          ChunkedBodyChunksEqualTo("chunk1", "chunk2"))
    EndGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendChunkedRequest(ctx, "GET", "/index.html", hdrs, "chunk notfound",
                           "chunk2", NULL);
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    Verify(mh)
      CuAssertTrue(tc, !VerifyAllRequestsReceived);
    EndVerify


}

/* TW9ja0hUVFA6TW9ja0hUVFBwd2Q= is Base64 encoding of MockHTTP:MockHTTPpwd */
static void test_verify_req_header(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(
        URLEqualTo("/index1.html"),
        HeaderEqualTo("Authorization", "TW9ja0hUVFA6TW9ja0hUVFBwd2Q="))
    GETRequest( /* header names are case insensitive */
        URLEqualTo("/index2.html"),
        HeaderEqualTo("autHORIZation", "TW9ja0hUVFA6TW9ja0hUVFBwd2Q="))
    EndGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        apr_hash_set(hdrs, "Authorization", APR_HASH_KEY_STRING,
                     "TW9ja0hUVFA6TW9ja0hUVFBwd2Q=");
        sendChunkedRequest(ctx, "GET", "/index1.html", hdrs, "1", NULL);
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
        sendChunkedRequest(ctx, "GET", "/index2.html", hdrs, "2", NULL);
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllRequestsReceivedInOrder);
    EndVerify
}

static void test_verify_req_header_not_set(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    clientCtx_t *ctx = initClient(mh);
    apr_hash_t *hdrs = apr_hash_make(mh->pool);

    Given(mh)
      GETRequest(
        URLEqualTo("/index1.html"),
        HeaderNotSet("Authorization"))
    Expect
      AllRequestsReceivedOnce
    EndGiven

    sendChunkedRequest(ctx, "GET", "/index1.html", hdrs, "1", NULL);
    mhRunServerLoop(mh);

    Verify(mh)
      CuAssertTrue(tc, VerifyAllExpectationsOk);
    EndVerify
}

static void test_verify_req_header_not_set_fails_if_set(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    clientCtx_t *ctx = initClient(mh);
    apr_hash_t *hdrs = apr_hash_make(mh->pool);

    Given(mh)
      GETRequest(URLEqualTo("/index1.html"), HeaderNotSet("Authorization"))
    Expect
      AllRequestsReceivedOnce
    EndGiven

    apr_hash_set(hdrs, "Authorization", APR_HASH_KEY_STRING,
                 "TW9ja0hUVFA6TW9ja0hUVFBwd2Q=");
    sendChunkedRequest(ctx, "GET", "/index1.html", hdrs, "1", NULL);
    mhRunServerLoop(mh);

    Verify(mh)
      CuAssertTrue(tc, !VerifyAllExpectationsOk);
    EndVerify
}

static void test_verify_req_header_fails(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(
        URLEqualTo("/index1.html"),
        HeaderEqualTo("Authorization", "TW9ja0hUVFA6TW9ja0hUVFBwd2Q="))
    EndGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        apr_hash_set(hdrs, "Authorizatio", APR_HASH_KEY_STRING,
                     "TW9ja0hUVFA6TW9ja0hUVFBwd2Q=");
        sendChunkedRequest(ctx, "GET", "/index1.html", hdrs, "1", NULL);
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
        sendChunkedRequest(ctx, "GET", "/index2.html", hdrs, "2", NULL);
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    Verify(mh)
      CuAssertTrue(tc, !VerifyAllRequestsReceivedInOrder);
    EndVerify
}

static void test_verify_error_message(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
    GETRequest(
      URLEqualTo("/index1.html"),
      HeaderEqualTo("Authorization", "incorrect_value"))
    GETRequest( /* header names are case insensitive */
      URLEqualTo("/index2.html"),
      HeaderEqualTo("autHORIZation", "TW9ja0hUVFA6TW9ja0hUVFBwd2Q="))
    EndGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        apr_hash_set(hdrs, "Authorization", APR_HASH_KEY_STRING,
                     "TW9ja0hUVFA6TW9ja0hUVFBwd2Q=");
        sendChunkedRequest(ctx, "GET", "/index1.html", hdrs, "1", NULL);
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
        sendChunkedRequest(ctx, "GET", "/index2.html", hdrs, "2", NULL);
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    Verify(mh)
      CuAssertTrue(tc, !VerifyAllRequestsReceivedInOrder);
      CuAssertPtrNotNull(tc, (void *)ErrorMessage);
      CuAssertTrue(tc, *ErrorMessage != '\0');
    EndVerify
}

static void test_one_request_response(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(
        URLEqualTo("/index.html"))
      Respond(
        WithCode(200),
        WithHeader("Connection", "Close"),
        WithBody("blabla"))
    EndGiven

    /* system under test */
    {
        const char *exp_body = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n"
                               "Connection: Close\r\n\r\nblabla";
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        char *buf;
        apr_size_t len;
        apr_status_t status;

        sendRequest(ctx, "GET", "/index.html", hdrs, "1");
        mhRunServerLoop(mh);
        mhRunServerLoop(mh);
        mhRunServerLoop(mh);
        do {
            int curpos = 0;
            status = receiveResponse(ctx, &buf, &len);
            CuAssertStrnEquals(tc, exp_body + curpos, len, buf);
            curpos += len;
        } while (status == APR_EAGAIN);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllRequestsReceivedInOrder);
    EndVerify
}

static void test_one_request_response_chunked(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
    GETRequest(
               URLEqualTo("/index.html"))
    Respond(
            WithCode(200),
            WithHeader("Connection", "Close"),
            WithChunkedBody("chunk1", "chunk2"))
    EndGiven

    /* system under test */
    {
        const char *exp_body = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked"
        "\r\nConnection: Close\r\n\r\n6\r\nchunk1\r\n6\r\nchunk2\r\n0\r\n\r\n";
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        char *buf;
        apr_size_t len;
        apr_status_t status;

        sendRequest(ctx, "GET", "/index.html", hdrs, "1");
        mhRunServerLoop(mh);
        mhRunServerLoop(mh);
        mhRunServerLoop(mh);
        do {
            int curpos = 0;
            status = receiveResponse(ctx, &buf, &len);
            CuAssertStrnEquals(tc, exp_body + curpos, len, buf);
            curpos += len;
        } while (status == APR_EAGAIN);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllRequestsReceivedInOrder);
    EndVerify
}

static void test_connection_close(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(URLEqualTo("/index1.html"))
        Respond(WithCode(200),
                WithConnectionCloseHeader,
                WithChunkedBody("chunk1", "chunk2"))
    EndGiven


    /* system under test */
    {
        const char *exp_body = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked"
        "\r\nConnection: close\r\n\r\n6\r\nchunk1\r\n6\r\nchunk2\r\n0\r\n\r\n";
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        char *buf;
        apr_size_t len;
        apr_status_t status;

        sendChunkedRequest(ctx, "GET", "/index1.html", hdrs, "chunk1", "chunk2",
                           NULL);
        mhRunServerLoop(mh);
        mhRunServerLoop(mh);
        mhRunServerLoop(mh);
        do {
            int curpos = 0;
            status = receiveResponse(ctx, &buf, &len);
            CuAssertStrnEquals(tc, exp_body + curpos, len, buf);
            curpos += len;
        } while (status == APR_EAGAIN || status == APR_SUCCESS);
        /* The server should have closed the connection. */
        CuAssertIntEquals(tc, APR_EOF, status);
    }

    Verify(mh)
      CuAssert(tc, ErrorMessage, VerifyAllRequestsReceivedInOrder);
    EndVerify
}

static void test_expectation_all_reqs_received(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(URLEqualTo("/index.html"))
      POSTRequest(URLEqualTo("/index2.html"))
    Expect
      AllRequestsReceivedOnce
    EndGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "POST", "/index2.html", hdrs, "1");
        sendRequest(ctx, "GET", "/index.html", hdrs, "1");
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllExpectationsOk);
      CuAssertTrue(tc, !VerifyAllRequestsReceivedInOrder);
    EndVerify
}

static void test_expectation_all_reqs_received_in_order(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(URLEqualTo("/index.html"))
      POSTRequest(URLEqualTo("/index2.html"))
    Expect
      AllRequestsReceivedInOrder
    EndGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "GET", "/index.html", hdrs, "1");
        sendRequest(ctx, "POST", "/index2.html", hdrs, "1");
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllExpectationsOk);
    EndVerify
}

static void test_init_httpserver(CuTest *tc)
{
    MockHTTP *mh;

    InitMockHTTP(mh)
      WithHTTPserver(WithPort(30080))
    EndInit
    tc->testBaton = mh; /* Ensure server gets cleaned up in testTeardown. */

    Given(mh)
      GETRequest(URLEqualTo("/index.html"))
      POSTRequest(URLEqualTo("/index2.html"))
    Expect
      AllRequestsReceivedInOrder
    EndGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "GET", "/index.html", hdrs, "1");
        sendRequest(ctx, "POST", "/index2.html", hdrs, "1");
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    Verify(mh)
      CuAssert(tc, ErrorMessage, VerifyAllExpectationsOk);
    EndVerify
}

static void test_conn_close_handle_reqs_one_by_one(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(URLEqualTo("/"), BodyEqualTo("1"))
        Respond(WithCode(200), WithChunkedBody(""))
      GETRequest(URLEqualTo("/"), BodyEqualTo("2"))
        Respond(WithCode(200), WithChunkedBody(""))
      GETRequest(URLEqualTo("/"), BodyEqualTo("3"))
        Respond(WithCode(200), WithChunkedBody(""))
      GETRequest(URLEqualTo("/"), BodyEqualTo("4"))
        Respond(WithCode(200), WithChunkedBody(""),
                WithConnectionCloseHeader)
      /* These requests will be sent by the client, but shouldn't be handled by
         the server because it has to close the connection first. */
/*      GETRequest(URLEqualTo("/"), BodyEqualTo("5"))
          Respond(WithCode(200), WithChunkedBody(""))
        GETRequest(URLEqualTo("/"), BodyEqualTo("6"))
          Respond(WithCode(200), WithChunkedBody(""))*/
    EndGiven

    /* system under test */
    {
        clientCtx_t *ctx = initClient(mh);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "GET", "/", hdrs, "1");
        sendRequest(ctx, "GET", "/", hdrs, "2");
        sendRequest(ctx, "GET", "/", hdrs, "3");
        sendRequest(ctx, "GET", "/", hdrs, "4");
        sendRequest(ctx, "GET", "/", hdrs, "5");
        sendRequest(ctx, "GET", "/", hdrs, "6");
        mhRunServerLoop(mh);
    }

    Verify(mh)
      CuAssert(tc, ErrorMessage, VerifyAllRequestsReceivedInOrder);
      CuAssertIntEquals(tc, 4, VerifyStats->requestsReceived);
      CuAssertIntEquals(tc, 4, VerifyStats->requestsResponded);
    EndVerify
}

CuSuite *testMockWithHTTPserver(void)
{
    CuSuite *suite = CuSuiteNew();
    CuSuiteSetSetupTeardownCallbacks(suite, testSetupWithHTTPServer,
                                     testTeardown);
#if 1
    SUITE_ADD_TEST(suite, test_mock_init);
    SUITE_ADD_TEST(suite, test_urlmatcher);
    SUITE_ADD_TEST(suite, test_methodmatcher);
    SUITE_ADD_TEST(suite, test_matchrequest);
    SUITE_ADD_TEST(suite, test_basic_reqmatch_response);
    SUITE_ADD_TEST(suite, test_basic_reqmatch_response_with_macros);
    SUITE_ADD_TEST(suite, test_one_request_received);
    SUITE_ADD_TEST(suite, test_match_method);
    SUITE_ADD_TEST(suite, test_verify_all_reqs_received);
    SUITE_ADD_TEST(suite, test_verify_all_reqs_received_inverse);
    SUITE_ADD_TEST(suite, test_verify_all_reqs_received_in_order);
    SUITE_ADD_TEST(suite, test_verify_all_reqs_received_in_order_more);
    SUITE_ADD_TEST(suite, test_verify_req_chunked_body);
    SUITE_ADD_TEST(suite, test_verify_req_chunked_body_fails);
    SUITE_ADD_TEST(suite, test_verify_req_header);
    SUITE_ADD_TEST(suite, test_verify_req_header_fails);
    SUITE_ADD_TEST(suite, test_verify_req_header_not_set);
    SUITE_ADD_TEST(suite, test_verify_req_header_not_set_fails_if_set);
    SUITE_ADD_TEST(suite, test_verify_error_message);
    SUITE_ADD_TEST(suite, test_one_request_response);
    SUITE_ADD_TEST(suite, test_one_request_response_chunked);
    SUITE_ADD_TEST(suite, test_connection_close);
    SUITE_ADD_TEST(suite, test_expectation_all_reqs_received);
    SUITE_ADD_TEST(suite, test_expectation_all_reqs_received_in_order);
    SUITE_ADD_TEST(suite, test_conn_close_handle_reqs_one_by_one);
#endif

    return suite;
}

CuSuite *testMockNoServer(void)
{
    CuSuite *suite = CuSuiteNew();
    CuSuiteSetSetupTeardownCallbacks(suite, testSetupNoServer, testTeardown);
#if 1
    SUITE_ADD_TEST(suite, test_init_httpserver);
#endif
    return suite;
}

int main(int argc, const char *argv[])
{
    CuString *output = CuStringNew();
    CuSuite* suite = CuSuiteNew();

    CuSuiteAddSuite(suite, testMockWithHTTPserver());
    CuSuiteAddSuite(suite, testMockNoServer());

    CuSuiteRun(suite);
    CuSuiteSummary(suite, output);
    CuSuiteDetails(suite, output);
    printf("%s\n", output->buffer);
}
