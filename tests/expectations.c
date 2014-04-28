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
#include <apr_strings.h>

#include "MockHTTP.h"

/* Include here to test some internals */
#include "MockHTTP_private.h"

#include "tests.h"
#include "CuTest/CuTest.h"

#define CRLF "\r\n"

void *testSetupNoServer(void *dummy)
{
    return NULL;
}

void *testSetupWithHTTPServer(void *dummy)
{
    MockHTTP *mh;

    mh = mhInit();
    InitMockServers(mh)
      SetupServer(WithHTTP, WithID("server"), WithPort(30080))
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
    mhReqMatcherBldr_t *mp;
    mhRequest_t *req;

    rm = mhGivenRequest(mh, "GET", NULL);
    CuAssertPtrNotNull(tc, rm);
    mp = mhMatchURLEqualTo(mh, "/index.html");
    CuAssertPtrNotNull(tc, mp);

    /* Create a fake request and check that the matcher works */
    req = _mhInitRequest(mh->pool);
    req->url = "/index.html";
    CuAssertIntEquals(tc, mp->matcher(mp, req), YES);

    req = _mhInitRequest(mh->pool);
    req->url = "/index2.html";
    CuAssertIntEquals(tc, mp->matcher(mp, req), NO);
}

static void test_urlnotmatcher(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    mhRequestMatcher_t *rm;
    mhReqMatcherBldr_t *mp;
    mhRequest_t *req;

    rm = mhGivenRequest(mh, "GET", NULL);
    CuAssertPtrNotNull(tc, rm);
    mp = mhMatchURLNotEqualTo(mh, "/index2.html");
    CuAssertPtrNotNull(tc, mp);

    /* Create a fake request and check that the matcher works */
    req = _mhInitRequest(mh->pool);
    req->url = "/index.html";
    CuAssertIntEquals(tc, mp->matcher(mp, req), YES);

    req = _mhInitRequest(mh->pool);
    req->url = "/index2.html";
    CuAssertIntEquals(tc, mp->matcher(mp, req), NO);
}

static void test_methodmatcher(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    mhRequestMatcher_t *rm;
    mhReqMatcherBldr_t *mp;
    mhRequest_t *req;

    mp = mhMatchMethodEqualTo(mh, "get");
    rm = mhGivenRequest(mh, "GET", mp, NULL);
    CuAssertPtrNotNull(tc, rm);

    /* Create a fake request and check that the matcher works */
    req = _mhInitRequest(mh->pool);
    req->method = "get";
    CuAssertIntEquals(tc, mp->matcher(mp, req), YES);
}

static void test_matchrequest(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    mhRequestMatcher_t *rm;
    mhRequest_t *req;

    rm = mhGivenRequest(mh, "GET", mhMatchURLEqualTo(mh, "/index.html"), NULL);

    /* Create a fake request and check that the matcher works */
    req = _mhInitRequest(mh->pool);
    req->method = "get";
    req->url = "/index.html";
    CuAssertIntEquals(tc, _mhRequestMatcherMatch(rm, req), YES);

    /* Create a fake request and check that it doesn't match */
    req = _mhInitRequest(mh->pool);
    req->method = "get";
    req->url = "/notexisting.html";
    CuAssertIntEquals(tc, _mhRequestMatcherMatch(rm, req), NO);
}

#if 0 /* mhNewResponseForRequest is now per server */
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

        /* Respond */
        __resp = mhNewResponseForRequest(__mh, __rm);
        mhConfigResponse(__resp,
                         /*     WithCode(200) */
                         mhRespSetCode(__resp, 200),
                         /*     WithHeader("Connection", "Close") */
                         mhRespAddHeader(__resp, "Connection", "Close"),
                         /*     WithBody("blabla") */
                         mhRespSetBody(__resp, "blabla"),
                         NULL);
        CuAssertPtrNotNull(tc, __resp);

    /* EndGiven */
    }

    req = _mhInitRequest(mh->pool);
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
    req = _mhInitRequest(mh->pool);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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
#endif

static void test_verify_all_reqs_received(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(
        URLEqualTo("/index.html"))
    EndGiven

    /* system under test */
    {
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "GET", "/index.html", hdrs, "1");
        mhRunServerLoop(mh); /* run 2 times, should be sufficient. */
        mhRunServerLoop(mh);
    }

    Verify(mh)
        CuAssertTrue(tc, VerifyAllRequestsReceived);
    EndVerify
}

static const char *
create_large_chunked_body(apr_pool_t *pool, int num_vecs)
{
    int i;
    apr_size_t len;
    struct iovec *vecs;

    vecs = apr_pcalloc(pool, sizeof(struct iovec) * num_vecs);
    for (i = 0; i < num_vecs; i++)
    {
        int chunk_len = 10 * (i + 1) * 3;
        int j;
        char *chunk, *buf;

        /* end with empty chunk */
        if (i == num_vecs - 1)
            chunk_len = 0;

        buf = apr_pcalloc(pool, chunk_len + 1);
        for (j = 0; j < chunk_len; j += 10)
            memcpy(buf + j, "0123456789", 10);

        chunk = apr_pstrcat(pool,
                            apr_psprintf(pool, "%x", chunk_len),
                            CRLF, buf, CRLF, NULL);
        vecs[i].iov_base = chunk;
        vecs[i].iov_len = strlen(chunk);
    }

    return apr_pstrcatv(pool, vecs, num_vecs, &len);
}

static void test_verify_large_chunked_request(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    const char *header = "GET /index.html HTTP/1.1" CRLF
                         "Transfer-Encoding: chunked" CRLF
                         CRLF;
    const char *body = create_large_chunked_body(mh->pool, 4);
    const char *request = apr_pstrcat(mh->pool, header, body, NULL);

    Given(mh)
      GETRequest(URLEqualTo("/index.html"), RawBodyEqualTo(body))
    EndGiven

    /* system under test */
    {
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_size_t len = strlen(request);
        apr_size_t part = len / 2;
        sendData(ctx, request, part);
        mhRunServerLoop(mh);
        sendData(ctx, request + part, len - part);
        mhRunServerLoopCompleteRequests(mh);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "GET", "/index1.html", hdrs, "1");
        mhRunServerLoopCompleteRequests(mh);
        sendRequest(ctx, "POST", "/index2.html", hdrs, "2");
        mhRunServerLoopCompleteRequests(mh);
        sendRequest(ctx, "GET", "/index3.html", hdrs, "3");
        mhRunServerLoopCompleteRequests(mh);
        sendRequest(ctx, "POST", "/index4.html", hdrs, "4");
        mhRunServerLoopCompleteRequests(mh);
        sendRequest(ctx, "GET", "/index5.html", hdrs, "5");
        mhRunServerLoopCompleteRequests(mh);
        sendRequest(ctx, "POST", "/index6.html", hdrs, "6");
        mhRunServerLoopCompleteRequests(mh);
        sendRequest(ctx, "GET", "/index7.html", hdrs, "7");
        mhRunServerLoopCompleteRequests(mh);
        sendRequest(ctx, "POST", "/index8.html", hdrs, "8");
        mhRunServerLoopCompleteRequests(mh);
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
        URLEqualTo("/index0.html"),
        BodyEqualTo("chunk0chunk1")) /* should matched chunked and not chunked */
      GETRequest(
        URLEqualTo("/index1.html"),
        ChunkedBodyEqualTo("1"))
      GETRequest(
        URLEqualTo("/index2.html"),
        ChunkedBodyChunksEqualTo("chunk1", "chunk2"))
    EndGiven

    /* system under test */
    {
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendChunkedRequest(ctx, "GET", "/index0.html", hdrs,
                           "chunk0", "chunk1", NULL);
        mhRunServerLoopCompleteRequests(mh);
        sendChunkedRequest(ctx, "GET", "/index1.html", hdrs, "1", NULL);
        mhRunServerLoopCompleteRequests(mh);
        sendChunkedRequest(ctx, "GET", "/index2.html", hdrs,
                           "chunk1", "chunk2", NULL);
        mhRunServerLoopCompleteRequests(mh);
    }

    Verify(mh)
      CuAssert(tc, ErrorMessage, VerifyAllRequestsReceived);
    EndVerify
}

static void test_verify_req_no_body(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(URLEqualTo("/index1.html"),
                 BodyEqualTo(""))
    EndGiven

    /* system under test */
    {
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        /* sendRequest will not add C-L header when len(body) = 0 */
        sendRequest(ctx, "GET", "/index1.html", hdrs, "");
        mhRunServerLoop(mh);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllRequestsReceived);
    EndVerify
}

static void test_verify_req_raw_body(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(URLEqualTo("/index0.html"),
                 RawBodyEqualTo("chunk1\r\n"
                                "chunk2\r\n"))
    EndGiven

    /* system under test */
    {
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "GET", "/index0.html", hdrs,
                         "chunk1\r\nchunk2\r\n");
        mhRunServerLoop(mh);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllRequestsReceived);
    EndVerify
}

static void test_verify_req_raw_chunked_body(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(URLEqualTo("/index0.html"),
                 RawBodyEqualTo("6\r\nchunk1\r\n"
                                "6\r\nchunk2\r\n"
                                "0\r\n\r\n"))
    EndGiven

    /* system under test */
    {
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendChunkedRequest(ctx, "GET", "/index0.html", hdrs,
                           "chunk1", "chunk2", NULL);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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

/* Test various stubs that partially match the body, but not completely. */
static void test_string_exact_match(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    /* None of these stubs are supposed to match. */
    Given(mh)
      GETRequest(URLEqualTo("/index1.html"), ChunkedBodyEqualTo("chunk1"))
      GETRequest(URLEqualTo("/index2.html"), ChunkedBodyEqualTo("chunk20"))
      GETRequest(URLEqualTo("/index3.html"), ChunkedBodyChunksEqualTo("chunk30",
                                                                      "chunk4"))
      GETRequest(URLEqualTo("/index4.html"), BodyEqualTo("body5"))
      GETRequest(URLEqualTo("/index5.html"), BodyEqualTo("body60"))
    EndGiven

    /* system under test */
    {
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendChunkedRequest(ctx, "GET", "/index1.html", hdrs, "chunk10", NULL);
        mhRunServerLoopCompleteRequests(mh);
        sendChunkedRequest(ctx, "GET", "/index2.html", hdrs, "chunk2", NULL);
        mhRunServerLoopCompleteRequests(mh);
        sendChunkedRequest(ctx, "GET", "/index3.html", hdrs, "chunk3", "chunk40",
                           NULL);
        mhRunServerLoopCompleteRequests(mh);
        sendChunkedRequest(ctx, "GET", "/index4.html", hdrs, "body50", NULL);
        mhRunServerLoopCompleteRequests(mh);
        sendChunkedRequest(ctx, "GET", "/index5.html", hdrs, "body6", NULL);
        mhRunServerLoopCompleteRequests(mh);
    }

    Verify(mh)
      CuAssert(tc, ErrorMessage, !VerifyAllRequestsReceived);
      CuAssertIntEquals(tc, 5, VerifyStats->requestsReceived);
      CuAssertIntEquals(tc, 5, VerifyStats->requestsResponded);
      CuAssertIntEquals(tc, 0, VerifyStats->requestsMatched);
      CuAssertIntEquals(tc, 5, VerifyStats->requestsNotMatched);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        apr_hash_set(hdrs, "Authorization", APR_HASH_KEY_STRING,
                     "TW9ja0hUVFA6TW9ja0hUVFBwd2Q=");
        sendChunkedRequest(ctx, "GET", "/index1.html", hdrs, "1", NULL);
        mhRunServerLoopCompleteRequests(mh);
        sendChunkedRequest(ctx, "GET", "/index2.html", hdrs, "2", NULL);
        mhRunServerLoopCompleteRequests(mh);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllRequestsReceivedInOrder);
    EndVerify
}

static void test_verify_req_header_set(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    unsigned int port = mhServerByIDPortNr(mh, "server");
    clientCtx_t *ctx = initClient(port);
    apr_hash_t *hdrs = apr_hash_make(mh->pool);

    Given(mh)
      GETRequest(
        URLEqualTo("/index1.html"),
        HeaderSet("Authorization"))
    Expect
      AllRequestsReceivedOnce
    EndGiven

    apr_hash_set(hdrs, "Authorization", APR_HASH_KEY_STRING,
                 "TW9ja0hUVFA6TW9ja0hUVFBwd2Q=");
    sendChunkedRequest(ctx, "GET", "/index1.html", hdrs, "1", NULL);
    mhRunServerLoop(mh);

    Verify(mh)
      CuAssertTrue(tc, VerifyAllExpectationsOk);
    EndVerify
}

static void test_verify_req_header_set_fails_if_not_set(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    unsigned int port = mhServerByIDPortNr(mh, "server");
    clientCtx_t *ctx = initClient(port);
    apr_hash_t *hdrs = apr_hash_make(mh->pool);

    Given(mh)
      GETRequest(URLEqualTo("/index1.html"), HeaderSet("Authorization"))
    Expect
      AllRequestsReceivedOnce
    EndGiven

    sendChunkedRequest(ctx, "GET", "/index1.html", hdrs, "1", NULL);
    mhRunServerLoop(mh);

    Verify(mh)
      CuAssertTrue(tc, !VerifyAllExpectationsOk);
    EndVerify
}

static void test_verify_req_header_not_set(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    unsigned int port = mhServerByIDPortNr(mh, "server");
    clientCtx_t *ctx = initClient(port);
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
    unsigned int port = mhServerByIDPortNr(mh, "server");
    clientCtx_t *ctx = initClient(port);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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

static void test_default_response(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      DefaultResponse(WithCode(200), WithRequestBody)

      GETRequest(URLEqualTo("/index1.html"), BodyEqualTo("body1"))
      GETRequest(URLEqualTo("/index2.html"), ChunkedBodyEqualTo("chunk1chunk2"))
    EndGiven

    /* system under test */
    {
        const char *exp_body1 = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                                "\r\nbody1";
        const char *exp_body2 = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                                "\r\n6\r\nchunk1\r\n6\r\nchunk2\r\n0\r\n\r\n";
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        char *buf;
        apr_size_t len;
        apr_status_t status;

        sendRequest(ctx, "GET", "/index1.html", hdrs, "body1");
        mhRunServerLoopCompleteRequests(mh);
        do {
            int curpos = 0;
            status = receiveResponse(ctx, &buf, &len);
            CuAssertStrnEquals(tc, exp_body1 + curpos, len, buf);
            curpos += len;
        } while (status == APR_EAGAIN);

        sendChunkedRequest(ctx, "GET", "/index2.html", hdrs, "chunk1", "chunk2",
                           NULL);
        mhRunServerLoopCompleteRequests(mh);
        do {
            int curpos = 0;
            status = receiveResponse(ctx, &buf, &len);
            CuAssertStrnEquals(tc, exp_body2 + curpos, len, buf);
            curpos += len;
        } while (status == APR_EAGAIN);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllRequestsReceivedInOrder);
      CuAssertIntEquals(tc, 2, VerifyStats->requestsMatched);
      CuAssertIntEquals(tc, 0, VerifyStats->requestsNotMatched);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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


static void test_conn_keep_alive_max_requests(CuTest *tc)
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
        Respond(WithCode(200), WithChunkedBody(""))
      /* These requests will be sent by the client, but shouldn't be handled by
         the server because it has to close the connection first. */
/*      GETRequest(URLEqualTo("/"), BodyEqualTo("5"))
          Respond(WithCode(200), WithChunkedBody(""))
        GETRequest(URLEqualTo("/"), BodyEqualTo("6"))
          Respond(WithCode(200), WithChunkedBody(""))*/
    EndGiven

    InitMockServers(mh)
        ConfigServerWithID("server", WithMaxKeepAliveRequests(4))
    EndInit

    /* system under test */
    {
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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

    mh = mhInit();
    InitMockServers(mh)
      SetupServer(WithHTTP, WithPort(30080))
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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

static void test_init_2httpservers(CuTest *tc)
{
    MockHTTP *mh;

    mh = mhInit();
    InitMockServers(mh)
      SetupServer(WithHTTP, WithID("server1"))
      SetupServer(WithHTTP, WithID("server2"))
    EndInit

    Given(mh)
      GETRequest(URLEqualTo("/index.html"), BodyEqualTo("1"))
        Respond(WithCode(200), WithRequestBody)
      GETRequest(URLEqualTo("/index.html"), BodyEqualTo("2"))
        Respond(WithCode(200), WithRequestBody)
    EndGiven

    /* system under test */
    {
        clientCtx_t *ctx1, *ctx2;
        unsigned int port1, port2;

        port1 = mhServerByIDPortNr(mh, "server1");
        port2 = mhServerByIDPortNr(mh, "server2");

        ctx1 = initClient(port1);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx1, "GET", "/index.html", hdrs, "1");
        mhRunServerLoop(mh);

        ctx2 = initClient(port2);
        sendRequest(ctx2, "GET", "/index.html", hdrs, "2");
        mhRunServerLoop(mh);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllRequestsReceivedInOrder);
    EndVerify

}

static void test_init_httpserver_2ndthread(CuTest *tc)
{
    MockHTTP *mh;

    mh = mhInit();
    InitMockServers(mh)
      SetupServer(WithHTTP, WithPort(30080), InSeparateThread)
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        char *buf;
        apr_size_t len;
        apr_status_t status;

        sendRequest(ctx, "GET", "/index.html", hdrs, "1");
        do {
            int curpos = 0;

            status = receiveResponse(ctx, &buf, &len);
            curpos += len;
        } while (status == APR_EAGAIN || status == APR_TIMEUP);

        sendRequest(ctx, "POST", "/index2.html", hdrs, "1");
        do {
            int curpos = 0;
            status = receiveResponse(ctx, &buf, &len);
            curpos += len;
        } while (status == APR_EAGAIN || status == APR_TIMEUP);
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
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

/* If a request contains both Transfer-Encoding and Content-Length, 
   RFC 2616, 4.4 specified that Content-Length should be ignored. */
static void test_ignore_content_length_when_chunked(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(URLEqualTo("/index.html"), ChunkedBodyEqualTo("chunk1chunk2"))
        Respond(WithCode(200), WithRequestBody)
    EndGiven

    /* system under test */
    {
        const char *exp_body = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                               "\r\n6\r\nchunk1\r\n6\r\nchunk2\r\n0\r\n\r\n";
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        char *buf;
        apr_size_t len;
        apr_status_t status;

        apr_hash_set(hdrs, "Content-Length", APR_HASH_KEY_STRING, "999999");
        /* chunked header is already set by sendChunkedRequest */

        sendChunkedRequest(ctx, "GET", "/index.html", hdrs, "chunk1", "chunk2",
                           NULL);
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

static void test_use_request_body(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(URLEqualTo("/index1.html"), BodyEqualTo("body1"))
        Respond(WithCode(200), WithRequestBody)
      GETRequest(URLEqualTo("/index2.html"))
        Respond(WithCode(200), WithRequestBody)
      GETRequest(URLEqualTo("/index4.html"), ChunkedBodyEqualTo("chunk1chunk2"))
        Respond(WithCode(200), WithRequestBody)
    EndGiven

    /* system under test */
    {
        const char *exp_body1 = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                                "\r\nbody1";
        const char *exp_body2 = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                                "\r\nbody2";
        const char *exp_body3 = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                                "\r\nbody3";
        const char *exp_body4 = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                                "\r\n6\r\nchunk1\r\n6\r\nchunk2\r\n0\r\n\r\n";
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        char *buf;
        apr_size_t len;
        apr_status_t status;

        /* request 1 */
        sendRequest(ctx, "GET", "/index1.html", hdrs, "body1");
        mhRunServerLoopCompleteRequests(mh);
        do {
            int curpos = 0;
            status = receiveResponse(ctx, &buf, &len);
            CuAssertStrnEquals(tc, exp_body1 + curpos, len, buf);
            curpos += len;
        } while (status == APR_EAGAIN);

        /* request 2 */
        sendRequest(ctx, "GET", "/index2.html", hdrs, "body2");
        mhRunServerLoopCompleteRequests(mh);
        do {
            int curpos = 0;
            status = receiveResponse(ctx, &buf, &len);
            CuAssertStrnEquals(tc, exp_body2 + curpos, len, buf);
            curpos += len;
        } while (status == APR_EAGAIN);

        /* request 3 */
        sendRequest(ctx, "GET", "/index2.html", hdrs, "body3");
        mhRunServerLoopCompleteRequests(mh);
        do {
            int curpos = 0;
            status = receiveResponse(ctx, &buf, &len);
            CuAssertStrnEquals(tc, exp_body3 + curpos, len, buf);
            curpos += len;
        } while (status == APR_EAGAIN);

        sendChunkedRequest(ctx, "GET", "/index4.html", hdrs, "chunk1", "chunk2",
                           NULL);
        mhRunServerLoopCompleteRequests(mh);
        do {
            int curpos = 0;
            status = receiveResponse(ctx, &buf, &len);
            CuAssertStrnEquals(tc, exp_body4 + curpos, len, buf);
            curpos += len;
        } while (status == APR_EAGAIN);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllRequestsReceived);
    EndVerify
}

#define CRLF "\r\n"
#define RESPONSE_408 "HTTP/1.1 408 Request Time-out" CRLF\
"Date: Wed, 14 Nov 2012 19:50:35 GMT" CRLF\
"Server: Apache/2.2.17 (Ubuntu)" CRLF\
"Vary: Accept-Encoding" CRLF\
"Content-Length: 305" CRLF\
"Connection: close" CRLF\
"Content-Type: text/html; charset=iso-8859-1" CRLF \
CRLF\
"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"><html><head>"\
"<title>408 Request Time-out</title></head><body><h1>Request Time-out</h1>"\
"<p>Server timeout waiting for the HTTP request from the client.</p><hr>"\
"<address>Apache/2.2.17 (Ubuntu) Server at lgo-ubuntu.local Port 80</address>"\
"</body></html>"

static void test_raw_response(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(URLEqualTo("/index.html"))
        Respond(WithRawData(RESPONSE_408))
    EndGiven

    /* system under test */
    {
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        char *buf;
        apr_size_t len;
        apr_status_t status;

        sendRequest(ctx, "GET", "/index.html", hdrs, "1");
        mhRunServerLoop(mh);
        do {
            const char *exp_body = RESPONSE_408;
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

#define PATTERN "01234567890abdefghijklmnopqrstuvwxyz"
#define EXPECTED_BODY PATTERN PATTERN PATTERN PATTERN PATTERN\
                      PATTERN PATTERN PATTERN PATTERN PATTERN

static void test_pattern_repeat_response(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;

    Given(mh)
      GETRequest(URLEqualTo("/index.html"))
        Respond(WithBodyRepeatedPattern(PATTERN, 10))
    EndGiven

    /* system under test */
    {
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        char *buf;
        apr_size_t len;
        apr_status_t status;

        sendRequest(ctx, "GET", "/index.html", hdrs, "1");
        mhRunServerLoop(mh);
        do {
            const char *exp_body = EXPECTED_BODY;
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

static void test_incomplete_request_body(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    const char *body = "first part\r\n"; /* Unsent "second part\r\n"; */
    Given(mh)
      GETRequest(URLEqualTo("/index.html"),
                 IncompleteBodyEqualTo("first part\r\n"))
        Respond(WithCode(200), WithRequestBody)
    EndGiven

    /* system under test */
    {
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        char *buf;
        apr_size_t len;
        apr_status_t status;

        /* Set Content-Length to the complete body length (first & second part),
           but only send the first part. */
        apr_hash_set(hdrs, "Content-Length", APR_HASH_KEY_STRING, "25");

        sendRequest(ctx, "GET", "/index.html", hdrs, body);
        mhRunServerLoop(mh);
        do {
            const char *exp_body = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n"
            "\r\nfirst part\r\n";
            int curpos = 0;
            status = receiveResponse(ctx, &buf, &len);
            CuAssertStrnEquals(tc, exp_body + curpos, len, buf);
            curpos += len;
            if (curpos >= strlen(exp_body)) {
                CuAssertIntEquals(tc, strlen(exp_body), curpos);
                break;
            }
        } while (status == APR_EAGAIN || status == APR_TIMEUP);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllRequestsReceivedInOrder);
    EndVerify
}

/* same test as test_incomplete_request_body but with a chunked request */
static void test_incomplete_chunked_request_body(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    const char *chunk = "first part\r\n"; /* Unsent "second part\r\n"; */
    Given(mh)
      GETRequest(URLEqualTo("/index.html"),
                 IncompleteBodyEqualTo("first part\r\n"))
        Respond(WithCode(200), WithRequestBody)
    EndGiven

    /* system under test */
    {
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        char *buf;
        apr_size_t len;
        apr_status_t status;

        sendIncompleteChunkedRequest(ctx, "GET", "/index.html", hdrs,
                                     chunk, NULL);
        mhRunServerLoop(mh);
        do {
            const char *exp_body = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked"
            "\r\n\r\nc\r\nfirst part\r\n\r\n0\r\n\r\n";
            int curpos = 0;
            status = receiveResponse(ctx, &buf, &len);
            CuAssertStrnEquals(tc, exp_body + curpos, len, buf);
            curpos += len;
            if (curpos >= strlen(exp_body)) {
                CuAssertIntEquals(tc, strlen(exp_body), curpos);
                break;
            }
        } while (status == APR_EAGAIN || status == APR_TIMEUP);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllRequestsReceivedInOrder);
    EndVerify
}


/* same test as test_incomplete_chunked_request_body but with a chunk parts
   not arriving at once at the server */
static void test_incomplete_large_chunked_request_body(CuTest *tc)
{
    MockHTTP *mh = tc->testBaton;
    apr_size_t len;
    const char *header = "GET /index.html HTTP/1.1" CRLF
                         "Transfer-Encoding: chunked" CRLF
                         CRLF;
#define BODY "0123456789012345678901234567890123456789"
    const char *rawbody = "28" CRLF BODY CRLF "0" CRLF CRLF;
    const char *request = apr_pstrcat(mh->pool, header, rawbody, NULL);
    apr_size_t rawpart = 80; /* right after second 0..9 block */

    Given(mh)
      GETRequest(URLEqualTo("/index.html"),
                 IncompleteBodyEqualTo("01234567890123456789"))
        Respond(WithCode(200), WithChunkedBody("part1", "part2"))
    EndGiven

    /* system under test */
    {
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_status_t status;

        sendData(ctx, request, rawpart);
        mhRunServerLoop(mh);
        do {
            char *buf;
            const char *exp_body = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked"
                                    "\r\n\r\n5\r\npart1\r\n5\r\npart2\r\n"
                                    "0\r\n\r\n";
            int curpos = 0;
            status = receiveResponse(ctx, &buf, &len);
            CuAssertStrnEquals(tc, exp_body + curpos, len, buf);
            curpos += len;
            if (curpos >= strlen(exp_body)) {
                CuAssertIntEquals(tc, strlen(exp_body), curpos);
                break;
            }
        } while (status == APR_EAGAIN || status == APR_TIMEUP);
    }

    Verify(mh)
      CuAssertTrue(tc, VerifyAllRequestsReceived);
    EndVerify
}

static void test_init_httpsserver(CuTest *tc)
{
    MockHTTP *mh;

    mh = mhInit();
    InitMockServers(mh)
      SetupServer(WithHTTPS,
                  WithPort(30080))
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
        unsigned int port = mhServerByIDPortNr(mh, "server");
        clientCtx_t *ctx = initClient(port);
        apr_hash_t *hdrs = apr_hash_make(mh->pool);
        sendRequest(ctx, "GET", "/index.html", hdrs, "1");
        sendRequest(ctx, "POST", "/index2.html", hdrs, "1");
        mhRunServerLoop(mh);
    }

    Verify(mh)
      CuAssert(tc, ErrorMessage, VerifyAllExpectationsOk);
    EndVerify
}

CuSuite *testMockWithHTTPserver(void)
{
    CuSuite *suite = CuSuiteNew();
    CuSuiteSetSetupTeardownCallbacks(suite, testSetupWithHTTPServer,
                                     testTeardown);

    SUITE_ADD_TEST(suite, test_mock_init);
    SUITE_ADD_TEST(suite, test_urlmatcher);
    SUITE_ADD_TEST(suite, test_urlnotmatcher);
    SUITE_ADD_TEST(suite, test_methodmatcher);
    SUITE_ADD_TEST(suite, test_matchrequest);
#if 0
    SUITE_ADD_TEST(suite, test_basic_reqmatch_response);
    SUITE_ADD_TEST(suite, test_basic_reqmatch_response_with_macros);
    SUITE_ADD_TEST(suite, test_one_request_received);
    SUITE_ADD_TEST(suite, test_match_method);
#endif
    SUITE_ADD_TEST(suite, test_verify_all_reqs_received);
    SUITE_ADD_TEST(suite, test_verify_large_chunked_request);
    SUITE_ADD_TEST(suite, test_verify_all_reqs_received_inverse);
    SUITE_ADD_TEST(suite, test_verify_all_reqs_received_in_order);
    SUITE_ADD_TEST(suite, test_verify_all_reqs_received_in_order_more);
    SUITE_ADD_TEST(suite, test_verify_req_chunked_body);
    SUITE_ADD_TEST(suite, test_verify_req_no_body);
    SUITE_ADD_TEST(suite, test_verify_req_raw_body);
    SUITE_ADD_TEST(suite, test_verify_req_raw_chunked_body);
    SUITE_ADD_TEST(suite, test_verify_req_chunked_body_fails);
    SUITE_ADD_TEST(suite, test_string_exact_match);
    SUITE_ADD_TEST(suite, test_verify_req_header);
    SUITE_ADD_TEST(suite, test_verify_req_header_fails);
    SUITE_ADD_TEST(suite, test_verify_req_header_set);
    SUITE_ADD_TEST(suite, test_verify_req_header_set_fails_if_not_set);
    SUITE_ADD_TEST(suite, test_verify_req_header_not_set);
    SUITE_ADD_TEST(suite, test_verify_req_header_not_set_fails_if_set);
    SUITE_ADD_TEST(suite, test_verify_error_message);
    SUITE_ADD_TEST(suite, test_one_request_response);
    SUITE_ADD_TEST(suite, test_default_response);
    SUITE_ADD_TEST(suite, test_one_request_response_chunked);
    SUITE_ADD_TEST(suite, test_connection_close);
    SUITE_ADD_TEST(suite, test_conn_keep_alive_max_requests);
    SUITE_ADD_TEST(suite, test_expectation_all_reqs_received);
    SUITE_ADD_TEST(suite, test_expectation_all_reqs_received_in_order);
    SUITE_ADD_TEST(suite, test_conn_close_handle_reqs_one_by_one);
    SUITE_ADD_TEST(suite, test_ignore_content_length_when_chunked);
    SUITE_ADD_TEST(suite, test_use_request_body);
    SUITE_ADD_TEST(suite, test_raw_response);
    SUITE_ADD_TEST(suite, test_pattern_repeat_response);
    SUITE_ADD_TEST(suite, test_incomplete_request_body);
    SUITE_ADD_TEST(suite, test_incomplete_chunked_request_body);
    SUITE_ADD_TEST(suite, test_incomplete_large_chunked_request_body);

    return suite;
}

CuSuite *testMockNoServer(void)
{
    CuSuite *suite = CuSuiteNew();
    CuSuiteSetSetupTeardownCallbacks(suite, testSetupNoServer, testTeardown);
#if 1
    SUITE_ADD_TEST(suite, test_init_httpserver);
    SUITE_ADD_TEST(suite, test_init_2httpservers);
    SUITE_ADD_TEST(suite, test_init_httpserver_2ndthread);
 #ifdef MOCKHTTP_OPENSSL
//    SUITE_ADD_TEST(suite, test_init_httpsserver);
 #endif
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
