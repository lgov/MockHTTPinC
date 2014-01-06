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

#ifndef MockHTTP_H
#define MockHTTP_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* TODO: define defaults, eg HTTP/1.1 in req/resp */
/* TODO: use requests only once, use them in order, use best matching first */
/* TODO: any method, raw requests + responses */
/* TODO: add delay time for accept skt, response */

/* Note: the variadic macro's used here require C99. Such macro's require at
   least one argument, otherwise compilation will fail. */
#define InitMockHTTP(mh)\
            {\
                MockHTTP *__mh = (mh) = mhInit();
#define   WithHTTPserver(...)\
                mhInitHTTPserver(__mh, __VA_ARGS__, NULL);
#define   WithHTTPSserver(...)
#define   WithHTTPproxy(...)
#define     WithPort(port)\
                mhConstructServerPortSetter(__mh, port)
#define EndInit\
            }

#define Given(mh)\
            {\
                MockHTTP *__mh = mh;\
                mhResponse_t *__resp;\
                mhRequestMatcher_t *__rm;
/*        Requests and high level tests */
#define   GetRequest(...)\
                __rm = mhGetRequest(__mh, __VA_ARGS__, NULL);\
                mhPushRequest(__mh, __rm);
#define   PostRequest(...)\
                __rm = mhPostRequest(__mh, __VA_ARGS__, NULL);\
                mhPushRequest(__mh, __rm);
#define     URLEqualTo(x)\
                mhMatchURLEqualTo(__mh, (x))
#define     BodyEqualTo(x)\
                mhMatchBodyEqualTo(__mh, (x))
#define     HeaderEqualTo(h, v)\
                mhMatchHeaderEqualTo(__mh, (h), (v))
#define     HeaderNotSet(h)\
                mhMatchHeaderEqualTo(__mh, (h), NULL)
/*          Network-level tests */
#define     NotChunkedBodyEqualTo(x)\
                mhMatchNotChunkedBodyEqualTo(__mh, (x))
#define     ChunkedBodyEqualTo(x)\
                mhMatchChunkedBodyEqualTo(__mh, (x))
#define     ChunkedBodyChunksEqualTo(...)\
                mhMatchChunkedBodyChunksEqualTo(__mh, __VA_ARGS__, NULL)
/* TODO: http version, conditional, */
/*        Responses */
#define   Respond(...)\
                __resp = mhResponse(__mh, __VA_ARGS__, NULL);\
                mhSetRespForReq(__mh, __rm, __resp);
#define     WithCode(x)\
                mhRespSetCode(__mh, (x))
#define     WithHeader(h,v)\
                mhRespAddHeader(__mh, (h), (v))
#define     WithBody(x)\
                mhRespSetBody(__mh, (x))
#define     WithChunkedBody(...)\
                mhRespSetChunkedBody(__mh, __VA_ARGS__, NULL)
/* Assign local variables to NULL to avoid 'variable unused' warnings. */
#define EndGiven\
                __resp = NULL; __rm = NULL; __mh = NULL;\
            }

/*        Expectations */
#define   Expect

#define     AllRequestsReceivedOnce\
                mhExpectAllRequestsReceivedOnce(__mh);
#define     AllRequestsReceivedInOrder\
                mhExpectAllRequestsReceivedInOrder(__mh);

#define Verify(mh)\
            {\
                MockHTTP *__mh = mh;
#define   GetRequestReceivedFor(x)\
                mhVerifyRequestReceived(__mh,\
                    mhGetRequestReceivedFor(__mh, (x), NULL))
#define   PostRequestReceivedFor(x)\
                mhVerifyRequestReceived(__mh,\
                    mhPostRequestReceivedFor(__mh, (x), NULL))
#define   VerifyAllRequestsReceived\
                mhVerifyAllRequestsReceived(__mh)
#define   VerifyAllRequestsReceivedInOrder\
                mhVerifyAllRequestsReceivedInOrder(__mh)
#define   VerifyAllExpectationsOk\
               mhVerifyAllExpectationsOk(__mh)
#define   ErrorMessage\
                mhGetLastErrorString(__mh)
#define EndVerify\
            }

typedef struct MockHTTP MockHTTP;
typedef struct mhMatchingPattern_t mhMatchingPattern_t;
typedef struct mhMapping_t mhMapping_t;
typedef struct mhRequest_t mhRequest_t;
typedef struct mhRequestMatcher_t mhRequestMatcher_t;
typedef struct mhResponse_t mhResponse_t;
typedef struct mhRespBuilder_t mhRespBuilder_t;
typedef struct mhServCtx_t mhServCtx_t;
typedef struct mhServerBuilder_t mhServerBuilder_t;

typedef unsigned long mhError_t;
#define MOCKHTTP_NO_ERROR 0
#define MOCKHTTP_SETUP_FAILED 1
#define MOCKHTTP_TEST_FAILED 2

/* Setup a mock HTTP server */
MockHTTP *mhInit(void);
void mhCleanup(MockHTTP *mh);
mhError_t mhInitHTTPserver(MockHTTP *mh, ...);
mhError_t mhRunServerLoop(MockHTTP *mh);
int mhServerPortNr(MockHTTP *mh);
mhServerBuilder_t *mhConstructServerPortSetter(MockHTTP *mh, unsigned int port);

/* Define request stubs */
mhRequestMatcher_t *mhGetRequest(MockHTTP *mh, ...);
mhRequestMatcher_t *mhPostRequest(MockHTTP *mh, ...);
#define mhGetRequestReceivedFor mhGetRequest
#define mhPostRequestReceivedFor mhPostRequest

/* Request matching functions */
mhMatchingPattern_t *mhMatchURLEqualTo(MockHTTP *mh, const char *expected);
mhMatchingPattern_t *mhMatchMethodEqualTo(MockHTTP *mh, const char *expected);
mhMatchingPattern_t *mhMatchBodyEqualTo(MockHTTP *mh, const char *expected);
/* Network level matching functions, for testing of http libraries */
mhMatchingPattern_t *mhMatchBodyNotChunkedEqualTo(MockHTTP *mh,
                                                  const char *expected);
mhMatchingPattern_t *mhMatchChunkedBodyEqualTo(MockHTTP *mh,
                                               const char *expected);
mhMatchingPattern_t *mhMatchChunkedBodyChunksEqualTo(MockHTTP *mh, ...);
mhMatchingPattern_t *mhMatchHeaderEqualTo(MockHTTP *mh,
                                          const char *hdr, const char *value);

/* Response functions */
mhResponse_t *mhResponse(MockHTTP *mh, ...);
mhRespBuilder_t *mhRespSetCode(MockHTTP *mh, unsigned int status);
mhRespBuilder_t *mhRespSetBody(MockHTTP *mh, const char *body);
mhRespBuilder_t *mhRespSetChunkedBody(MockHTTP *mh, ...);
mhRespBuilder_t *mhRespAddHeader(MockHTTP *mh, const char *header,
                                 const char *value);
void mhResponseBuild(mhResponse_t *resp);

/* Define request/response pairs */
void mhPushRequest(MockHTTP *mh, mhRequestMatcher_t *rm);
void mhSetRespForReq(MockHTTP *mh, mhRequestMatcher_t *rm, mhResponse_t *resp);

/* Define expectations */
void mhExpectAllRequestsReceivedOnce(MockHTTP *mh);
void mhExpectAllRequestsReceivedInOrder(MockHTTP *mh);

/* Verify */
int mhVerifyRequestReceived(MockHTTP *mh, mhRequestMatcher_t *rm);
int mhVerifyAllRequestsReceived(MockHTTP *mh);
int mhVerifyAllRequestsReceivedInOrder(MockHTTP *mh);
int mhVerifyAllRequestsReceivedOnce(MockHTTP *mh);
int mhVerifyAllExpectationsOk(MockHTTP *mh);
const char *mhGetLastErrorString(MockHTTP *mh);

#define MOCKHTTP_VERSION 0.1

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHTTP_H */
