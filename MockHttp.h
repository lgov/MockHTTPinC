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

#ifndef MockHTTP_H
#define MockHTTP_H

#include <apr.h>
#include <apr_poll.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define Given(mh)\
            {\
                MockHTTP *__mh = mh;\
                mhResponse_t *__resp;\
                mhRequestMatcher_t *__rm;
#define   GetRequest(x)\
                __rm = mhGetRequestReceivedFor(__mh, (x), NULL);
#define     URLEqualTo(x)\
                mhMatchURLEqualTo(__mh, (x))
#define   Respond(...)\
                __resp = mhResponse(__mh, __VA_ARGS__, NULL);\
                mhPushReqResp(__mh, __rm, __resp);
#define     WithStatus(x)\
                mhRespSetStatus(__mh, (x))
#define     WithHeader(h,v)\
                mhRespAddHeader(__mh, (h), (v))
#define     WithBody(x)\
                mhRespSetBody(__mh, (x))
#define     WithChunkedBody(x)\
                mhRespSetChunkedBody(__mh, (x));
/* Assign local variables to NULL to avoid 'variable unused' warnings. */
#define SubmitGiven\
            __resp = NULL; __rm = NULL; __mh = NULL;\
            }

#define Verify(mh)\
            {\
                MockHTTP *__mh = mh;
#define   GetRequestReceivedFor(x)\
                mhVerifyRequestReceived(__mh,\
                    mhGetRequestReceivedFor(__mh, (x), NULL))
#define   PostRequestReceivedFor(x)\
                mhVerifyRequestReceived(__mh,\
                    mhPostRequestReceivedFor(__mh, (x), NULL))
#define SubmitVerify\
            }

typedef struct MockHTTP MockHTTP;
typedef struct mhMatchingPattern_t mhMatchingPattern_t;
typedef struct mhMapping_t mhMapping_t;
typedef struct mhRequest_t mhRequest_t;
typedef struct mhRequestMatcher_t mhRequestMatcher_t;
typedef struct mhResponse_t mhResponse_t;
typedef struct mhRespBuilder_t mhRespBuilder_t;

/* Define a mock server */
MockHTTP *mhInit(void);
void mhCleanup(MockHTTP *mh);
void mhRunServerLoop(MockHTTP *mh);

void mhPushReqResp(MockHTTP *mh, mhRequestMatcher_t *rm, mhResponse_t *resp);

/* Define expectations*/

/* Request functions */
mhRequestMatcher_t *mhGetRequest(MockHTTP *mh, ...);
mhRequestMatcher_t *mhPostRequest(MockHTTP *mh, ...);

/*  */
mhMatchingPattern_t *mhMatchURLEqualTo(MockHTTP *mh, const char *expected);
mhMatchingPattern_t *mhMatchMethodEqualTo(MockHTTP *mh, const char *expected);
    

/* Response functions */
mhResponse_t *mhResponse(MockHTTP *mh, ...);
mhRespBuilder_t *mhRespSetStatus(MockHTTP *mh, unsigned int status);
mhRespBuilder_t *mhRespSetBody(MockHTTP *mh, const char *body);
mhRespBuilder_t *mhRespSetChunkedBody(MockHTTP *mh, const char *body);
mhRespBuilder_t *
    mhRespAddHeader(MockHTTP *mh, const char *header, const char *value);

/* Verify */
int mhVerifyRequestReceived(MockHTTP *mh, mhRequestMatcher_t *rm);
/* There's no difference in these two functions for now. */
#define mhGetRequestReceivedFor mhGetRequest
#define mhPostRequestReceivedFor mhPostRequest

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHTTP_H */
