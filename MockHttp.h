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
                mhRequestMatcher_t *__rm;\
                mhResponse_t *__resp;
#define   GetRequest\
                __rm = mhGetRequest(__mh);
#define     URLEqualTo(x)\
                mhMatchURLEqualTo(__rm, (x));
#define   Respond\
                __resp = mhResponse(__mh);\
                mhPushReqResp(__mh, __rm, __resp);
#define     WithStatus(x)\
                mhRespSetStatus(__resp, (x));
#define     WithHeader(h,v)\
                mhRespAddHeader(__resp, (h), (v));
#define     WithBody(x)\
                mhRespSetBody(__resp, (x));
#define     WithChunkedBody(x)\
                mhRespSetChunkedBody(__resp, (x));
#define SubmitGiven\
            }

typedef struct MockHTTP MockHTTP;
typedef struct mhMatchingPattern_t mhMatchingPattern_t;
typedef struct mhMapping_t mhMapping_t;
typedef struct mhRequest_t mhRequest_t;
typedef struct mhRequestMatcher_t mhRequestMatcher_t;
typedef struct mhResponse_t mhResponse_t;

/* Define a mock server */
MockHTTP *mhInit(void);
void mhCleanup(MockHTTP *mh);
void mhRunServerLoop(MockHTTP *mh);

void mhPushReqResp(MockHTTP *mh, mhRequestMatcher_t *rm, mhResponse_t *resp);
int mhVerifyRequestReceived(MockHTTP *mh, mhRequestMatcher_t *rm);

/* Define expectations*/

/* Request functions */
mhRequestMatcher_t *mhGetRequest(MockHTTP *mh);

/*  */
mhMatchingPattern_t *mhMatchURLEqualTo(mhRequestMatcher_t *rm, const char *expected);
mhMatchingPattern_t *mhMatchMethodEqualTo(mhRequestMatcher_t *rm, const char *expected);
    

/* Response functions */
mhResponse_t *mhResponse(MockHTTP *mh);
void mhRespSetStatus(mhResponse_t *resp, unsigned int status);
void mhRespSetBody(mhResponse_t *resp, const char *body);
void mhRespSetChunkedBody(mhResponse_t *resp, const char *body);
void mhRespAddHeader(mhResponse_t *resp, const char *header, const char *value);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHTTP_H */
