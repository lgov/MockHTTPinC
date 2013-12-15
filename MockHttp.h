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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct MockHTTP MockHTTP;
typedef struct mhMatchingPattern_t mhMatchingPattern_t;
typedef struct mhMapping_t mhMapping_t;
typedef struct mhRequest_t mhRequest_t;
typedef struct mhRequestMatcher_t mhRequestMatcher_t;
typedef struct mhResponse_t mhResponse_t;

/* Define a mock server */
MockHTTP *mhInit(void);
void mhCleanup(MockHTTP *mh);

void mhPushReqResp(MockHTTP *mh, mhRequestMatcher_t *rm, mhResponse_t *resp);

/* Define expectations*/

/* Request functions */
mhRequestMatcher_t *mhGetRequest(MockHTTP *mh);

/*  */
mhMatchingPattern_t *mhURLEqualTo(mhRequestMatcher_t *rm, const char *expected);
mhMatchingPattern_t *mhMethodEqualTo(mhRequestMatcher_t *rm, const char *expected);
    

/* Response functions */
mhResponse_t *mhResponse(MockHTTP *mh);
void mhRespSetStatus(mhResponse_t *resp, unsigned int status);
void mhRespSetBody(mhResponse_t *resp, const char *body);
void mhRespAddHeader(mhResponse_t *resp, const char *header, const char *value);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHTTP_H */
