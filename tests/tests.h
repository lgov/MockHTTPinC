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

#ifndef MockHTTPinC_tests_h
#define MockHTTPinC_tests_h

#include <apr_hash.h>

typedef struct clientCtx_t clientCtx_t ;

clientCtx_t *initClient();
apr_status_t sendData(clientCtx_t *ctx, const char *data, apr_size_t len);
apr_status_t sendRequest(clientCtx_t *ctx, const char *method, const char *url,
                         const apr_hash_t *hdrs, const char *body);
apr_status_t sendChunkedRequest(clientCtx_t *ctx, const char *method,
                                const char *url, const apr_hash_t *hdrs, ...);
apr_status_t sendIncompleteChunkedRequest(clientCtx_t *ctx, const char *method,
                                          const char *url,
                                          const apr_hash_t *test_hdrs, ...);

apr_status_t receiveResponse(clientCtx_t *ctx, char **buf, apr_size_t *len);

#endif /* MockHTTPinC_tests.h */
