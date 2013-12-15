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

#ifndef MockHttp_private_H
#define MockHttp_private_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct mhRequest_t mhRequest_t;
typedef int (*matchfunc_t)(mhMatchingPattern_t *mp, mhRequest_t *req);

struct mhMatchingPattern_t {
    const void *baton;
    matchfunc_t matcher;
};

typedef short int bool;
static const bool YES = 1;
static const bool NO = 0;


struct mhRequest_t {
    const char *method;
    const char *url;
};

/* Initialize a mhRequest_t object. */
mhRequest_t *_mhRequestInit(MockHttp *mh);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHttp_private_H */
