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

#ifndef MockHttp_H
#define MockHttp_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct MockHttp MockHttp;
typedef struct mhMatchingPattern_t mhMatchingPattern_t;
typedef struct mhMapping_t mhMapping_t;

/* Define a mock server */
MockHttp *mhInit();
void mhCleanup(MockHttp *mh);

/* Define expectations*/



/*  */
mhMatchingPattern_t *mhURLEqualTo(MockHttp *mh, const char *expected);
mhMatchingPattern_t *mhMethodEqualTo(MockHttp *mh, const char *expected);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MockHttp_H */
