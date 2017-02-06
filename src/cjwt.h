/**
 * Copyright 2017 Comcast Cable Communications Management, LLC
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
 *
 */
#include <time.h>

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
#define OPT_ALLOW_ALG_NONE  (1<<0)
#define OPT_ALLOW_ANY_TIME  (1<<1)

/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/
typedef enum {
    alg_none,
    alg_es256,
    alg_es384,
    alg_es512,
    alg_hs256,
    alg_hs384,
    alg_hs512,
    alg_ps256,
    alg_ps384,
    alg_ps512,
    alg_rs256,
    alg_rs384,
    alg_rs512
} jwa_alg_t;

typedef struct {
    jwa_alg_t alg;
    char *kid

    /* Unsupported:
     *  jku
     *  jwk
     *  x5u
     *  x5c
     *  x5t
     *  x5ts256
     *  type
     *  cty
     *  crit
     */
} jose_t;

typedef struct {
    jose_t header;

    char *iss;
    char *sub;
    char *aud;
    struct timespec exp;
    struct timespec nbf;
    struct timespec iat;
    char *jti;

    cJSON *private_claims;

    void *internal_use_only;
} cjwt_t

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/

/**
 *  The function to use to decode and validate a JWT.
 *
 *  @note This function allocates memory associated with the output jwt that
 *        must be freed.  cjwt_destroy() must be called to destry the object
 *        when we are done with it.
 *
 *  @note This function does not
 *
 *  @param encoded [IN]  the incoming encoded JWT (MUST be '\0' terminated string)
 *  @param options [IN]  a bitmask of the options
 *  @param jwt     [OUT] the resulting JWT if found to be valid,
 *                       set to NULL if not successful
 *  @param key     [IN]  the public key to use for validating the signature
 *  @param key_len [IN]  the length of the key in bytes
 *
 *  @retval   0 successful
 *  @retval  -1 invalid jwt format
 *  @retval  -2 mismatched key
 *  ... etc
 */
int cjwt_decode( const char *encoded, unsigned int options, cjwt_t **jwt,
                 const uint8_t *key, size_t key_len );

/**
 */
int cjwt_destroy( cjwt_t **jwt );
