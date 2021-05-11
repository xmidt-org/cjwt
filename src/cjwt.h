// SPDX-FileCopyrightText: 2017-2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0
#ifndef __CJWT_H__
#define __CJWT_H__

#include <stdint.h>
#include <time.h>
#include <cjson/cJSON.h>

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
#define OPT_ALLOW_ALG_NONE  (1<<0)
#define OPT_ALLOW_ANY_TIME  (1<<1)


/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/
typedef enum {
    alg_none = 0,
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
    alg_rs512,
    num_algorithms
} cjwt_alg_t;

typedef struct {
    cjwt_alg_t alg;

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
} cjwt_header_t;

typedef struct cjwt_aud_list {
    int  count;
    char **names;
} cjwt_aud_list_t;

typedef struct {
    cjwt_header_t header;

    char *iss;
    char *sub;
    char *jti;

    cjwt_aud_list_t aud;

    struct timespec exp;
    struct timespec nbf;
    struct timespec iat;

    cJSON *private_claims;
} cjwt_t;

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/

/**
 *  The function to use to decode and validate a JWT.
 *
 *  @note This function allocates memory associated with the output jwt that
 *        must be freed.  cjwt_destroy() must be called to destroy the object
 *        when we are done with it.
 *
 *  @param encoded [IN]  the incoming encoded JWT
 *  @param enc_len [IN]  length of the encoded JWT bytes
 *  @param options [IN]  a bitmask of the options
 *  @param jwt     [OUT] the resulting JWT if found to be valid,
 *                       set to NULL if not successful
 *  @param key     [IN]  the public key to use for validating the signature
 *  @param key_len [IN]  the length of the key in bytes
 *
 *  @retval  0       successful
 *  @retval  EINVAL  invalid jwt format or mismatched key
 *  @retval  ENOMEM  unable to allocate needed memory
 *  @retval  ENOTSUP unsupported algorithm
 */
int cjwt_decode( const char *encoded, size_t enc_len, unsigned int options,
                 cjwt_t **jwt, const uint8_t *key, size_t key_len );


/**
 *  The function to free cjwt object
 *
 *  @note Cleanup funtion for corresponding cjwt
 *
 *  @param jwt  [IN] the to be freed cjwt
 *
 *  @retval   0 successful
 */
int cjwt_destroy( cjwt_t *jwt );

#endif
