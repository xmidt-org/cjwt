// SPDX-FileCopyrightText: 2017-2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0
#ifndef __INTERNAL_H__
#define __INTERNAL_H__

#include <stdint.h>
#include <cjson/cJSON.h>

#include "cjwt.h"

/**
 *  This internal file is present to bridge the updated impementation with
 *  the older implementation.  Much of this file will replace the cjwt.h
 *  file when we upgrade the major version to 2.0.0, but moving it to be
 *  internal allows the API to be preserved but the improvements to be used.
 *
 *  The prepending of `__` for functions helps us with this as well.
 */

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
#define OPT_ALLOW_ANY_TYP   (1<<2)


/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/

/* All possible error codes from all the cjwt functions. Future versions may
 * return other values.
 *
 * Always add new return codes last.  Do not remove any.  The return codes
 * must remain the same.
 */
typedef enum {
    CJWTE_OK = 0,
    CJWTE_INVALID_PARAMETERS,           /*  1 */
    CJWTE_INVALID_SECTIONS,             /*  2 */
    CJWTE_OUT_OF_MEMORY,                /*  3 */
    CJWTE_LIBRARY_BUG_SHA,              /*  4 */
    CJWTE_LIBRARY_BUG_RSA,              /*  5 */
    CJWTE_HEADER_MISSING,               /*  6 */
    CJWTE_HEADER_INVALID_BASE64,        /*  7 */
    CJWTE_HEADER_INVALID_JSON,          /*  8 */
    CJWTE_HEADER_MISSING_ALG,           /*  9 */
    CJWTE_HEADER_UNSUPPORTED_ALG,       /* 10 */
    CJWTE_PAYLOAD_MISSING,              /* 11 */
    CJWTE_PAYLOAD_INVALID_BASE64,       /* 12 */
    CJWTE_PAYLOAD_INVALID_JSON,         /* 13 */
    CJWTE_PAYLOAD_AUD_NOT_VALID,        /* 14 */
    CJWTE_PAYLOAD_EXPECTED_STRING,      /* 15 */
    CJWTE_PAYLOAD_EXPECTED_NUMBER,      /* 16 */
    CJWTE_SIGNATURE_MISSING,            /* 17 */
    CJWTE_SIGNATURE_INVALID_BASE64,     /* 18 */
    CJWTE_SIGNATURE_UNSUPPORTED_ALG,    /* 19 */
    CJWTE_SIGNATURE_VALIDATION_FAILED,  /* 20 */
    CJWTE_SIGNATURE_MISSING_KEY,        /* 21 */
    CJWTE_SIGNATURE_INVALID_KEY,        /* 22 */
    CJWTE_TIME_BEFORE_NBF,              /* 23 */
    CJWTE_TIME_AFTER_EXP,               /* 24 */
    CJWTE_HEADER_UNSUPPORTED_TYP,       /* 25 */
    CJWTE_HEADER_UNSUPPORTED_UNKNOWN,   /* 26 */
    CJWTE_KEY_TOO_LARGE,                /* 27 */
    CJWTE_SIGNATURE_KEY_TOO_LARGE,      /* 28 */

    CJWTE_LAST  /* never use! */
} cjwt_code_t;


typedef struct {
    cjwt_header_t header;

    char *iss;
    char *sub;
    char *jti;

    cjwt_aud_list_t aud;

    int64_t *exp;
    int64_t *nbf;
    int64_t *iat;

    cJSON *private_claims;
} __cjwt_t;

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/

/**
 *  The function to use to decode and validate a JWT.
 *
 *  @note This function allocates memory associated with the output jwt that
 *        must be freed.  cjwt_destroy() must be called to destroy the object
 *        when it is no longer needed.
 *
 *  @note This code defaults secure so `alg_none` is not allowed unless
 *        OPT_ALLOW_ALG_NONE is specified as an option.
 *  @note This code defaults strict so only claims with a valid time window
 *        are accepted unless OPT_ALLOW_ANY_TIME is specified as an option.
 *
 *  @param text     [IN]  the original JWT text
 *  @param text_len [IN]  length of the encoded JWT bytes
 *  @param options  [IN]  a bitmask of the options
 *  @param key      [IN]  the public key to use for validating the signature
 *  @param key_len  [IN]  the length of the key in bytes
 *  @param time     [IN]  the time to use for evaluation of time based claims
 *  @param skew     [IN]  the allowed time scew to permit in seconds
 *  @param jwt      [OUT] the resulting JWT if found to be valid,
 *                        set to NULL if not successful
 *
 *  @return  CJWTE_OK if successful, reason for failure otherwise
 */
cjwt_code_t __cjwt_decode( const char *text, size_t text_len, uint32_t options,
                           const uint8_t *key, size_t key_len,
                           int64_t time, int64_t skew, __cjwt_t **jwt );

/**
 *  The function to free cjwt object
 *
 *  @note Cleanup funtion for corresponding cjwt
 *
 *  @param jwt  [IN] the to be freed cjwt
 *
 *  @retval   0 successful
 */
void __cjwt_destroy( __cjwt_t *jwt );

#endif