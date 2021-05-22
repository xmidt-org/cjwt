/* SPDX-FileCopyrightText: 2017-2021 Comcast Cable Communications Management, LLC */
/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __CJWT_H__
#define __CJWT_H__

#include <stdint.h>

#include <cjson/cJSON.h>

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/

/* If you specify OPT_ALLOW_ALG_NONE as part of the options bitmask you
 * are allowing `alg_none` to be supported.
 *
 * ---ALG_NONE IS INSECURE AND SHOULD NEVER BE USED IN PRODUCTION---
 */
#define OPT_ALLOW_ALG_NONE  (1<<0)


/* If you specify OPT_ALLOW_ANY_TIME as part of the options bitmask you
 * are telling cjwt to ignore enforcing the 'nbf' and 'exp' declarations
 * from the JWT and always accept the JWT.
 *
 * ---ACCEPTING TOKENS OUTSIDE THEIR INTENDED WINDOW IS DANGEROUS---
 */
#define OPT_ALLOW_ANY_TIME  (1<<1)


/* If you specify OPT_ALLOW_ANY_TYP as part of the options bitmask you
 * are telling cjwt to not strictly enforce the 'typ' processing rules for
 * that header.  CJWT already ignores the case of 'JWT', but this disables
 * the check entirely.
 *
 * This is mainly a strict compliance option & does not impact security.
 */
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


/**
 * The jwt defined algorithms.
 */
typedef enum {
    alg_none = 0,   /* Only allowed if an option is set to prevent dangerous
                     * conditions where an attacker could bypass security
                     * checks.  DO NOT USE THIS IN A PRODUCTION ENVIRONMENT. */
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

    num_algorithms  /* never use! */
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

    int64_t *exp;   /* Time is seconds since Jan 1, 1970 */
    int64_t *nbf;   /* Time is seconds since Jan 1, 1970 */
    int64_t *iat;   /* Time is seconds since Jan 1, 1970 */

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
 *        when it is no longer needed.
 *
 *  @note This code defaults secure so `alg_none` is not allowed unless
 *        OPT_ALLOW_ALG_NONE is specified as an option.
 *
 *  @note This code defaults strict so only claims with a valid time window
 *        are accepted unless OPT_ALLOW_ANY_TIME is specified as an option.
 *
 *  @note The key for HS signed JWTs is the plain text secret.
 *
 *  @note The key for PS, RS and EC signed JWTs expect the text from the PEM
 *        file including the -----BEGIN PUBLIC KEY----- and 
 *        -----END PUBLIC KEY----- lines.
 *
 *  @note The 'time' parameter is seconds since Jan 1, 1970.
 *
 *  @param text     [IN]  the original JWT text
 *  @param text_len [IN]  length of the original text
 *  @param options  [IN]  a bitmask of the options (see #defines at top of file)
 *  @param key      [IN]  the public key to use for validating the signature
 *  @param key_len  [IN]  the length of the key in bytes
 *  @param time     [IN]  the time to use for evaluation of time based claims
 *  @param skew     [IN]  the allowed time skew to accept in seconds
 *  @param jwt      [OUT] the resulting JWT if found to be valid,
 *                        set to NULL if not successful
 *
 *  @return  CJWTE_OK if successful, reason for failure otherwise
 */
cjwt_code_t cjwt_decode( const char *text, size_t text_len, uint32_t options,
                         const uint8_t *key, size_t key_len,
                         int64_t time, int64_t skew, cjwt_t **jwt );


/**
 *  The function that cleans up cjwt object allocations.
 *
 *  @param jwt  [IN] the to be freed cjwt
 */
void cjwt_destroy( cjwt_t *jwt );

#endif
