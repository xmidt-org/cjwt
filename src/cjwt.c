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
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdio.h>

#include <base64.h>
#include <cJSON.h>

#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "cjwt.h"

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
//#define _DEBUG
#ifdef _DEBUG

#define cjwt_error(...) printf(__VA_ARGS__)
#define cjwt_warn(...)  printf(__VA_ARGS__)
#define cjwt_info(...)  printf(__VA_ARGS__)
#define cjwt_rsa_error() ERR_print_errors_fp(stdout)

#else

#define cjwt_error(...)
#define cjwt_warn(...)
#define cjwt_info(...)
#define cjwt_rsa_error()

#endif


/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/
/* none */

/*----------------------------------------------------------------------------*/
/*                            File Scoped Variables                           */
/*----------------------------------------------------------------------------*/
/* none */

/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
/* none */

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
/* none */


/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/
static char *__get_cjson_string( cJSON*, const char*, int* );
static void __get_numericdate( cJSON*, const char*, struct timespec*, int* );
static char *__dup_cjson_string( cJSON*, const char*, int* );
static void __process_aud( cjwt_t*, cJSON*, int* );
static int __verify_hs( cjwt_alg_t, const uint8_t*, size_t, const uint8_t*,
                        size_t, const uint8_t*, size_t );
static int __verify_rsa( cjwt_alg_t, const uint8_t*, size_t, const uint8_t*,
                         size_t, const uint8_t*, size_t );
static int __verify_signature( cjwt_alg_t, const uint8_t *, size_t,
                               const uint8_t*, int, const uint8_t*, size_t );
static uint8_t* __base64_decode_blob( const uint8_t*, size_t, size_t* );
static int __decode_section( cjwt_t*, const uint8_t*, size_t,
                             int (*fn)(cjwt_t*,cJSON*) );
static int __decode_header( cjwt_t*, cJSON* );
static int __decode_payload( cjwt_t*, cJSON* );


/**
 *  Looks up the object with the specified key in the specified object, ensures
 *  it is a string & returns the pointer to the string.
 *
 *  Note: Do not free() the resulting string as it is owned by the cJSON obj.
 *
 *  @param obj  the cJSON object to look in for the key
 *  @param key  the key to look for
 *  @param err  where the error code is written ONLY if there is an error
 *
 *  @return the string value if successful, NULL on error
 */
static char *__get_cjson_string( cJSON *obj, const char *key, int *err )
{
    if( obj ) {
        cJSON *value;

        value = cJSON_GetObjectItem( obj, key );
        if( value ) {
            if( cJSON_String == value->type ) {
                return value->valuestring;
            } else {
                if( err ) {
                    *err = EINVAL;
                }
            }
        }
    }

    return NULL;
}


/**
 *  Validates and sets the JWT NumericDate based data.
 *
 *  @param obj  the JSON to process
 *  @param key  the key to look for
 *  @param t    the timespec to populate (MUST NOT BE NULL)
 *  @param err  where the error code is written ONLY if there is an error
 */
static void __get_numericdate( cJSON *obj, const char *key, struct timespec *t,
                               int *err )
{
    if( obj ) {
        cJSON *value;

        value = cJSON_GetObjectItem( obj, key );
        if( value ) {
            if( cJSON_Number == value->type ) {
                t->tv_sec = value->valueint;
                t->tv_nsec = 0;
            } else {
                if( err ) {
                    *err = EINVAL;
                }
            }
        }
    }
}


/**
 *  Validates and duplicates a key expected to be a string.
 *
 *  Note: This function results in a string that must be free()d.
 *
 *  @param obj  the JSON to process
 *  @param key  the key to look for
 *  @param err  where the error code is written ONLY if there is an error
 *
 *  @return NULL on error or the new string.
 */
static char *__dup_cjson_string( cJSON *obj, const char *key, int *err )
{
    char *value;

    value = __get_cjson_string( obj, key, err );

    if( NULL != value ) {
        return strdup( value );
    }

    return NULL;
}


/**
 *  Converts the 'aud' claim and validates the types match.
 *
 *  Note: No arguments may be NULL.
 *
 *  @param cjwt where to write the data
 *  @param obj  the JSON to process
 *  @param err  where the error code is written ONLY if there is an error
 */
static void __process_aud( cjwt_t *cjwt, cJSON *obj, int *err )
{
    cJSON *aud_json;

    int _err = 0;

    aud_json = cJSON_GetObjectItem( obj, "aud" );
    if( aud_json ) {
        _err = ENOMEM;
        if( cJSON_String == aud_json->type ) {
            cjwt->aud_count = 1;
            cjwt->aud_names = (char**) malloc( sizeof(char*) );
            if( cjwt->aud_names ) {
                cjwt->aud_names[0] = strdup( aud_json->valuestring );
                if( cjwt->aud_names[0] ) {
                    _err = 0;
                }
            }
        } else if( cJSON_Array == aud_json->type ) {
            int len = cJSON_GetArraySize( aud_json );
            if( 0 < len ) {
                int i;

                // Validate they are strings
                for( i = 0; i < len; i++ ) {
                    cJSON *tmp;

                    tmp = cJSON_GetArrayItem( aud_json, i );
                    if( cJSON_String != tmp->type ) {
                        _err = EINVAL;
                        goto done;
                    }
                }

                cjwt->aud_count = len;
                cjwt->aud_names = (char**) malloc( len * sizeof(char*) );
                if( cjwt->aud_names ) {
                    int valid = 0;
                    memset( cjwt->aud_names, 0, (len * sizeof(char*)) );

                    for( i = 0; i < len; i++ ) {
                        cJSON *tmp;

                        tmp = cJSON_GetArrayItem( aud_json, i );
                        cjwt->aud_names[i] = strdup( tmp->valuestring );
                        if( cjwt->aud_names[i] ) {
                            valid++;
                        }
                    }

                    if( len == valid ) {
                        _err = 0;
                    }
                }
            }
        } else {
            _err = EINVAL;
        }
    }

done:
    if( 0 != _err ) {
        *err = _err;
    }
}


/**
 *  Convert the 'alg' string into an enumeration.
 *
 *  @param alg_str the string to convert
 *
 *  @return -1 on error, the cjwt_alg_t enum value when identified
 */
static int __alg_str_to_enum( const char *alg_str )
{
    struct alg_map {
        cjwt_alg_t alg;
        const char *text;
    };
    const struct alg_map m[] = {
        { .alg = alg_none,  .text = "none"  },
        { .alg = alg_es256, .text = "ES256" },
        { .alg = alg_es384, .text = "ES384" },
        { .alg = alg_es512, .text = "ES512" },
        { .alg = alg_hs256, .text = "HS256" },
        { .alg = alg_hs384, .text = "HS384" },
        { .alg = alg_hs512, .text = "HS512" },
        { .alg = alg_ps256, .text = "PS256" },
        { .alg = alg_ps384, .text = "PS384" },
        { .alg = alg_ps512, .text = "PS512" },
        { .alg = alg_rs256, .text = "RS256" },
        { .alg = alg_rs384, .text = "RS384" },
        { .alg = alg_rs512, .text = "RS512" }
    };
    size_t count, i;
    count = sizeof( m ) / sizeof( struct alg_map );

    if( alg_str ) {
        for( i = 0; i < count; i++ ) {
            if( !strcasecmp( alg_str, m[i].text ) ) {
                return m[i].alg;
            }
        }
    }

    return -1;
}


/**
 *  This function verifies the HMAC based signing algorithms.
 *
 *  @param alg     where to write the data
 *  @param in      the data bytes to verify
 *  @param len     the length of the data
 *  @param sig     the signature bytes
 *  @param sig_len the length of the data
 *  @param key     the key bytes
 *  @param key_len the length of the key
 *
 *  @return 0 if successful, EINVAL or ENOMEM on error
 */
static int __verify_hs( cjwt_alg_t alg, const uint8_t *in, size_t len,
                        const uint8_t *sig, size_t sig_len,
                        const uint8_t *key, size_t key_len )
{
    uint8_t result[EVP_MAX_MD_SIZE];
    unsigned int result_len;

    result_len = !sig_len;

    if( alg_hs256 == alg ) {
        HMAC( EVP_sha256(), key, key_len, in, len, result, &result_len );
    } else if( alg_hs384 == alg ) {
        HMAC( EVP_sha384(), key, key_len, in, len, result, &result_len );
    } else if( alg_hs512 == alg ) {
        HMAC( EVP_sha512(), key, key_len, in, len, result, &result_len );
    }

    if( (result_len != sig_len) ||
        (0 != CRYPTO_memcmp(result, sig, sig_len)) )
    {
        return EINVAL;
    }

    return 0;
}


/**
 *  This function verifies the RSA based signing algorithms.
 *
 *  @param alg     where to write the data
 *  @param in      the data bytes to verify
 *  @param len     the length of the data
 *  @param sig     the signature bytes
 *  @param sig_len the length of the data
 *  @param key     the key bytes
 *  @param key_len the length of the key
 *
 *  @return 0 if successful, EINVAL or ENOMEM on error
 */
static int __verify_rsa( cjwt_alg_t alg, const uint8_t *in, size_t len,
                         const uint8_t *sig, size_t sig_len,
                         const uint8_t *key, size_t key_len )
{
    int ret = ENOMEM;
    int rsa_rv = 0;
    BIO *keybio;

    keybio = BIO_new_mem_buf( key, key_len );
    if( keybio ) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        RSA *rsa;

        ret = EINVAL;

        rsa = PEM_read_bio_RSA_PUBKEY( keybio, NULL, NULL, NULL );

        BIO_free( keybio );

        if( !rsa ) {
            cjwt_rsa_error();
            cjwt_error( "key to rsa conversion failed\n" );
            return EINVAL;
        }

        if( alg_rs256 == alg ) {
            SHA256( in, len, digest );
            rsa_rv = RSA_verify( NID_sha256, digest, SHA256_DIGEST_LENGTH,
                                 sig, sig_len, rsa );
        } else if( alg_rs384 == alg ) {
            SHA384( in, len, digest );
            rsa_rv = RSA_verify( NID_sha384, digest, SHA384_DIGEST_LENGTH,
                                 sig, sig_len, rsa );
        } else if( alg_rs512 == alg ) {
            SHA512( in, len, digest );
            rsa_rv = RSA_verify( NID_sha512, digest, SHA512_DIGEST_LENGTH,
                                 sig, sig_len, rsa );
        }

        RSA_free( rsa );
    }

    if( rsa_rv ==  1 ) {
        ret = 0;
    }

    return ret;
}


/**
 *  This function handles the verification of the signature and data integrity.
 *
 *  @param alg     where to write the data
 *  @param in      the data bytes to verify
 *  @param len     the length of the data
 *  @param b64sig  the base64 encoded signature bytes
 *  @param options the options to apply
 *  @param key     the key bytes
 *  @param key_len the length of the key
 *
 *  @return 0 if successful, EINVAL or ENOMEM on error
 */
static int __verify_signature( cjwt_alg_t alg, const uint8_t *in, size_t len,
                               const uint8_t *b64sig, int options,
                               const uint8_t *key, size_t key_len )
{
    int ret = EINVAL;
    size_t sig_len, b64sig_len;
    uint8_t *sig;

    if( alg_none == alg ) {
        if( 0 != (OPT_ALLOW_ALG_NONE & options) ) {
            if( '\0' == *b64sig ) {
                /* Only allow none if there is no signature. */
                return 0;
            } else if( 0 != (OPT_ALLOW_ALG_NONE_IGNORE_SIG & options) ) {
                /* Ignore the signature to make testing simpler. */
                return 0;
            }
        }
        return EINVAL;
    }

    if( (NULL == key) || (key_len < 1) || (!b64sig) ) {
        return EINVAL;
    }

    b64sig_len = strlen( (char*) b64sig );

    sig = __base64_decode_blob( b64sig, b64sig_len, &sig_len );
    if( !sig ) {
        return EINVAL;
    }

    ret = ENOTSUP;
    switch( alg ) {
        // case alg_es256:
        // case alg_es384:
        // case alg_es512:
        case alg_hs256:
        case alg_hs384:
        case alg_hs512:
            ret = __verify_hs( alg, in, len, sig, sig_len, key, key_len );
            break;
        // case alg_ps256:
        // case alg_ps384:
        // case alg_ps512:

        case alg_rs256:
        case alg_rs384:
        case alg_rs512:
            ret = __verify_rsa( alg, in, len, sig, sig_len, key, key_len );
            break;

        default:
            break;
    }

    free( sig );

    return ret;
}

/**
 *  Decode a base64 blob and return the buffer with the bytes.
 *
 *  Note: You need to free what is returned or you'll have a leak.
 *
 *  @param in       the base64 encoded buffer to decode
 *  @param len      the length of the buffer
 *  @param out_len  the length of the decoded buffer
 *
 *  @return the decoded buffer on success or NULL on error
 */
static uint8_t* __base64_decode_blob( const uint8_t *in, size_t len,
                                      size_t *out_len )
{
    uint8_t *buf;
    size_t buf_len;

    buf = NULL;
    buf_len = b64url_get_decoded_buffer_size( len );
    if( 0 < buf_len ) {
        buf = (uint8_t*) malloc( buf_len + 1 );
        if( buf ) {
            int raw_len;

            raw_len = b64url_decode( in, len, buf );
            if( 0 < raw_len ) {
                buf[raw_len] = '\0';
                if( out_len ) {
                    *out_len = raw_len;
                }
            } else {
                free( buf );
                buf = NULL;
            }
        }
    }

    return buf;
}


/**
 *  This function base64 decodes a blob, runs it into the JSON parser, then
 *  calls the provided function to do something with the data.
 *
 *  @param cjwt the jwt to fill in
 *  @param blob the base64 encoded blob to process
 *  @param len  the length of the base64 blob
 *  @param fn   the function to call to process the decoded data
 *
 *  @return 0 on success, error otherwise
 */
static int __decode_section( cjwt_t *cjwt, const uint8_t *blob, size_t len,
                             int (*fn)(cjwt_t*,cJSON*) )
{
    uint8_t *text;
    int rv;

    rv = EINVAL;

    text = __base64_decode_blob( blob, len, NULL );
    if( text ) {
        cJSON *tree;

        tree = cJSON_Parse( (char*) text );

        if( tree ) {

            rv = (*fn)( cjwt, tree );
            cJSON_Delete( tree );
        }

        free( text );
    }

    return rv;
}


/**
 *  This function process the header part of a JWT.
 *
 *  @param cjwt the jwt to fill in
 *  @param tree the JSON document to process
 *
 *  @return 0 on success, error otherwise
 */
static int __decode_header( cjwt_t *cjwt, cJSON *tree )
{
    char *typ_str;

    typ_str = __get_cjson_string( tree, "typ", NULL );
    if( typ_str && !strcasecmp(typ_str, "jwt") ) {
        int alg;

        alg = __alg_str_to_enum( __get_cjson_string(tree, "alg", NULL) );
        if( -1 == alg ) {
            return ENOTSUP;
        } else {
            cjwt->header.alg = alg;
            return 0;
        }
    }

    return EINVAL;
}


/**
 *  This function process the payload part of a JWT.  All public claim types
 *  are validated.  This function must not silently fail or the jwt struct
 *  may be only a partial representation of the actual JWT.
 *
 *  @param cjwt the jwt to fill in
 *  @param tree the JSON document to process
 *
 *  @return 0 on success, error otherwise
 */
static int __decode_payload( cjwt_t *cjwt, cJSON *tree )
{
    int rv = 0;

    cjwt->iss = __dup_cjson_string( tree, "iss", &rv );
    cjwt->sub = __dup_cjson_string( tree, "sub", &rv );
    cjwt->jti = __dup_cjson_string( tree, "jti", &rv );
    __get_numericdate( tree, "exp", &cjwt->exp, &rv );
    __get_numericdate( tree, "nbf", &cjwt->nbf, &rv );
    __get_numericdate( tree, "iat", &cjwt->iat, &rv );

    __process_aud( cjwt, tree, &rv );

    cJSON_DeleteItemFromObject( tree, "iss" );
    cJSON_DeleteItemFromObject( tree, "sub" );
    cJSON_DeleteItemFromObject( tree, "aud" );
    cJSON_DeleteItemFromObject( tree, "jti" );
    cJSON_DeleteItemFromObject( tree, "exp" );
    cJSON_DeleteItemFromObject( tree, "nbf" );
    cJSON_DeleteItemFromObject( tree, "iat" );

    if( 0 < cJSON_GetArraySize(tree) ) {
        cjwt->private_claims = cJSON_Duplicate( tree, 1 );
    }

    return rv;
}

/**
 * validates jwt token and extracts data
 */
int cjwt_decode( const char *encoded, unsigned int options, cjwt_t **jwt,
                 const uint8_t *key, size_t key_len )
{
    cjwt_t *out;
    int ret = 0;
    const char *payload, *signature;
    size_t header_len, payload_len, validation_len;

    //validate inputs
    if( !encoded ) {
        cjwt_error( "null parameter\n" );
        return EINVAL;
    }

    cjwt_info( "parameters cjwt_decode()\n encoded : %s\n options : %d\n", encoded, options );

    // Split the header.payload.signature
    payload = strchr( encoded, '.' );
    if( (NULL == payload) || (encoded == payload)) {
        return EINVAL;
    }
    header_len = payload - encoded;
    payload++;

    signature = strchr( payload, '.' );
    if( (NULL == signature) || (payload == signature) ) {
        return EINVAL;
    }
    payload_len = signature - payload;
    validation_len = signature - encoded;
    signature++;

    ret = ENOMEM;
    out = (cjwt_t*) malloc( sizeof(cjwt_t) );
    if( out ) {
        memset( out, 0, sizeof(cjwt_t) );

        //parse header
        ret = __decode_section( out, (const uint8_t*) encoded, header_len, __decode_header );
        if( !ret ) {
            ret = __verify_signature( out->header.alg, (const uint8_t*) encoded, validation_len, (const uint8_t*) signature, options, key, key_len );
            if( !ret ) {
                //parse payload
                ret = __decode_section( out, (const uint8_t*) payload, payload_len, __decode_payload );
                if( !ret ) {
                    if( jwt ) {
                        *jwt = out;
                        out = NULL;
                    }
                }
            }
        }

        if( NULL != out ) {
            cjwt_destroy( &out );
        }
    }

    return ret;
}

/**
 * cleanup jwt object
 */
int cjwt_destroy( cjwt_t **jwt )
{
    cjwt_t *p = *jwt;

    if( p ) {
        if( p->iss ) {
            free( p->iss );
        }
        if( p->sub ) {
            free( p->sub );
        }
        if( p->jti ) {
            free( p->jti );
        }
        if( p->private_claims ) {
            cJSON_Delete( p->private_claims );
        }
        if( p->aud_names ) {
            size_t i;

            for( i = 0; i < p->aud_count; i++ ) {
                    if( p->aud_names[i] ) {
                        free( p->aud_names[i] );
                    }
                }
                free( p->aud_names );
        }
        free( p );
    }

    return 0;
}
