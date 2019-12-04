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

#define IS_RSA_ALG(alg) ((alg) > alg_ps512)


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
static char *__get_cjson_string( cJSON *obj, const char *key );
static void __get_numericdate( cJSON *obj, const char *key, struct timespec *t );
static char *__dup_cjson_string( cJSON *obj, const char *key );
static int __process_aud( cjwt_t *cjwt, cJSON *obj );
static int cjwt_verify_hs( cjwt_t *cjwt, const uint8_t *in, size_t len,
                           const uint8_t *sig, size_t sig_len );
static int cjwt_verify_rsa( cjwt_t *cjwt, const uint8_t *in, size_t len,
                            const uint8_t *sig, size_t sig_len );
static int cjwt_verify_signature( cjwt_t *cjwt, const uint8_t *in, size_t len,
                                  const uint8_t *b64sig, int options );
static uint8_t* cjwt_base64_decode_blob( const uint8_t *head, size_t len, size_t *out_len );
static int cjwt_decode_section( cjwt_t *cjwt, const uint8_t *blob, size_t len,
                                int (*fn)(cjwt_t*,cJSON*) );
static int cjwt_decode_header( cjwt_t *cjwt, cJSON *tree );
static int cjwt_decode_payload( cjwt_t *cjwt, cJSON *tree );
static cjwt_t* cjwt_create( const uint8_t *key, size_t key_len );


/**
 *  Looks up the object with the specified key in the specified object, ensures
 *  it is a string & returns the pointer to the string.
 *
 *  Note: Do not free() the resulting string as it is owned by the cJSON obj.
 *
 *  @param obj the cJSON object to look in for the key
 *  @param key the key to look for
 *
 *  @return the string value if successful, NULL on error
 */
static char *__get_cjson_string( cJSON *obj, const char *key )
{
    if( obj ) {
        cJSON *value;

        value = cJSON_GetObjectItem( obj, key );
        if( value && (cJSON_String == value->type) ) {
            return value->valuestring;
        }
    }

    return NULL;
}

static void __get_numericdate( cJSON *obj, const char *key, struct timespec *t )
{
    if( obj ) {
        cJSON *value;

        value = cJSON_GetObjectItem( obj, key );
        if( value && (cJSON_Number == value->type) ) {
            t->tv_sec = value->valueint;
            t->tv_nsec = 0;
        }
    }
}

static char *__dup_cjson_string( cJSON *obj, const char *key )
{
    char *value;

    value = __get_cjson_string( obj, key );

    if( NULL != value ) {
        return strdup( value );
    }

    return NULL;
}

static int __process_aud( cjwt_t *cjwt, cJSON *obj )
{
    cJSON *aud_json;

    aud_json = cJSON_GetObjectItem( obj, "aud" );
    if( aud_json ) {
        if( cJSON_String == aud_json->type ) {
            cjwt->aud = (p_cjwt_aud_list) malloc( sizeof(cjwt_aud_list_t) );
            if( !cjwt->aud ) {
                return ENOMEM;
            }

            cjwt->aud->count = 1;
            cjwt->aud->names = (char**) malloc( sizeof(char*) );
            if( !cjwt->aud ) {
                return ENOMEM;
            }
            cjwt->aud->names[0] = strdup( aud_json->valuestring );
            if( !cjwt->aud->names[0] ) {
                return ENOMEM;
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
                        return EINVAL;
                    }
                }

                cjwt->aud = (p_cjwt_aud_list) malloc( sizeof(cjwt_aud_list_t) );
                if( !cjwt->aud ) {
                    return ENOMEM;
                }

                cjwt->aud->count = len;
                cjwt->aud->names = (char**) malloc( len * sizeof(char*) );
                if( !cjwt->aud ) {
                    return ENOMEM;
                }
                memset( cjwt->aud->names, 0, (len * sizeof(char*)) );
                for( i = 0; i < len; i++ ) {
                    cJSON *tmp;

                    tmp = cJSON_GetArrayItem( aud_json, i );
                    cjwt->aud->names[i] = strdup( tmp->valuestring );
                    if( !cjwt->aud->names[i] ) {
                        return ENOMEM;
                    }
                }
            }
        }
    }

    return 0;
}

int cjwt_alg_str_to_enum( const char *alg_str )
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

static int cjwt_verify_hs( cjwt_t *cjwt, const uint8_t *in, size_t len, const uint8_t *sig, size_t sig_len )
{
    const EVP_MD *alg;
    uint8_t result[EVP_MAX_MD_SIZE];
    unsigned int result_len;

    switch( cjwt->header.alg ) {
        case alg_hs256: alg = EVP_sha256(); break;
        case alg_hs384: alg = EVP_sha384(); break;
        case alg_hs512: alg = EVP_sha512(); break;
        default:
            return EINVAL;
    }

    HMAC( alg, cjwt->header.key, cjwt->header.key_len, in, len, result, &result_len );

    if( (result_len != sig_len) || (0 != CRYPTO_memcmp(result, sig, sig_len)) ) {
        return EINVAL;
    }

    return 0;
}

static int cjwt_verify_rsa( cjwt_t *cjwt, const uint8_t *in, size_t len, const uint8_t *sig, size_t sig_len )
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    int ret = EINVAL;
    RSA *rsa;
    BIO *keybio;

    keybio = BIO_new_mem_buf( cjwt->header.key, cjwt->header.key_len );
    if( !keybio ) {
        return EINVAL;
    }
    rsa = PEM_read_bio_RSA_PUBKEY( keybio, NULL, NULL, NULL );

    BIO_free( keybio );

    if( !rsa ) {
        cjwt_rsa_error();
        cjwt_error( "key to rsa conversion failed\n" );
        return EINVAL;
    }

    switch( cjwt->header.alg ) {
        case alg_rs256:
            SHA256( in, len, digest );
            ret = RSA_verify( NID_sha256, digest, SHA256_DIGEST_LENGTH, sig, sig_len, rsa );
            break;
        case alg_rs384:
            SHA384( in, len, digest );
            ret = RSA_verify( NID_sha384, digest, SHA384_DIGEST_LENGTH, sig, sig_len, rsa );
            break;
        case alg_rs512:
            SHA512( in, len, digest );
            ret = RSA_verify( NID_sha512, digest, SHA512_DIGEST_LENGTH, sig, sig_len, rsa );
            break;
        default:
            break;
    }

    RSA_free( rsa );

    if( ret ==  1 ) {
        return 0;
    }

    cjwt_rsa_error();
    return EINVAL;
}

static int cjwt_verify_signature( cjwt_t *cjwt, const uint8_t *in, size_t len,
                                  const uint8_t *b64sig, int options )
{
    int ret = EINVAL;
    size_t sig_len, b64sig_len;
    uint8_t *sig;

    if( alg_none == cjwt->header.alg ) {
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

    if( (NULL == cjwt->header.key) || (cjwt->header.key_len < 1) || (!b64sig) ) {
        return EINVAL;
    }

    b64sig_len = strlen( (char*) b64sig );

    sig = cjwt_base64_decode_blob( b64sig, b64sig_len, &sig_len );
    if( !sig ) {
        return EINVAL;
    }

    if( 0 < sig_len ) {
        switch( cjwt->header.alg ) {
            // case alg_es256:
            // case alg_es384:
            // case alg_es512:
            case alg_hs256:
            case alg_hs384:
            case alg_hs512:
                ret = cjwt_verify_hs( cjwt, in, len, sig, sig_len );
                break;
            // case alg_ps256:
            // case alg_ps384:
            // case alg_ps512:

            case alg_rs256:
            case alg_rs384:
            case alg_rs512:
                ret = cjwt_verify_rsa( cjwt, in, len, sig, sig_len );
                break;

            default:
                ret = ENOTSUP;
                break;
        }
    }

    free( sig );

    return ret;
}

/* You need to free what is returned or you'll have a leak.*/
static uint8_t* cjwt_base64_decode_blob( const uint8_t *head, size_t len, size_t *out_len )
{
    uint8_t *buf;
    size_t buf_len;

    buf = NULL;
    buf_len = b64url_get_decoded_buffer_size( len );
    if( 0 < buf_len ) {
        buf = (uint8_t*) malloc( buf_len + 1 );
        if( buf ) {
            int raw_len;

            raw_len = b64url_decode( (uint8_t*) head, len, buf );
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

static int cjwt_decode_section( cjwt_t *cjwt, const uint8_t *blob, size_t len,
                                int (*fn)(cjwt_t*,cJSON*) )
{
    uint8_t *text;
    int rv;

    rv = EINVAL;

    text = cjwt_base64_decode_blob( blob, len, NULL );
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

static int cjwt_decode_header( cjwt_t *cjwt, cJSON *tree )
{
    char *typ_str;

    typ_str = __get_cjson_string( tree, "typ" );
    if( typ_str && !strcasecmp(typ_str, "jwt") ) {
        int alg;

        alg = cjwt_alg_str_to_enum( __get_cjson_string(tree, "alg") );
        if( -1 == alg ) {
            return ENOTSUP;
        } else {
            cjwt->header.alg = alg;
            return 0;
        }
    }

    return EINVAL;
}

static int cjwt_decode_payload( cjwt_t *cjwt, cJSON *tree )
{
    int rv;

    cjwt->iss = __dup_cjson_string( tree, "iss" );
    cjwt->sub = __dup_cjson_string( tree, "sub" );
    cjwt->jti = __dup_cjson_string( tree, "jti" );
    __get_numericdate( tree, "exp", &cjwt->exp );
    __get_numericdate( tree, "nbf", &cjwt->nbf );
    __get_numericdate( tree, "iat", &cjwt->iat );

    rv = __process_aud( cjwt, tree );

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

static cjwt_t* cjwt_create( const uint8_t *key, size_t key_len )
{
    cjwt_t *rv;

    rv = (cjwt_t*) malloc( sizeof(cjwt_t) );

    if( rv ) {
        memset( rv, 0, sizeof(cjwt_t) );
        rv->header.alg = alg_none;

        if( key && key_len ) {
            rv->header.key = (uint8_t*) malloc( key_len * sizeof(uint8_t) );
            if( rv->header.key ) {
                memcpy( rv->header.key, key, key_len );
                rv->header.key_len = key_len;
            } else {
                free( rv );
                rv = NULL;
            }
        }
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
    if( !encoded || !jwt ) {
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

    out = cjwt_create( key, key_len );
    if( !out ) {
        return ENOMEM;
    }

    //parse header
    ret = cjwt_decode_section( out, (const uint8_t*) encoded, header_len, cjwt_decode_header );
    if( !ret ) {
        ret = cjwt_verify_signature( out, (const uint8_t*) encoded, validation_len, (const uint8_t*) signature, options );
        if( !ret ) {
            //parse payload
            ret = cjwt_decode_section( out, (const uint8_t*) payload, payload_len, cjwt_decode_payload );
            if( !ret ) {
                *jwt = out;
                out = NULL;
            }
        }
    }

    if( NULL != out ) {
        cjwt_destroy( &out );
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
        if( p->header.key ) {
            free( p->header.key );
        }
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
        if( p->aud ) {
            int i;

            if( p->aud->names ) {
                for( i = 0; i < p->aud->count; i++ ) {
                    if( p->aud->names[i] ) {
                        free( p->aud->names[i] );
                    }
                }
                free( p->aud->names );
            }
            free( p->aud );
        }
        free( p );
    }

    return 0;
}
