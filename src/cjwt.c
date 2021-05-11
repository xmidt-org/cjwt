// SPDX-FileCopyrightText: 2017-2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdio.h>

#include <cjson/cJSON.h>

#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "cjwt.h"
#include "b64.h"
#include "utils.h"

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
extern char *strdup(const char *s);


/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/
/* none */

int cjwt_alg_str_to_enum( const char *alg_str, cjwt_alg_t *alg )
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

    for( size_t i = 0; i < sizeof(m) / sizeof(struct alg_map); i++ ) {
        if( !strcmp( alg_str, m[i].text ) ) {
            *alg = m[i].alg;
            return 0;
        }
    }

    return -1;
}


static void cjwt_delete_public_claims( cJSON* json )
{
    const char *claims[] = { "iss",
                             "sub",
                             "aud",
                             "jti",
                             "exp",
                             "nbf",
                             "iat" };

    for( size_t i = 0; i < sizeof(claims)/sizeof(char*); i++ ) {
        if( cJSON_HasObjectItem(json, claims[i]) ) {
            cJSON_DeleteItemFromObject( json, claims[i] );
        }
    }
}


static int cjwt_verify_sha( cjwt_alg_t alg, const char    *full, size_t full_len,
                                            const uint8_t *sig,  size_t sig_len,
                                            const uint8_t *key,  size_t key_len )
{
    const EVP_MD *evp_alg = NULL;
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int len;

    switch( alg ) {
        case alg_hs256:
            evp_alg = EVP_sha256();
            break;
        case alg_hs384:
            evp_alg = EVP_sha384();
            break;
        case alg_hs512:
            evp_alg = EVP_sha512();
            break;
        default:
            return EINVAL;
    }

    HMAC( evp_alg, key, (int) key_len,
          (const unsigned char*) full, full_len,
          buf, &len);

    if( len != sig_len || CRYPTO_memcmp(buf, sig, len) ) {
        return EINVAL;
    }
    return 0;
}


static int cjwt_verify_rsa( cjwt_alg_t alg, const char    *full, size_t full_len,
                                            const uint8_t *sig,  size_t sig_len,
                                            const uint8_t *key,  size_t key_len )
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    int ret = -1;
    RSA *rsa = NULL;
    BIO *keybio = NULL;

    if( (0 == key_len) || (NULL == key) ) {
        return EINVAL;
    }

    keybio = BIO_new_mem_buf( key, (int) key_len );
    if( keybio ) {
        rsa = PEM_read_bio_RSA_PUBKEY( keybio, &rsa, NULL, NULL );
        if( !rsa ) {
            cjwt_rsa_error();
            BIO_free( keybio );
            return EINVAL;
        }
        BIO_free( keybio );
    }

    switch( alg ) {
        case alg_rs256:
            SHA256( (const unsigned char*) full, full_len, digest );
            ret = RSA_verify( NID_sha256, digest, SHA256_DIGEST_LENGTH, sig,
                              (unsigned int) sig_len, rsa );
            break;
        case alg_rs384:
            SHA384( (const unsigned char*) full, full_len, digest );
            ret = RSA_verify( NID_sha384, digest, SHA384_DIGEST_LENGTH, sig,
                              (unsigned int) sig_len, rsa );
            break;
        case alg_rs512:
            SHA512( (const unsigned char*) full, full_len, digest );
            ret = RSA_verify( NID_sha512, digest, SHA512_DIGEST_LENGTH, sig,
                              (unsigned int) sig_len, rsa );
            break;
        default:
            ret = -1;
            break;
    }

    RSA_free( rsa );

    if( ret ==  1 ) {
        return 0;
    }

    return EINVAL;
}

static int cjwt_verify_signature( const cjwt_t *jwt,
                                  const char *full, size_t full_len,
                                  const char *enc_sig, size_t enc_sig_len,
                                  const uint8_t *key, size_t key_len )
{
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    int rv = 0;

    sig = b64_url_decode( enc_sig, enc_sig_len, &sig_len );
    if( !sig ) {
        return EINVAL;
    }

    switch( jwt->header.alg ) {
        case alg_hs256:
        case alg_hs384:
        case alg_hs512:
            rv = cjwt_verify_sha( jwt->header.alg, full, full_len, sig, sig_len,
                                  key, key_len);
            break;
        case alg_rs256:
        case alg_rs384:
        case alg_rs512:
            rv = cjwt_verify_rsa( jwt->header.alg, full, full_len, sig, sig_len,
                                  key, key_len );
            break;
        default:
            rv = ENOTSUP;
            break;
    }

    free( sig );
    return rv;
}

static int process_string( const cJSON *json, const char *name, char **dest )
{
    const cJSON *val = cJSON_GetObjectItemCaseSensitive( json, name );

    if( val ) {
        *dest = strdup( val->valuestring );
        if( !(*dest) ) {
            return ENOMEM;
        }
    }

    return 0;
}

static int process_time( const cJSON *json, const char *name, struct timespec *dest )
{
    const cJSON *val = cJSON_GetObjectItemCaseSensitive( json, name );

    if( val ) {
        cjwt_info( "%s Json  = %s,type=%d,int=%d,double=%f\n", name,
                   cJSON_Print( val ),
                   val->type, val->valueint, val->valuedouble );

        if( val->type == cJSON_Number ) {
            dest->tv_sec = val->valueint;
            dest->tv_nsec = 0;
        } else {
            return ENOTSUP;
        }
    }

    return 0;
}

static int process_aud( const cJSON *json, cjwt_t *cjwt )
{
    const cJSON *tmp = NULL;
    const cJSON *aud = NULL;

    aud = cJSON_GetObjectItemCaseSensitive( json, "aud" );

    if( !aud ) {
        return 0;
    }

    if( aud->type != cJSON_Object ) {
        return EINVAL;
    }

    cjwt->aud.count = cJSON_GetArraySize( aud->child );
    cjwt->aud.names = calloc( cjwt->aud.count, sizeof(char*) );

    if( !cjwt->aud.names ) {
        return ENOMEM;
    }

    for( int i = 0; i < cjwt->aud.count; i++ ) {
        tmp = cJSON_GetArrayItem( aud->child, i );

        if( tmp->type != cJSON_String ) {
            return EINVAL;
        }

        cjwt->aud.names[i] = strdup( tmp->valuestring );
        if( !cjwt->aud.names[i] ) {
            return ENOMEM;
        }
    }

    return 0;
}

static int cjwt_process_payload( cjwt_t *cjwt, const char *payload, size_t len )
{
    int rv = 0;
    size_t decoded_len = 0;
    char *decoded = NULL;
    cJSON *json = NULL;

    decoded = (char*) b64_url_decode( payload, len, &decoded_len );
    if( !decoded ) {
        return EINVAL;
    }

    cjwt_info( "----------------- payload ------------------- \n" );
    cjwt_info( "Payload Size = %zd , Decoded size = %zd\n", len, decoded_len );
    cjwt_info( "Raw data  = '%*s'\n", (int) decoded_len, decoded );

    json = cJSON_ParseWithLength( decoded, decoded_len );
    if( !json ) {
        free( decoded );
        return EINVAL;
    }

    //extract data
    cjwt_info( "Json  = %s\n", cJSON_Print( j_payload ) );
    cjwt_info( "--------------------------------------------- \n\n" );

    rv |= process_string( json, "iss", &cjwt->iss );
    rv |= process_string( json, "sub", &cjwt->sub );
    rv |= process_string( json, "jti", &cjwt->jti );

    rv |= process_time( json, "exp", &cjwt->exp );
    rv |= process_time( json, "nbf", &cjwt->nbf );
    rv |= process_time( json, "iat", &cjwt->iat );

    rv |= process_aud( json, cjwt );

    /* The private_claims either is assigned the json blob or deletes it. */
    cjwt_delete_public_claims( json );
    cjwt_info( "private claims count = %d\n", cJSON_GetArraySize( json ) );

    if( cJSON_GetArraySize( json ) ) {
        cjwt->private_claims = json;
    } else {
        cJSON_Delete( json );
    }

    free( decoded );
    return rv;
}


static int cjwt_process_header( cjwt_t *cjwt, unsigned int options,
                                const char *header, size_t len )
{
    int ret = 0;
    size_t decoded_len = 0;
    char *decoded = NULL;
    cJSON *json = NULL;
    const cJSON *alg = NULL;

    decoded = (char*) b64_url_decode( header, len, &decoded_len );
    if( !decoded ) {
        return EINVAL;
    }

    cjwt_info( "----------------- header -------------------- \n" );
    cjwt_info( "Header Size = %zd , Decoded size = %zd\n", len, decoded_len );
    cjwt_info( "Raw data  = '%*s'\n", (int) decoded_len, decoded );

    json = cJSON_ParseWithLength( decoded, decoded_len );
    if( !json ) {
        free( decoded );
        return EINVAL;
    }

    cjwt_info( "Json  = %s\n", cJSON_Print( json ) );
    cjwt_info( "--------------------------------------------- \n\n" );

    alg = cJSON_GetObjectItemCaseSensitive( json, "alg" );
    if( !alg ) {
        cJSON_Delete( json );
        free( decoded );
        return EINVAL;
    }

    if( 0 != cjwt_alg_str_to_enum( alg->valuestring, &cjwt->header.alg ) ) {
        cJSON_Delete( json );
        free( decoded );
        return ENOTSUP;
    }

    if( alg_none == cjwt->header.alg ) {
        ret = ENOTSUP;
        if( OPT_ALLOW_ALG_NONE & options ) {
            ret = 0;
        }
    }

    cJSON_Delete( json );
    free( decoded );
    return ret;
}


/**
 * validates jwt token and extracts data
 */
int cjwt_decode( const char *encoded, size_t enc_len, unsigned int options,
                 cjwt_t **jwt, const uint8_t *key, size_t key_len )
{
    int ret = 0;
    struct split_jwt sections;
    const struct section *header = NULL;
    const struct section *payload = NULL;

    if( !encoded || !jwt || !enc_len ) {
        return EINVAL;
    }

    if( split(encoded, enc_len, &sections) ) {
        return EINVAL;
    }

    if( (sections.count < 2) || (sections.count < 3) ) {
        return EINVAL;
    }

    header = &sections.sections[0];
    payload = &sections.sections[1];

    if( (!header->len) || (!payload->len) )  {
        return EINVAL;
    }


    cjwt_t *out = calloc( 1, sizeof(cjwt_t) );
    if( !out ) {
        return ENOMEM;
    }

    ret = cjwt_process_header( out, options, header->data, header->len );
    if( ret ) {
        cjwt_error( "Invalid header\n" );
        goto invalid;
    }

    if( out->header.alg != alg_none ) {
        const struct section *sig = NULL;
        size_t signed_len = 0;
        
        sig = &sections.sections[2];
        if( 3 != sections.count || (0 == sig->len)) {
            ret = EINVAL;
            goto invalid;
        }
        signed_len = header->len + payload->len + 1;
        ret = cjwt_verify_signature( out, encoded, signed_len, sig->data, sig->len, key, key_len );

        if( ret ) {
            cjwt_error( "\nSignature authentication failed\n" );
            goto invalid;
        }

        cjwt_info( "\nSignature authentication passed\n" );
    }

    ret = cjwt_process_payload( out, payload->data, payload->len );
    if( ret ) {
        cjwt_error( "Invalid payload\n" );
        goto invalid;
    }

invalid:

    if( ret ) {
        cjwt_destroy( out );
    } else {
        *jwt = out;
    }

    return ret;
}


/**
 * cleanup jwt object
 */
int cjwt_destroy( cjwt_t *jwt )
{
    if( jwt ) {
        if( jwt->iss ) {
            free( jwt->iss );
        }

        if( jwt->sub ) {
            free( jwt->sub );
        }

        if( jwt->jti ) {
            free( jwt->jti );
        }

        for( int i = 0; i < jwt->aud.count; i++ ) {
            if( jwt->aud.names[i] ) {
                free( jwt->aud.names[i] );
            }
        }

        if( jwt->aud.names ) {
            free( jwt->aud.names );
        }

        if( jwt->private_claims ) {
            cJSON_Delete( jwt->private_claims );
        }

        free( jwt );
    }

    return 0;
}
