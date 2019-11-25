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
extern char *strdup(const char *s);
extern size_t b64url_get_decoded_buffer_size( const size_t encoded_size );
extern size_t b64url_decode( const uint8_t *input, const size_t input_size, uint8_t *output );


/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/
/* none */

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

    for( i = 0; i < count; i++ ) {
        if( !strcasecmp( alg_str, m[i].text ) ) {
            return m[i].alg;
        }
    }

    return -1;
}


inline static void cjwt_delete_child_json( cJSON* j, const char* s )
{
    if( j && cJSON_HasObjectItem( j, s ) ) {
        cJSON_DeleteItemFromObject( j, s );
    }
}

static void cjwt_delete_public_claims( cJSON* val )
{
    cjwt_delete_child_json( val, "iss" );
    cjwt_delete_child_json( val, "sub" );
    cjwt_delete_child_json( val, "aud" );
    cjwt_delete_child_json( val, "jti" );
    cjwt_delete_child_json( val, "exp" );
    cjwt_delete_child_json( val, "nbf" );
    cjwt_delete_child_json( val, "iat" );
}

static int cjwt_sign_sha_hmac( cjwt_t *jwt, unsigned char **out, const EVP_MD *alg,
                               const char *in, int *out_len )
{
    unsigned char res[EVP_MAX_MD_SIZE];
    unsigned int res_len;
    cjwt_info( "string for signing : %s \n", in );
    HMAC( alg, jwt->header.key, jwt->header.key_len,
          ( const unsigned char * )in, strlen( in ), res, &res_len );
    unsigned char *resptr = ( unsigned char * )malloc( res_len + 1 );

    if( !resptr ) {
        return ENOMEM;
    }

    memcpy( resptr, res, res_len );
    resptr[res_len] = '\0';
    *out = resptr;
    *out_len = res_len;
    return 0;
}

static int cjwt_sign( cjwt_t *cjwt, unsigned char **out, const char *in, int *out_len )
{
    switch( cjwt->header.alg ) {
        case alg_none:
            return 0;
        case alg_hs256:
            return cjwt_sign_sha_hmac( cjwt, out, EVP_sha256(), in, out_len );
        case alg_hs384:
            return cjwt_sign_sha_hmac( cjwt, out, EVP_sha384(), in, out_len );
        case alg_hs512:
            return cjwt_sign_sha_hmac( cjwt, out, EVP_sha512(), in, out_len );
        default :
            return  -1;
    }//switch

    return -1;
}

static RSA* cjwt_create_rsa( unsigned char *key, int key_len, int public )
{
    RSA *rsa = NULL;
    BIO *keybio ;

    if( key == NULL ) {
        cjwt_error( "invalid rsa key\n" );
        goto rsa_end;
    }

    keybio = BIO_new_mem_buf( key, key_len );

    if( keybio == NULL ) {
        cjwt_error( "BIO creation for key failed\n" );
        goto rsa_end;
    }

    if( public ) {
        rsa = PEM_read_bio_RSA_PUBKEY( keybio, &rsa, NULL, NULL );
    } else {
        rsa = PEM_read_bio_RSAPrivateKey( keybio, &rsa, NULL, NULL );
    }

    if( rsa == NULL ) {
        cjwt_rsa_error();
    }
    BIO_free (keybio);

rsa_end:
    return rsa;
}

static int cjwt_verify_rsa( cjwt_t *jwt, const char *p_enc, const char *p_sigb64 )
{
    int ret = EINVAL, sz_sigb64 = 0;
    RSA *rsa = NULL;
    size_t enc_len = 0, sig_desize = 0;
    uint8_t *decoded_sig = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];

    if( jwt->header.key_len == 0 ) {
        cjwt_error( "invalid rsa key\n" );
        return EINVAL;
    }

    rsa = cjwt_create_rsa( jwt->header.key, jwt->header.key_len, 1 );

    if( rsa == NULL ) {
        cjwt_error( "key to rsa conversion failed\n" );
        return EINVAL;
    }

    //decode p_sigb64
    sz_sigb64 = strlen( ( char * )p_sigb64 );
    sig_desize = b64url_get_decoded_buffer_size( sz_sigb64 );
    //Because b64url_decode() always writes in blocks of 3 bytes for every 4 
    //characters even when the last 2 bytes are not used, we need up to 2 
    //extra bytes of output buffer to avoid a buffer overrun 
    decoded_sig = malloc( sig_desize + 2 );

    if( !decoded_sig ) {
        cjwt_error( "memory allocation failed\n" );
        //free rsa
        RSA_free( rsa );
        cjwt_rsa_error();
        return ENOMEM;
    }

    memset( decoded_sig, 0, sig_desize + 2 );
    sig_desize = b64url_decode( ( uint8_t * )p_sigb64, sz_sigb64, decoded_sig );
    cjwt_info( "----------------- signature ----------------- \n" );
    cjwt_info( "Bytes = %d\n", ( int )sig_desize );
    cjwt_info( "--------------------------------------------- \n" );

    if( !sig_desize ) {
        cjwt_error( "b64url_decode failed\n" );
        goto end;
    }

    decoded_sig[sig_desize] = '\0';
    //verify rsa
    enc_len = strlen( p_enc );

    switch( jwt->header.alg ) {
        case alg_rs256:
            SHA256( ( const unsigned char* ) p_enc, enc_len, digest );
            ret = RSA_verify
                  ( NID_sha256, digest, SHA256_DIGEST_LENGTH, decoded_sig,
                    ( unsigned int ) sig_desize, rsa );
            break;
        case alg_rs384:
            SHA384( ( const unsigned char * ) p_enc, enc_len, digest );
            ret = RSA_verify
                  ( NID_sha384, digest, SHA384_DIGEST_LENGTH, decoded_sig,
                    ( unsigned int ) sig_desize, rsa );
            break;
        case alg_rs512:
            SHA512( ( const unsigned char* ) p_enc, enc_len, digest );
            ret = RSA_verify
                  ( NID_sha512, digest, SHA512_DIGEST_LENGTH, decoded_sig,
                    ( unsigned int ) sig_desize, rsa );
            break;
        default:
            cjwt_error( "invalid rsa algorithm\n" );
            ret = EINVAL;
            break;
    }

end:
    RSA_free( rsa );
    free( decoded_sig );

    if( ret ==  1 ) {
        return 0;
    }

    cjwt_rsa_error();
    return EINVAL;
}

static int cjwt_verify_signature( cjwt_t *p_jwt, char *p_in, const char *p_sign )
{
    int ret = 0;
    int sz_signed = 0;
    unsigned char* signed_out = NULL;

    if( !p_jwt || !p_in || !p_sign ) {
        ret = EINVAL;
        goto end;
    }

    if( IS_RSA_ALG( p_jwt->header.alg ) ) {
        ret = cjwt_verify_rsa( p_jwt, p_in, p_sign );
        goto end;
    }

    //sign
    ret = cjwt_sign( p_jwt, &signed_out, p_in, &sz_signed );

    if( ret ) {
        ret = EINVAL;
        goto end;
    }

    //decode signature from input token
    size_t sz_p_sign = strlen( p_sign );
    size_t sz_decoded = b64url_get_decoded_buffer_size( sz_p_sign );
    uint8_t *signed_dec = malloc( sz_decoded + 1 );

    if( !signed_dec ) {
        ret = ENOMEM;
        goto err_decode;
    }

    memset( signed_dec, 0, ( sz_decoded + 1 ) );
    //decode
    int out_size = b64url_decode( ( uint8_t * )p_sign, sz_p_sign, signed_dec );

    if( !out_size ) {
        ret = EINVAL;
        goto err_match;
    }

    signed_dec[out_size] = '\0';
    cjwt_info( "Signature length : enc %d, signature %d\n",
               ( int )sz_signed, ( int )out_size );
    cjwt_info( "signed token : %s\n", signed_out );
    cjwt_info( "expected token signature  %s\n", signed_dec );

    if( sz_signed != out_size ) {
        cjwt_info( "Signature length mismatch: enc %d, signature %d\n",
                   ( int )sz_signed, ( int )out_size );
        ret = EINVAL;
        goto err_match;
    }

    if( 0 != CRYPTO_memcmp(signed_out, signed_dec, out_size) ) {
        ret = EINVAL;
    }

err_match:
    free( signed_dec );
err_decode:
    free( signed_out );
end:
    return ret;
}


static int cjwt_update_payload( cjwt_t *p_cjwt, char *p_decpl )
{
    cJSON*  j_val = NULL;
   
    if( !p_cjwt || !p_decpl ) {
        return EINVAL;
    }

    //create cJSON object
    cJSON *j_payload = cJSON_Parse( ( char* )p_decpl );

    if( !j_payload ) {
        // The data is probably not json vs. memory allocation error.
        return EINVAL;
    }

    //extract data
    cjwt_info( "Json  = %s\n", cJSON_Print( j_payload ) );
    cjwt_info( "--------------------------------------------- \n\n" );
    //iss
    j_val = cJSON_GetObjectItem( j_payload, "iss" );

    if( j_val ) {
        if( p_cjwt->iss ) {
            free( p_cjwt->iss );
            p_cjwt->iss = NULL;
        }

        p_cjwt->iss = strdup(j_val->valuestring);

        if( !p_cjwt->iss ) {
            cJSON_Delete( j_payload );
            return ENOMEM;
        }
    }

    //sub
    j_val = cJSON_GetObjectItem( j_payload, "sub" );

    if( j_val ) {
        if( p_cjwt->sub ) {
            free( p_cjwt->sub );
            p_cjwt->sub = NULL;
        }

        p_cjwt->sub = strdup(j_val->valuestring);

        if( !p_cjwt->sub ) {
            cJSON_Delete( j_payload );
            return ENOMEM;
        }
    }

    //aud
    j_val = cJSON_GetObjectItem( j_payload, "aud" );

    if( j_val ) {
        if( j_val->type == cJSON_Object ) {
            //array of strings
            cJSON*  j_tmp = NULL;
            int     cnt, i = 0;
            char    **ptr_values = NULL;
            char    *str_val = NULL;
            cnt = cJSON_GetArraySize( j_val->child );
            ptr_values = ( char** ) malloc( ( cnt ) * sizeof( char* ) );

            if( !ptr_values ) {
                cJSON_Delete( j_payload );
                return ENOMEM;
            }

            for( i = 0; i < cnt; i++ ) {
                j_tmp = cJSON_GetArrayItem( j_val->child, i );
                cjwt_info( "aud[%d] Json  = %s,type=%d,val=%s\n", i, cJSON_Print( j_tmp ), j_tmp->type, j_tmp->valuestring );

                if( j_tmp->type == cJSON_String ) {
                    str_val =  strdup(j_tmp->valuestring);

                    if( !str_val ) {
                        cJSON_Delete( j_payload );
                        i--;

                        while( i ) {
                            free( ptr_values[--i] );
                        }
                        
                        free (ptr_values);
                        return ENOMEM;
                    }

                    ptr_values[i] = str_val;
                }
            }//for
			
            p_cjwt_aud_list aud_new = malloc( sizeof( cjwt_aud_list_t ) );

            if( !aud_new ) {
                cJSON_Delete( j_payload );

                while( cnt ) {
                    free( ptr_values[--cnt] );
                }

                free (ptr_values);
                return ENOMEM;
            }

            aud_new->count = cnt;
            aud_new->names = ptr_values;
            p_cjwt->aud = aud_new;
        }
    }

    //jti
    j_val = cJSON_GetObjectItem( j_payload, "jti" );

    if( j_val ) {
        if( p_cjwt->jti ) {
            free( p_cjwt->jti );
            p_cjwt->jti = NULL;
        }

        p_cjwt->jti = strdup(j_val->valuestring);

        if( !p_cjwt->jti ) {
            cJSON_Delete( j_payload );
            return ENOMEM;
        }
    }

    //exp
    j_val = cJSON_GetObjectItem( j_payload, "exp" );

    if( j_val ) {
        cjwt_info( "exp Json  = %s,type=%d,int=%d,double=%f\n", cJSON_Print( j_val ), j_val->type, j_val->valueint, j_val->valuedouble );

        if( j_val->type == cJSON_Number ) {
            p_cjwt->exp.tv_sec = j_val->valueint;
            p_cjwt->exp.tv_nsec = 0;
        }
    }

    //nbf
    j_val = cJSON_GetObjectItem( j_payload, "nbf" );

    if( j_val ) {
        cjwt_info( "nbf Json  = %s,type=%d,int=%d,double=%f\n", cJSON_Print( j_val ), j_val->type, j_val->valueint, j_val->valuedouble );

        if( j_val->type == cJSON_Number ) {
            p_cjwt->nbf.tv_sec = j_val->valueint;
            p_cjwt->nbf.tv_nsec = 0;
        }
    }

    //iat
    j_val = cJSON_GetObjectItem( j_payload, "iat" );

    if( j_val ) {
        cjwt_info( "iat Json  = %s,type=%d,int=%d,double=%f\n", cJSON_Print( j_val ), j_val->type, j_val->valueint, j_val->valuedouble );

        if( j_val->type == cJSON_Number ) {
            p_cjwt->iat.tv_sec = j_val->valueint;
            p_cjwt->iat.tv_nsec = 0;
        }
    }

    //private_claims
    cJSON* j_new = cJSON_Duplicate( j_payload, 1 );

    if( j_new ) {
        cjwt_delete_public_claims( j_new );
        cjwt_info( "private claims count = %d\n", cJSON_GetArraySize( j_new ) );

        if( cJSON_GetArraySize( j_new ) ) {
            //cjwt_info( "private claims  = %s\n", cJSON_Print( j_new ) );
            if( p_cjwt->private_claims ) {
                cJSON_Delete( p_cjwt->private_claims );
            }

            p_cjwt->private_claims = j_new;
        } else {
            cJSON_Delete ( j_new );
        }
    }

    //destroy cJSON object
    cJSON_Delete( j_payload );
    return 0;
}

static int cjwt_update_header( cjwt_t *p_cjwt, char *p_dechead )
    // The data is probably not json vs. memory allocation error.
{
    if( !p_cjwt || !p_dechead ) {
        return EINVAL;
    }

    //create cJSON object
    cJSON *j_header = cJSON_Parse( ( char* )p_dechead );

    if( !j_header ) {
        // The data is probably not json vs. memory allocation error.
        return EINVAL;
    }

    cjwt_info( "Json  = %s\n", cJSON_Print( j_header ) );
    cjwt_info( "--------------------------------------------- \n\n" );
    //extract data
    cJSON* j_typ = cJSON_GetObjectItem( j_header, "typ" );

    if( !j_typ || strcmp( j_typ->valuestring, "JWT" ) ) {
        cjwt_info( "may not be a JWT token\n" );
    }

    cJSON* j_alg = cJSON_GetObjectItem( j_header, "alg" );

    if( j_alg ) {
        int alg;

        alg = cjwt_alg_str_to_enum( j_alg->valuestring );
        if( -1 == alg ) {
            cJSON_Delete( j_header );
            return ENOTSUP;
        }
        p_cjwt->header.alg = alg;
    }

    //destroy cJSON object
    cJSON_Delete( j_header );
    return 0;
}

static int cjwt_parse_payload( cjwt_t *p_cjwt, char *p_payload )
{
    int ret, sz_payload;
    size_t pl_desize;
    size_t out_size = 0;
    uint8_t *decoded_pl;

    if( !p_cjwt || !p_payload ) {
        return EINVAL;
    }

    sz_payload = strlen( ( char * )p_payload );
    pl_desize = b64url_get_decoded_buffer_size( sz_payload );
    cjwt_info( "----------------- payload ------------------- \n" );
    cjwt_info( "Payload Size = %d , Decoded size = %d\n", sz_payload, ( int )pl_desize );
    decoded_pl = malloc( pl_desize + 1 );

    if( !decoded_pl ) {
        return ENOMEM;
    }

    memset( decoded_pl, 0, ( pl_desize + 1 ) );
    //decode payload
    out_size = b64url_decode( ( uint8_t * )p_payload, sz_payload, decoded_pl );
    cjwt_info( "Bytes = %d\n", ( int )out_size );

    if( !out_size ) {
        ret = EINVAL;
        goto end;
    }

    decoded_pl[out_size] = '\0';
    cjwt_info( "Raw data  = %*s\n", ( int )out_size, decoded_pl );
    ret = cjwt_update_payload( p_cjwt, ( char* )decoded_pl );
end:
    free( decoded_pl );
    return ret;
}

static int cjwt_parse_header( cjwt_t *p_cjwt, char *p_head )
{
    int sz_head, ret = 0;
    size_t head_desize;
    uint8_t *decoded_head;
    size_t out_size = 0;

    if( !p_cjwt || !p_head ) {
        return EINVAL;
    }

    sz_head = strlen( ( char * )p_head );
    head_desize = b64url_get_decoded_buffer_size( sz_head );
    cjwt_info( "----------------- header -------------------- \n" );
    cjwt_info( "Header Size = %d , Decoded size = %d\n", sz_head, ( int )head_desize );
    decoded_head = malloc( head_desize + 1 );

    if( !decoded_head ) {
        return ENOMEM;
    }

    memset( decoded_head, 0, head_desize + 1 );
    //decode header
    out_size = b64url_decode( ( uint8_t * )p_head, sz_head, decoded_head );
    cjwt_info( "Bytes = %d\n", ( int )out_size );

    if( !out_size ) {
        ret = EINVAL;
        goto end;
    }

    decoded_head[out_size] = '\0';
    cjwt_info( "Raw data  = %*s\n", ( int )out_size, decoded_head );
    ret = cjwt_update_header( p_cjwt, ( char* )decoded_head );
end:
    free( decoded_head );
    return ret;
}

static int cjwt_update_key( cjwt_t *p_cjwt, const uint8_t *key, size_t key_len )
{
    int ret = 0;

    if( ( NULL != key ) && ( key_len > 0 ) ) {
        p_cjwt->header.key = malloc( key_len );

        if( !p_cjwt->header.key ) {
            ret = ENOMEM;
            return ret;
        }

        memcpy( p_cjwt->header.key, key, key_len );
        p_cjwt->header.key_len = key_len;
    }

    return ret;
}

static cjwt_t* cjwt_create()
{
    cjwt_t *init = malloc( sizeof( cjwt_t ) );

    if( init ) {
			memset (init, 0, sizeof(cjwt_t));
    }

    return init;
}

/**
 * validates jwt token and extracts data
 */
int cjwt_decode( const char *encoded, unsigned int options, cjwt_t **jwt,
                 const uint8_t *key, size_t key_len )
{
    int ret = 0;
    char *payload, *signature;
    ( void )options; //suppressing unused parameter warning

    //validate inputs
    if( !encoded || !jwt ) {
        cjwt_error( "null parameter\n" );
        ret = EINVAL;
        goto error;
    }

    cjwt_info( "parameters cjwt_decode()\n encoded : %s\n options : %d\n", encoded, options );
    //create copy
    char *enc_token = malloc( strlen( encoded ) + 1 );

    if( !enc_token ) {
        cjwt_error( "memory alloc failed\n" );
        ret = ENOMEM;
        goto error;
    }

    strcpy( enc_token, encoded );

    //tokenize the jwt token
    for( payload = enc_token; payload[0] != '.'; payload++ ) {
        if( payload[0] == '\0' ) {
            cjwt_error( "Invalid jwt token,has only header\n" );
            ret = EINVAL;
            goto end;
        }
    }

    payload[0] = '\0';
    payload++;

    for( signature = payload; signature[0] != '.'; signature++ ) {
        if( signature[0] == '\0' ) {
            cjwt_error( "Invalid jwt token,missing signature\n" );
            ret = EINVAL;
            goto end;
        }
    }

    signature[0] = '\0';
    signature++;
    //create cjson
    cjwt_t *out = cjwt_create();

    if( !out ) {
        cjwt_error( "cjwt memory alloc failed\n" );
        ret = ENOMEM;
        goto end;
    }

    //populate key
    ret = cjwt_update_key( out, key, key_len );

    if( ret ) {
        cjwt_error( "Failed to update key\n" );
        goto invalid;
    }

    //parse header
    ret = cjwt_parse_header( out, enc_token );

    if( ret ) {
        cjwt_error( "Invalid header\n" );
        goto invalid;
    }

    //parse payload
    ret = cjwt_parse_payload( out, payload );

    if( ret ) {
        cjwt_error( "Invalid payload\n" );
        goto invalid;
    }

    if( out->header.alg != alg_none ) {
        enc_token[strlen( enc_token )] = '.';
        //verify
        ret = cjwt_verify_signature( out, enc_token, signature );

        if( ret ) {
            cjwt_error( "\nSignature authentication failed\n" );
            goto invalid;
        }

        cjwt_info( "\nSignature authentication passed\n" );
    }

invalid:

    if( ret ) {
        cjwt_destroy( &out );
        *jwt = NULL;
    } else {
        *jwt = out;
    }

end:
    free( enc_token );
error:
    return ret;
}

/**
 * cleanup jwt object
 */
int cjwt_destroy( cjwt_t **jwt )
{
    cjwt_t *del = *jwt;
    *jwt = NULL;

    if( !del ) {
        return 0;
    }

    if(del->header.key)
    {
        free(del->header.key);
    }
    del->header.key = NULL;

    if( del->iss ) {
        free( del->iss );
    }

    del->iss = NULL;

    if( del->sub ) {
        free( del->sub );
    }

    del->sub = NULL;

    if( del->aud ) {
        char** tmp = del->aud->names;
        int cnt_lst = del->aud->count;
        free( del->aud );
        del->aud = NULL;

        while( cnt_lst ) {
            free( tmp[--cnt_lst] );
        }
    }

    if( del->jti ) {
        free( del->jti );
    }

    del->jti = NULL;

    if( del->private_claims ) {
        cJSON_Delete( del->private_claims );
    }

    del->private_claims = NULL;
    free (del);
    return 0;
}
//end of file
