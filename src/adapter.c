/* SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC */
/* SPDX-FileCopyrightText: 2021 Weston Schmidt */
/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "cjwt.h"
#include "internal.h"

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
/* none */

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
extern int alg_to_enum( const char *alg_str, cjwt_alg_t *alg );

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
int cjwt_decode( const char *encoded, unsigned int options, cjwt_t **jwt_out,
                 const uint8_t *key, size_t key_len )
{
    size_t enc_len;
    __cjwt_t *obj = NULL;
    cjwt_t *jwt = NULL;
    cjwt_code_t rv;

    if( !encoded || !jwt_out ) {
        return EINVAL;
    }

    enc_len = strlen( encoded );
    if( 0 == enc_len ) {
        return EINVAL;
    }

    options |= OPT_ALLOW_ANY_TIME | OPT_ALLOW_ANY_TYP;

    rv = __cjwt_decode( encoded, enc_len, options, key, key_len, 0, 0, &obj );
    switch( rv ) {
        case CJWTE_OK:
            break;

        case CJWTE_HEADER_UNSUPPORTED_ALG:
        case CJWTE_SIGNATURE_UNSUPPORTED_ALG:
            return ENOTSUP;
        default:
            return EINVAL;
    }

    jwt = calloc( 1, sizeof(cjwt_t) );
    if( !jwt ) {
        __cjwt_destroy( obj );
        return ENOMEM;
    }

    jwt->header.alg = obj->header.alg;
    jwt->header.key = (uint8_t*) key;
    jwt->header.key_len = (int) key_len;
    jwt->iss = obj->iss;
    jwt->sub = obj->sub;
    jwt->jti = obj->jti;

    if( 0 < obj->aud.count ) {
        jwt->aud = calloc( 1, sizeof(cjwt_aud_list_t) );
        if( !jwt->aud ) {
            free( jwt );
            __cjwt_destroy( obj );
            return ENOMEM;
        }

        jwt->aud->count = obj->aud.count;
        jwt->aud->names = obj->aud.names;
    }

    if( obj->iat ) {
        jwt->iat.tv_sec = (int) *obj->iat;
    }
    if( obj->nbf ) {
        jwt->nbf.tv_sec = (int) *obj->nbf;
    }
    if( obj->exp ) {
        jwt->exp.tv_sec = (int) *obj->exp;
    }

    jwt->private_claims = obj->private_claims;

    /* Nothing can fail at this point, so transfer ownership by NULLing out
     * the old references. */
    obj->iss = NULL;
    obj->sub = NULL;
    obj->jti = NULL;
    obj->private_claims = NULL;
    obj->aud.names = NULL;
    obj->aud.count = 0;

    __cjwt_destroy( obj );

    *jwt_out = jwt;

    return 0;
}


int cjwt_destroy( cjwt_t **obj )
{
    if( obj ) {
        cjwt_t *jwt = *obj;

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
            if( jwt->aud ) {
                if( jwt->aud->names ) {
                    for( int i = 0; i < jwt->aud->count; i++ ) {
                        if( jwt->aud->names[i] ) {
                            free( jwt->aud->names[i] );
                        }
                    }
                    free( jwt->aud->names );
                }
                free( jwt->aud );
            }

            if( jwt->private_claims ) {
                cJSON_Delete( jwt->private_claims );
            }

            free( jwt );
        }
    }

    return 0;
}


int cjwt_alg_str_to_enum( const char *alg_str )
{
    cjwt_alg_t alg;

    if( 0 == alg_to_enum(alg_str, &alg) ) {
        return (int) alg;
    }

    return -1;
}

/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/
/* none */

