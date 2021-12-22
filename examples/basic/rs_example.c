/* SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "cjwt.h"

/*
 * The output of the program should be as following (the private claims
 * formatting may vary.
 *
 * =====================
 * header
 * ---------------------
 *    alg: HS256
 * 
 * payload
 * ---------------------
 *    iat: 1516239022
 * 
 *    exp: NULL
 *    nbf: NULL
 * 
 *    iss: NULL
 *    sub: 1234567890
 *    jti: NULL
 *    aud: NULL
 * 
 * private claims
 * ---------------------
 * {
 *      "library":  "https://github.com/xmidt-org/cjwt"
 * }
 * =====================
 */

int main( void )
{
    cjwt_t *jwt = NULL;
    cjwt_code_t rv;

    /* the ps variant is very similar */
    const char *rs_text =
        /* header */
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
        /* payload */
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibGlicmFyeSI6Imh0dHBzOi8vZ2l"
        "0aHViLmNvbS94bWlkdC1vcmcvY2p3dCIsImlhdCI6MTUxNjIzOTAyMn0."
        /* signature */
        "e-pFjFcKyrWa6ODgkclHe26EEF6AkI-xaW6J-Z37IdfygRKmgqy5cIz"
        "hjIGBPQg2aJGrPmCc5zP-zeK1M98odo5OCxCDdfQsKTtJJlCIVC2Iv1"
        "CaZDc-dTNnmjZE6PBM9fzwhXd5ESNjSxhtHSt8_9gFmogaixcxD1D7A"
        "nSJ1kl-o9yVK2vBRTHfFEyx5npUGbuNGSdIcoUHQUvL3B55XhQW_IlT"
        "moYUjBKAg0Mqk1HAhzQ-ZXz2C6Ptopx9ga3ccK4QmXnUHwo_bRF7eIh"
        "WweMfy_JM7pNGZc1VGa0hCpp-Axwq3CZfwLL0DY7ohcSYfJN_4d4Qn7"
        "2S8EHKg_E5Ng";
    const char *rs_pub_key =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\n"
        "vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\n"
        "aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\n"
        "tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\n"
        "e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\n"
        "V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\n"
        "MwIDAQAB\n"
        "-----END PUBLIC KEY-----";

    rv = cjwt_decode( rs_text, strlen(rs_text), 0,
                      (uint8_t*) rs_pub_key, strlen(rs_pub_key), 0, 0, &jwt );

    if( CJWTE_OK != rv ) {
        printf( "There was an error processing the text: %d\n", rv );
        return -1;
    }

    cjwt_print( stdout, jwt );

    cjwt_destroy( jwt );

    return 0;
}
