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
 *      "name":     "John Doe",
 *      "hello":    "world",
 *      "bob":      ["dog", 123],
 *      "cat": {
 *          "mouse": {
 *              "cheese":   "lots"
 *          }
 *      }
 * }
 * =====================
 */

int main( void )
{
    cjwt_t *jwt = NULL;
    cjwt_code_t rv;

    const char *hs_text = 
        /* header */
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        /* payload */
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaGVsbG8i"
        "OiJ3b3JsZCIsImJvYiI6WyJkb2ciLDEyM10sImNhdCI6eyJtb3VzZSI6eyJj"
        "aGVlc2UiOiJsb3RzIn19LCJpYXQiOjE1MTYyMzkwMjJ9."
        /* signature */
        "mJYSucD6RRg6zdPcSKvb5-LKFDJzRvdKqTlqAvDBknU";

    const char *hs_key = "hs256-secret";

    rv = cjwt_decode( hs_text, strlen(hs_text), 0, (uint8_t*) hs_key, strlen(hs_key), 0, 0, &jwt );
    if( CJWTE_OK != rv ) {
        printf( "There was an error processing the text: %d\n", rv );
        return -1;
    }

    cjwt_print( stdout, jwt );

    cjwt_destroy( jwt );

    return 0;
}
