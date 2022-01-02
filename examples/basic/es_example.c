/* SPDX-FileCopyrightText: 2021-2022 Comcast Cable Communications Management, LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stddef.h>
#include <stdint.h>
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

int main(void)
{
    cjwt_t *jwt = NULL;
    cjwt_code_t rv;

    const char *es_text =
        /* header */
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
        /* payload */
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibGlicmFyeSI6Imh0dHBzOi8vZ2l"
        "0aHViLmNvbS94bWlkdC1vcmcvY2p3dCIsImlhdCI6MTUxNjIzOTAyMn0."
        /* signature */
        "dVNftrYfhBrS7tNzJj5UKM-GTzFfZpL7rTUsrYUFn9m0EFPtFT85DVcW"
        "I5mYrkms7TMhcU9i18CAna_Xd0qCBA";

    const char *es_pub_key =
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9\n"
        "q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==\n"
        "-----END PUBLIC KEY-----";

    rv = cjwt_decode(es_text, strlen(es_text), 0,
                     (uint8_t *) es_pub_key, strlen(es_pub_key), 0, 0, &jwt);

    if (CJWTE_OK != rv) {
        printf("There was an error processing the text: %d\n", rv);
        return -1;
    }

    cjwt_print(stdout, jwt);

    cjwt_destroy(jwt);

    return 0;
}
