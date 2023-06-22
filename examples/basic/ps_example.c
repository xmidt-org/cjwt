/* SPDX-FileCopyrightText: 2021-2023 Comcast Cable Communications Management, LLC */
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
 *    alg: PS384
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

    /* the rs variant is very similar */
    const char *ps_text =
        /* header */
        "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9."
        /* payload */
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibGlicmFyeSI6Imh0dHBzOi8vZ2l"
        "0aHViLmNvbS94bWlkdC1vcmcvY2p3dCIsImlhdCI6MTUxNjIzOTAyMn0."
        /* signature */
        "Jt2SaHKp56wizHwwzomeRo-9a4M6ODg02sB7cZUZslEg-1QtoDTGHXZv"
        "F73KmG8AJ9S2r4FbhZ9mmP_wL4OJs2fObA3RdMkyd2P1rpdXfXpK7mXU"
        "10fzQzT-l7RHQ3MqKkALs1iaczSp-rUOB-FiekkrAGSca0K02oHM9rpX"
        "xICL4Gc_nV-mk32e-R7jihV3BCX_8zpQoBt0cUwufW6R1GyD6DdmOErU"
        "0cTqa6t0oTmZIFNARCZ4AXj-GRajwN5meEwFjtmyGAXCL9bZl8Sv_7Fs"
        "NEnscW8UaL9CWIz_4CInAdFnWFj4EGNKfKt60lfdNPUAxZYPERXFkxBb"
        "cqQXBg";

    const char *ps_pub_key =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\n"
        "vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\n"
        "aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\n"
        "tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\n"
        "e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\n"
        "V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\n"
        "MwIDAQAB\n"
        "-----END PUBLIC KEY-----";

    rv = cjwt_decode(ps_text, strlen(ps_text), 0,
                     (uint8_t *) ps_pub_key, strlen(ps_pub_key), 0, 0, &jwt);

    if (CJWTE_OK != rv) {
        printf("There was an error processing the text: %d\n", rv);
        return -1;
    }

    cjwt_print(stdout, jwt);

    cjwt_destroy(jwt);

    return 0;
}
