<!--
SPDX-FileCopyrightText: 2017-2021 Comcast Cable Communications Management, LLC
SPDX-License-Identifier: Apache-2.0
-->
# cjwt

A C JWT Implementation

[![Build Status](https://github.com/xmidt-org/cjwt/workflows/CI/badge.svg)](https://github.com/xmidt-org/cjwt/actions)
[![codecov.io](http://codecov.io/github/xmidt-org/cjwt/coverage.svg?branch=main)](http://codecov.io/github/xmidt-org/cjwt?branch=main)
[![Coverity](https://img.shields.io/coverity/scan/23236.svg)](https://scan.coverity.com/projects/xmidt-org-cjwt)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=xmidt-org_cjwt&metric=alert_status)](https://sonarcloud.io/dashboard?id=xmidt-org_cjwt)
[![Language Grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/xmidt-org/cjwt.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/xmidt-org/cjwt/context:cpp)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/xmidt-org/cjwt/blob/main/LICENSES/Apache-2.0.txt)
[![GitHub release](https://img.shields.io/github/release/xmidt-org/cjwt.svg)](CHANGELOG.md)
[![JWT.io](http://jwt.io/img/badge.svg)](https://jwt.io/)

`cjwt` is a small JWT handler designed to allow consumers of JWTs of the JWS variant
the ability to securely and easily get claims and data from a JWT.  This particular
JWT implementation uses [cJSON](https://github.com/DaveGamble/cJSON) and is designed
to support multiple different crypto libraries in the future.

## API

The API is meant to be fairly small & leverage what cJSON already provides nicely.

[Here are the details](https://github.com/xmidt-org/cjwt/blob/main/src/cjwt.h)

There are 3 function:

 - `cjwt_decode()` that decodes successfully or fails with a more detailed reason
 - `cjwt_destroy()` that destroys the `cjwt_t` object cleanly
 - `cjwt_print()` that prints the `cjwt_t` object to a stream (generally for debugging)

Otherwise you get a simple C struct to work with in your code.

## Dependencies

- [cJSON](https://github.com/DaveGamble/cJSON)
- [openssl](https://github.com/openssl/openssl)
- [trower-base64](https://github.com/xmidt-org/trower-base64)


## Opinionated Default Secure

To help adopters not make costly security mistakes, cjwt tries to default to
secure wherever possible.  If you **must** use an insecure feature there are
option flags that let you do so, but use them sparingly and with care.


# Examples:

- [HS](https://github.com/xmidt-org/cjwt/blob/main/examples/basic/hs_example.c)
- [RS / PS](https://github.com/xmidt-org/cjwt/blob/main/examples/basic/rs_example.c)
- [ES](https://github.com/xmidt-org/cjwt/blob/main/examples/basic/es_example.c)

## Inline

Using the decoder:

```c
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <cjwt/cjwt.h>

int main( int argc, char *argv[] )
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
```

Gives you this output:

```txt
=====================
header
---------------------
   alg: HS256

payload
---------------------
   iat: 1516239022

   exp: NULL
   nbf: NULL

   iss: NULL
   sub: 1234567890
   jti: NULL
   aud: NULL

private claims
---------------------
{
     "name":     "John Doe",
     "hello":    "world",
     "bob":      ["dog", 123],
     "cat": {
         "mouse": {
             "cheese":   "lots"
         }
     }
}
```

# Building and Testing Instructions

```
meson setup --warnlevel 3 --werror build
cd build
ninja all test coverage
firefox ./meson-logs/coveragereport/index.html
```
