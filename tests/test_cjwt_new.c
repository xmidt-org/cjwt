// SPDX-FileCopyrightText: 2017-2022 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <CUnit/Basic.h>
#include <cjson/cJSON.h>
#include <trower-base64/base64.h>

#include "cjwt.h"

typedef struct {
    const char *desc;
    const char *filename;
    const char *key_fn;
    const char *key;
    cjwt_code_t expected;
} test_case_t;

typedef struct {
    const char *header;
    const char *payload;
    cjwt_code_t expected;
    int options;
    int64_t time;
    int64_t skew;
    cjwt_t jwt;
} json_test_case_t;

// clang-format off
test_case_t test_list[] = {
    /* Valid, positive tests */
    /*------------------------------------------------------------------------*/
    { "HS256", "hs256.jwt", NULL,            "hs256-secret", CJWTE_OK },
    { "HS384", "hs384.jwt", NULL,            "hs384-secret", CJWTE_OK },
    { "HS512", "hs512.jwt", NULL,            "hs512-secret", CJWTE_OK },
    { "RS256", "rs256.jwt", "rs.pub",        NULL,           CJWTE_OK },
    { "RS384", "rs384.jwt", "rs.pub",        NULL,           CJWTE_OK },
    { "RS512", "rs512.jwt", "rs.pub",        NULL,           CJWTE_OK },
    { "ES256", "es256.jwt", "es256.jwt.pub", NULL,           CJWTE_OK },
    { "ES384", "es384.jwt", "es384.jwt.pub", NULL,           CJWTE_OK },
    { "ES512", "es512.jwt", "es512.jwt.pub", NULL,           CJWTE_OK },
    { "PS256", "ps256.jwt", "ps.pub",        NULL,           CJWTE_OK },
    { "PS384", "ps384.jwt", "ps.pub",        NULL,           CJWTE_OK },
    { "PS512", "ps512.jwt", "ps.pub",        NULL,           CJWTE_OK },

    /* Negative tests around signature validation */
    /*------------------------------------------------------------------------*/
    { "HS256 bad secret",  "hs256.jwt",   NULL,            "hs000-secret", CJWTE_SIGNATURE_VALIDATION_FAILED },
    { "HS384 bad secret",  "hs384.jwt",   NULL,            "hs000-secret", CJWTE_SIGNATURE_VALIDATION_FAILED },
    { "HS512 bad secret",  "hs512.jwt",   NULL,            "hs000-secret", CJWTE_SIGNATURE_VALIDATION_FAILED },
    { "HS256 NULL secret", "hs256.jwt",   NULL,            NULL,           CJWTE_SIGNATURE_VALIDATION_FAILED },
    { "HS384 NULL secret", "hs384.jwt",   NULL,            NULL,           CJWTE_SIGNATURE_VALIDATION_FAILED },
    { "HS512 NULL secret", "hs512.jwt",   NULL,            NULL,           CJWTE_SIGNATURE_VALIDATION_FAILED },

    { "RS256 bad secret",  "rs256.jwt",   "rs-alt.pub",    NULL,           CJWTE_SIGNATURE_VALIDATION_FAILED },
    { "RS384 bad secret",  "rs384.jwt",   "rs-alt.pub",    NULL,           CJWTE_SIGNATURE_VALIDATION_FAILED },
    { "RS512 bad secret",  "rs512.jwt",   "rs-alt.pub",    NULL,           CJWTE_SIGNATURE_VALIDATION_FAILED },
    { "RS256 partial",     "rs256.jwt",   "rs.partial",    NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "RS384 partial",     "rs384.jwt",   "rs.partial",    NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "RS512 partial",     "rs512.jwt",   "rs.partial",    NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "RS256 invalid",     "rs256.jwt",   "es256.jwt.pub", NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "RS384 invalid",     "rs384.jwt",   "es256.jwt.pub", NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "RS512 invalid",     "rs512.jwt",   "es256.jwt.pub", NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "RS256 NULL secret", "rs256.jwt",   NULL,            NULL,           CJWTE_SIGNATURE_MISSING_KEY       },
    { "RS384 NULL secret", "rs384.jwt",   NULL,            NULL,           CJWTE_SIGNATURE_MISSING_KEY       },
    { "RS512 NULL secret", "rs512.jwt",   NULL,            NULL,           CJWTE_SIGNATURE_MISSING_KEY       },

    { "PS256 bad secret",  "ps256.jwt",   "rs-alt.pub",    NULL,           CJWTE_SIGNATURE_VALIDATION_FAILED },
    { "PS384 bad secret",  "ps384.jwt",   "rs-alt.pub",    NULL,           CJWTE_SIGNATURE_VALIDATION_FAILED },
    { "PS512 bad secret",  "ps512.jwt",   "rs-alt.pub",    NULL,           CJWTE_SIGNATURE_VALIDATION_FAILED },
    { "PS256 partial",     "ps256.jwt",   "rs.partial",    NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "PS384 partial",     "ps384.jwt",   "rs.partial",    NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "PS512 partial",     "ps512.jwt",   "rs.partial",    NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "PS256 invalid",     "ps256.jwt",   "es256.jwt.pub", NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "PS384 invalid",     "ps384.jwt",   "es256.jwt.pub", NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "PS512 invalid",     "ps512.jwt",   "es256.jwt.pub", NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "PS256 NULL secret", "ps256.jwt",   NULL,            NULL,           CJWTE_SIGNATURE_MISSING_KEY       },
    { "PS384 NULL secret", "ps384.jwt",   NULL,            NULL,           CJWTE_SIGNATURE_MISSING_KEY       },
    { "PS512 NULL secret", "ps512.jwt",   NULL,            NULL,           CJWTE_SIGNATURE_MISSING_KEY       },

    { "ES256 bad secret",  "es256.jwt",   "rs-alt.pub",    NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "ES384 bad secret",  "es384.jwt",   "rs-alt.pub",    NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "ES512 bad secret",  "es512.jwt",   "rs-alt.pub",    NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "ES256 partial",     "es256.jwt",   "rs.partial",    NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "ES384 partial",     "es384.jwt",   "rs.partial",    NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "ES512 partial",     "es512.jwt",   "rs.partial",    NULL,           CJWTE_SIGNATURE_INVALID_KEY       },
    { "ES256 invalid",     "es256.jwt",   "es512.jwt.pub", NULL,           CJWTE_SIGNATURE_VALIDATION_FAILED },
    { "ES384 invalid",     "es384.jwt",   "es512.jwt.pub", NULL,           CJWTE_SIGNATURE_VALIDATION_FAILED },
    { "ES512 invalid",     "es512.jwt",   "es256.jwt.pub", NULL,           CJWTE_SIGNATURE_VALIDATION_FAILED },
    { "ES256 NULL secret", "es256.jwt",   NULL,            NULL,           CJWTE_SIGNATURE_MISSING_KEY       },
    { "ES384 NULL secret", "es384.jwt",   NULL,            NULL,           CJWTE_SIGNATURE_MISSING_KEY       },
    { "ES512 NULL secret", "es512.jwt",   NULL,            NULL,           CJWTE_SIGNATURE_MISSING_KEY       },

    /* These are some nefarious focused tests */
    { "Try 5 section",     "try_5.inv",   NULL,            "hs256-secret", CJWTE_INVALID_SECTIONS            },
    { "Try 4 section",     "try_4.inv",   NULL,            "hs256-secret", CJWTE_INVALID_SECTIONS            },
    { "Try 2 section",     "try_2.inv",   NULL,            "hs256-secret", CJWTE_INVALID_SECTIONS            },
    { "Try 1 section",     "try_1.inv",   NULL,            "hs256-secret", CJWTE_HEADER_MISSING              },

    { "Invld b64 header",  "hdr_b64.inv", NULL,            "hs256-secret", CJWTE_HEADER_INVALID_BASE64       },
    { "Invld b64 sig",     "sig_b64.inv", NULL,            "hs256-secret", CJWTE_SIGNATURE_INVALID_BASE64    },
};

json_test_case_t json_test_list[] = {
    /* Valid, positive tests */
    { .header   = "{ \"alg\": \"none\", \"typ\": \"JWT\" }",
      .payload  = "{ \"sub\": \"1234567890\", \"iat\": 1516239022, \"iss\": \"example.com\", \"jti\": \"1029301923asdf\" }",
      .expected = CJWTE_OK,
      .options = OPT_ALLOW_ALG_NONE,
      .jwt = {  .header.alg = alg_none,
                .iss = "example.com",
                .sub = "1234567890",
                .jti = "1029301923asdf",

                .aud.count = 0,
                .aud.names = NULL,

                .exp = NULL,
                .nbf = NULL,
                .iat = (int64_t[1]){ 1516239022 },

                .private_claims = NULL,
             },
    },
    { .header   = "{ \"alg\": \"none\", \"typ\": \"jwt\" }",
      .payload  = "{ \"sub\": \"1234567890\", \"iat\": 1516239022, \"aud\": \"example.com\" }",
      .expected = CJWTE_OK,
      .options = OPT_ALLOW_ALG_NONE,
      .jwt = {  .header.alg = alg_none,
                .iss = NULL,
                .sub = "1234567890",
                .jti = NULL,

                .aud.count = 1,
                .aud.names = (char*[1]){ "example.com" },

                .exp = NULL,
                .nbf = NULL,
                .iat = (int64_t[1]){ 1516239022 },

                .private_claims = NULL,
             },
    },
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"sub\": \"1234567890\", \"iat\": 1516239022, \"aud\": [ \"example.com\" ] }",
      .expected = CJWTE_OK,
      .options = OPT_ALLOW_ALG_NONE,
      .jwt = {  .header.alg = alg_none,
                .iss = NULL,
                .sub = "1234567890",
                .jti = NULL,

                .aud.count = 1,
                .aud.names = (char*[1]){ "example.com" },

                .exp = NULL,
                .nbf = NULL,
                .iat = (int64_t[1]){ 1516239022 },

                .private_claims = NULL,
             },
    },
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"sub\": \"1234567890\", \"iat\": 1516239022, \"aud\": [ \"foo.com\", \"example.com\" ] }",
      .expected = CJWTE_OK,
      .options = OPT_ALLOW_ALG_NONE,
      .jwt = {  .header.alg = alg_none,
                .iss = NULL,
                .sub = "1234567890",
                .jti = NULL,

                .aud.count = 2,
                .aud.names = (char*[2]){ "foo.com", "example.com" },

                .exp = NULL,
                .nbf = NULL,
                .iat = (int64_t[1]){ 1516239022 },

                .private_claims = NULL,
             },
    },

    /* Time based checks */

    /* Equal to the expriration time */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"sub\": \"1234567890\", \"iat\": 1511223344, \"exp\": 1522334455, \"nbf\": 1522334450 }",
      .expected = CJWTE_OK,
      .options = OPT_ALLOW_ALG_NONE,
      .skew = 0,
      .time = 1522334455,
      .jwt = {  .header.alg = alg_none,
                .iss = NULL,
                .sub = "1234567890",
                .jti = NULL,

                .aud.count = 0,
                .aud.names = NULL,

                .exp = (int64_t[1]){ 1522334455 },
                .nbf = (int64_t[1]){ 1522334450 },
                .iat = (int64_t[1]){ 1511223344 },

                .private_claims = NULL,
             },
    },
    /* Equal to the not before time */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"sub\": \"1234567890\", \"iat\": 1511223344, \"exp\": 1522334455, \"nbf\": 1522334450 }",
      .expected = CJWTE_OK,
      .options = OPT_ALLOW_ALG_NONE,
      .skew = 0,
      .time = 1522334450,
      .jwt = {  .header.alg = alg_none,
                .iss = NULL,
                .sub = "1234567890",
                .jti = NULL,

                .aud.count = 0,
                .aud.names = NULL,

                .exp = (int64_t[1]){ 1522334455 },
                .nbf = (int64_t[1]){ 1522334450 },
                .iat = (int64_t[1]){ 1511223344 },

                .private_claims = NULL,
             },
    },
    /* Beyond expiration time, but within skew */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"sub\": \"1234567890\", \"iat\": 1511223344, \"exp\": 1522334455, \"nbf\": 1522334450 }",
      .expected = CJWTE_OK,
      .options = OPT_ALLOW_ALG_NONE,
      .skew = 1,
      .time = 1522334456,
      .jwt = {  .header.alg = alg_none,
                .iss = NULL,
                .sub = "1234567890",
                .jti = NULL,

                .aud.count = 0,
                .aud.names = NULL,

                .exp = (int64_t[1]){ 1522334455 },
                .nbf = (int64_t[1]){ 1522334450 },
                .iat = (int64_t[1]){ 1511223344 },

                .private_claims = NULL,
             },
    },
    /* Before not before, but within skew */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"sub\": \"1234567890\", \"iat\": 1511223344, \"exp\": 1522334455, \"nbf\": 1522334450 }",
      .expected = CJWTE_OK,
      .options = OPT_ALLOW_ALG_NONE,
      .skew = 1,
      .time = 1522334449,
      .jwt = {  .header.alg = alg_none,
                .iss = NULL,
                .sub = "1234567890",
                .jti = NULL,

                .aud.count = 0,
                .aud.names = NULL,

                .exp = (int64_t[1]){ 1522334455 },
                .nbf = (int64_t[1]){ 1522334450 },
                .iat = (int64_t[1]){ 1511223344 },

                .private_claims = NULL,
             },
    },
    /* Time is ignored with special flag - too soon */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"sub\": \"1234567890\", \"iat\": 1511223344, \"exp\": 1522334455, \"nbf\": 1522334450 }",
      .expected = CJWTE_OK,
      .options = OPT_ALLOW_ALG_NONE | OPT_ALLOW_ANY_TIME,
      .skew = 0,
      .time = 1522334449,
      .jwt = {  .header.alg = alg_none,
                .iss = NULL,
                .sub = "1234567890",
                .jti = NULL,

                .aud.count = 0,
                .aud.names = NULL,

                .exp = (int64_t[1]){ 1522334455 },
                .nbf = (int64_t[1]){ 1522334450 },
                .iat = (int64_t[1]){ 1511223344 },

                .private_claims = NULL,
             },
    },
    /* Time is ignored with special flag - too late */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"sub\": \"1234567890\", \"iat\": 1511223344, \"exp\": 1522334455, \"nbf\": 1522334450 }",
      .expected = CJWTE_OK,
      .options = OPT_ALLOW_ALG_NONE | OPT_ALLOW_ANY_TIME,
      .skew = 0,
      .time = 1522334466,
      .jwt = {  .header.alg = alg_none,
                .iss = NULL,
                .sub = "1234567890",
                .jti = NULL,

                .aud.count = 0,
                .aud.names = NULL,

                .exp = (int64_t[1]){ 1522334455 },
                .nbf = (int64_t[1]){ 1522334450 },
                .iat = (int64_t[1]){ 1511223344 },

                .private_claims = NULL,
             },
    },
    /* type header is ignored with special flag */
    { .header   = "{ \"alg\": \"none\", \"typ\": \"invalid\" }",
      .payload  = "{  }",
      .expected = CJWTE_OK,
      .options = OPT_ALLOW_ALG_NONE | OPT_ALLOW_ANY_TYP,
      .jwt = {  .header.alg = alg_none,
                .iss = NULL,
                .sub = NULL,
                .jti = NULL,

                .aud.count = 0,
                .aud.names = NULL,

                .exp = NULL,
                .nbf = NULL,
                .iat = NULL,

                .private_claims = NULL,
             },
    },
    /* smallest jwt */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{  }",
      .expected = CJWTE_OK,
      .options = OPT_ALLOW_ALG_NONE,
      .jwt = {  .header.alg = alg_none,
                .iss = NULL,
                .sub = NULL,
                .jti = NULL,

                .aud.count = 0,
                .aud.names = NULL,

                .exp = NULL,
                .nbf = NULL,
                .iat = NULL,

                .private_claims = NULL,
             },
    },

    /*------------------------------------------------------------------------*/
    /*                        Error / Boundary Tests                          */
    /*------------------------------------------------------------------------*/
    /* header json is invalid */
    { .header   = "{ \"alg\": \"no",
      .payload  = "{  }",
      .expected = CJWTE_HEADER_INVALID_JSON,
      .options = OPT_ALLOW_ALG_NONE,
    },
    /* payload json is invalid */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ ",
      .expected = CJWTE_PAYLOAD_INVALID_JSON,
      .options = OPT_ALLOW_ALG_NONE,
    },

    /* alg none not allowed. */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{  }",
      .expected = CJWTE_HEADER_UNSUPPORTED_ALG,
      .options = 0,
    },
    /* alg none not allowed. */
    { .header   = "{ \"alg\": 123 }",
      .payload  = "{  }",
      .expected = CJWTE_HEADER_UNSUPPORTED_ALG,
      .options = 0,
    },
    /* alg none not allowed. */
    { .header   = "{ \"alg\": \"\" }",
      .payload  = "{  }",
      .expected = CJWTE_HEADER_UNSUPPORTED_ALG,
      .options = 0,
    },
    /* Missing the alg */
    { .header   = "{ }",
      .payload  = "{ }",
      .expected = CJWTE_HEADER_MISSING_ALG,
      .options = 0,
    },

    /* typ int not allowed. */
    { .header   = "{ \"alg\": \"none\", \"typ\": 123 }",
      .payload  = "{  }",
      .expected = CJWTE_HEADER_UNSUPPORTED_TYP,
      .options = OPT_ALLOW_ALG_NONE,
    },
    /* typ invalid not allowed. */
    { .header   = "{ \"alg\": \"none\", \"typ\": \"jwt \" }",
      .payload  = "{  }",
      .expected = CJWTE_HEADER_UNSUPPORTED_TYP,
      .options = OPT_ALLOW_ALG_NONE,
    },
    /* typ invalid not allowed. */
    { .header   = "{ \"alg\": \"none\", \"typ\": \"jwP\" }",
      .payload  = "{  }",
      .expected = CJWTE_HEADER_UNSUPPORTED_TYP,
      .options = OPT_ALLOW_ALG_NONE,
    },
    /* typ invalid not allowed. */
    { .header   = "{ \"alg\": \"none\", \"typ\": \"jPt\" }",
      .payload  = "{  }",
      .expected = CJWTE_HEADER_UNSUPPORTED_TYP,
      .options = OPT_ALLOW_ALG_NONE,
    },
    /* typ invalid not allowed. */
    { .header   = "{ \"alg\": \"none\", \"typ\": \"Pwt\" }",
      .payload  = "{  }",
      .expected = CJWTE_HEADER_UNSUPPORTED_TYP,
      .options = OPT_ALLOW_ALG_NONE,
    },
    /* Unexpected header present */
    { .header   = "{ \"alg\": \"none\", \"dog\": \"woof!\" }",
      .payload  = "{  }",
      .expected = CJWTE_HEADER_UNSUPPORTED_UNKNOWN,
      .options = OPT_ALLOW_ALG_NONE,
    },

    /* Invalid iss type */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"iss\": 123 }",
      .expected = CJWTE_PAYLOAD_EXPECTED_STRING,
      .options = OPT_ALLOW_ALG_NONE,
    },
    /* Invalid sub type */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"sub\": 123 }",
      .expected = CJWTE_PAYLOAD_EXPECTED_STRING,
      .options = OPT_ALLOW_ALG_NONE,
    },
    /* Invalid jti type */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"jti\": 123 }",
      .expected = CJWTE_PAYLOAD_EXPECTED_STRING,
      .options = OPT_ALLOW_ALG_NONE,
    },

    /* Invalid exp type */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"exp\": \"12345\" }",
      .expected = CJWTE_PAYLOAD_EXPECTED_NUMBER,
      .options = OPT_ALLOW_ALG_NONE,
    },
    /* Invalid nbf type */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"nbf\": \"12345\" }",
      .expected = CJWTE_PAYLOAD_EXPECTED_NUMBER,
      .options = OPT_ALLOW_ALG_NONE,
    },
    /* Invalid iat type */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"iat\": \"12345\" }",
      .expected = CJWTE_PAYLOAD_EXPECTED_NUMBER,
      .options = OPT_ALLOW_ALG_NONE,
    },
    /* Invalid aud type */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"aud\": 12345 }",
      .expected = CJWTE_PAYLOAD_EXPECTED_STRING,
      .options = OPT_ALLOW_ALG_NONE,
    },
    /* Invalid aud type */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"aud\": [ \"foo\", 12345 ] }",
      .expected = CJWTE_PAYLOAD_EXPECTED_STRING,
      .options = OPT_ALLOW_ALG_NONE,
    },

    /* Time is ignored with special flag - too soon */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"sub\": \"1234567890\", \"iat\": 1511223344, \"exp\": 1522334455, \"nbf\": 1522334450 }",
      .expected = CJWTE_TIME_BEFORE_NBF,
      .options = OPT_ALLOW_ALG_NONE,
      .skew = 0,
      .time = 1522334449,
    },
    /* Time is ignored with special flag - too soon even with skew */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"sub\": \"1234567890\", \"iat\": 1511223344, \"exp\": 1522334455, \"nbf\": 1522334450 }",
      .expected = CJWTE_TIME_BEFORE_NBF,
      .options = OPT_ALLOW_ALG_NONE,
      .skew = 1,
      .time = 1522334440,
    },
    /* Time is ignored with special flag - too late */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"sub\": \"1234567890\", \"iat\": 1511223344, \"exp\": 1522334455, \"nbf\": 1522334450 }",
      .expected = CJWTE_TIME_AFTER_EXP,
      .options = OPT_ALLOW_ALG_NONE,
      .skew = 0,
      .time = 1522334466,
    },
    /* Time is ignored with special flag - too late even with skew */
    { .header   = "{ \"alg\": \"none\" }",
      .payload  = "{ \"sub\": \"1234567890\", \"iat\": 1511223344, \"exp\": 1522334455, \"nbf\": 1522334450 }",
      .expected = CJWTE_TIME_AFTER_EXP,
      .options = OPT_ALLOW_ALG_NONE,
      .skew = 0,
      .time = 1522334466,
    },
};
// clang-format on

int open_input_file(const char *fname)
{
    char cwd[1024];

    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        strcat(cwd, "/../tests/new_inputs/");
    } else {
        perror("getcwd() error");
        return -1;
    }

    if ((fname == NULL) || ((strlen(cwd) + strlen(fname)) > sizeof(cwd)))
    {
        perror("filename too long error");
        return -1;
    }
    strcat(cwd, fname);
    int fd = open(cwd, O_RDONLY);

    if (fd < 0) {
        printf("File %s open error\n", fname);
    }

    return fd;
}

ssize_t read_file(const char *fname, char *buf, size_t buflen)
{
    ssize_t nbytes = 0;
    int fd         = open_input_file(fname);

    if (fd < 0) {
        return fd;
    }

    nbytes = read(fd, buf, buflen);

    if (nbytes < 0) {
        printf("Read file %s error\n", fname);
        close(fd);
        return nbytes;
    }

    close(fd);
    return nbytes;
}

void test_case(const test_case_t *t)
{
    int key_len = 0;
    ssize_t jwt_bytes;
    cjwt_code_t result = CJWTE_OK;
    cjwt_t *jwt        = NULL;
    char jwt_buf[65535];
    char pem_buf[8192];
    const uint8_t *key = (const uint8_t *) t->key;

    if (NULL != t->key) {
        key_len = strlen(t->key);
    } else if (t->key_fn) {
        key_len = read_file(t->key_fn, pem_buf, sizeof(pem_buf));

        CU_ASSERT_FATAL(key_len >= 0);
        key = (uint8_t *) pem_buf;
    }

    memset(jwt_buf, 0, sizeof(jwt_buf));
    jwt_bytes = read_file(t->filename, jwt_buf, sizeof(jwt_buf));

    if (jwt_bytes > 0) {
        while (isspace(jwt_buf[jwt_bytes - 1])) {
            jwt_bytes--;
        }
        result = cjwt_decode(jwt_buf, jwt_bytes, 0, key, key_len, 0, 0, &jwt);
    } else {
        result = jwt_bytes;
    }

    if (t->expected != result) {
        printf("\n\x1B[01;31m--- FAILED: %s (exp: %d != got: %d)\x1B[00m\n", t->desc, t->expected, result);
    }

    cjwt_destroy(jwt);
    CU_ASSERT(t->expected == result);
}

void str_eq(const char *exp, const char *act)
{
    if (NULL == exp) {
        CU_ASSERT(exp == act);
        return;
    }

    CU_ASSERT_FATAL(NULL != exp);
    CU_ASSERT_FATAL(NULL != exp);
    CU_ASSERT_STRING_EQUAL(exp, act);
}

void int64_eq(int64_t *exp, int64_t *act)
{
    if (NULL == exp) {
        CU_ASSERT(exp == act);
        return;
    }

    CU_ASSERT_FATAL(NULL != exp);
    CU_ASSERT_FATAL(NULL != exp);
    CU_ASSERT_FATAL(*exp == *act);
}

void claims_eq(cJSON *exp, cJSON *act)
{
    if (NULL == exp) {
        CU_ASSERT(exp == act);
        return;
    }
}

void json_test_case(const json_test_case_t *t)
{
    char *b64_h = b64url_encode_with_alloc((uint8_t *) t->header, strlen(t->header), NULL);
    char *b64_p = b64url_encode_with_alloc((uint8_t *) t->payload, strlen(t->payload), NULL);
    char buf[4096];
    int rv;
    cjwt_t *jwt = NULL;
    cjwt_code_t result;

    CU_ASSERT_FATAL(NULL != b64_h);
    CU_ASSERT_FATAL(NULL != b64_p);

    rv = snprintf(buf, sizeof(buf), "%s.%s.", b64_h, b64_p);
    CU_ASSERT_FATAL((0 < rv) && (rv < (int) sizeof(buf)));

    result = cjwt_decode(buf, rv, t->options, NULL, 0, t->time, t->skew, &jwt);

    if (result != t->expected) {
        printf("\n\x1B[01;31m--- FAILED: %s.%s\nexp: %d, got: %d\x1B[00m\n",
               t->header, t->payload, t->expected, result);
    }
    CU_ASSERT_FATAL(result == t->expected);
    if (CJWTE_OK == result) {
        CU_ASSERT(t->jwt.header.alg == jwt->header.alg);
        str_eq(t->jwt.iss, jwt->iss);
        str_eq(t->jwt.sub, jwt->sub);
        str_eq(t->jwt.jti, jwt->jti);

        int64_eq(t->jwt.exp, jwt->exp);
        int64_eq(t->jwt.nbf, jwt->nbf);
        int64_eq(t->jwt.iat, jwt->iat);

        claims_eq(t->jwt.private_claims, jwt->private_claims);

        CU_ASSERT_FATAL(t->jwt.aud.count == jwt->aud.count);
        if (0 == t->jwt.aud.count) {
            CU_ASSERT_FATAL(NULL == t->jwt.aud.names);
        }
        for (int i = 0; i < t->jwt.aud.count; i++) {
            CU_ASSERT_STRING_EQUAL(t->jwt.aud.names[i], jwt->aud.names[i]);
        }
    }

    if (jwt) {
        cjwt_destroy(jwt);
    }
    if (b64_h) {
        free(b64_h);
    }
    if (b64_p) {
        free(b64_p);
    }
}

void test_cjwt(void)
{
    // char *header  = "{ \"alg\": \"RS256\" }";
    // char *payload = "{ \"bob\": 123 }";
    // char *b64_h = b64url_encode_with_alloc( (uint8_t*) header, strlen(header), NULL );
    // char *b64_p = b64url_encode_with_alloc( (uint8_t*) payload, strlen(payload), NULL );
    char *bad_h1     = "eyAiYWxnI|ogIm5vbmUiIH0.eyAiYm9iIjogMTIzIH0.";
    char *bad_h2     = ".eyAiYm9iIjogMTIzIH0.";
    char *bad_p1     = "eyAiYWxnIjogIm5vbmUiIH0.eyAiYm9iI|ogMTIzIH0.";
    char *bad_p2     = "eyAiYWxnIjogIm5vbmUiIH0..";
    char *bad_3group = "eyAiYWxnIjogIlJTMjU2IiB9.eyAiYm9iIjogMTIzIH0.";
    char *bad_5group = "eyAiYWxnIjogIlJTMjU2IiB9.eyAiYm9iIjogMTIzIH0...";
    cjwt_t *jwt;
    cjwt_code_t result;

    for (size_t i = 0; i < sizeof(test_list) / sizeof(test_case_t); i++) {
        test_case(&test_list[i]);
    }
    for (size_t i = 0; i < sizeof(json_test_list) / sizeof(json_test_case_t); i++) {
        json_test_case(&json_test_list[i]);
    }

    // printf( "%s.%s.", b64_h, b64_p );
    result = cjwt_decode(bad_h1, strlen(bad_h1), OPT_ALLOW_ALG_NONE, NULL, 0, 0, 0, &jwt);
    CU_ASSERT(CJWTE_HEADER_INVALID_BASE64 == result);

    result = cjwt_decode(bad_p1, strlen(bad_p1), OPT_ALLOW_ALG_NONE, NULL, 0, 0, 0, &jwt);
    CU_ASSERT(CJWTE_PAYLOAD_INVALID_BASE64 == result);

    result = cjwt_decode(bad_h2, strlen(bad_h2), OPT_ALLOW_ALG_NONE, NULL, 0, 0, 0, &jwt);
    CU_ASSERT(CJWTE_HEADER_MISSING == result);

    result = cjwt_decode(bad_p2, strlen(bad_p2), OPT_ALLOW_ALG_NONE, NULL, 0, 0, 0, &jwt);
    CU_ASSERT(CJWTE_PAYLOAD_MISSING == result);

    result = cjwt_decode(NULL, strlen(bad_p2), 0, NULL, 0, 0, 0, &jwt);
    CU_ASSERT(CJWTE_INVALID_PARAMETERS == result);

    result = cjwt_decode(bad_p2, 0, 0, NULL, 0, 0, 0, &jwt);
    CU_ASSERT(CJWTE_INVALID_PARAMETERS == result);

    result = cjwt_decode(bad_p2, strlen(bad_p2), 0, NULL, 0, 0, 0, NULL);
    CU_ASSERT(CJWTE_INVALID_PARAMETERS == result);

    result = cjwt_decode(bad_3group, strlen(bad_3group), 0, NULL, 0, 0, 0, &jwt);
    CU_ASSERT(CJWTE_SIGNATURE_MISSING == result);

    result = cjwt_decode(bad_5group, strlen(bad_5group), 0, NULL, 0, 0, 0, &jwt);
    CU_ASSERT(CJWTE_INVALID_SECTIONS == result);
}


void add_suites(CU_pSuite *suite)
{
    printf("--------Start of Test Cases Execution ---------\n");
    *suite = CU_add_suite("tests", NULL, NULL);
    CU_add_test(*suite, "Test cjwt", test_cjwt);
}

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
int main(void)
{
    unsigned rv     = 1;
    CU_pSuite suite = NULL;

    if (CUE_SUCCESS == CU_initialize_registry()) {
        add_suites(&suite);

        if (NULL != suite) {
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
            printf("\n");
            CU_basic_show_failures(CU_get_failure_list());
            printf("\n\n");
            rv = CU_get_number_of_tests_failed();
        }

        CU_cleanup_registry();
    }

    return rv;
}
