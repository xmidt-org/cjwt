/* SPDX-FileCopyrightText: 2021-2022 Comcast Cable Communications Management, LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "cjwt.h"

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
extern const char *alg_to_string(cjwt_alg_t alg);
static const char *str(const char *s);
static void priv(FILE *stream, cJSON *list);

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
void cjwt_print(FILE *stream, cjwt_t *jwt)
{
    if (!jwt) {
        fprintf(stream,
                "=====================\n"
                "jwt is NULL\n"
                "=====================\n");
        return;
    }

    fprintf(stream,
            "=====================\n"
            "header\n"
            "---------------------\n"
            "   alg: %s\n"
            "   kid: %s\n"
            "   private_headers:\n\n",
            alg_to_string(jwt->header.alg),
            str(jwt->header.kid));

    priv(stream, jwt->header.private_headers);


    fprintf(stream,
            "payload\n"
            "---------------------\n");

    if (jwt->iat) {
        fprintf(stream, "   iat: %" PRId64 "\n\n", *jwt->iat);
    } else {
        fprintf(stream, "   iat: NULL\n\n");
    }
    if (jwt->exp) {
        fprintf(stream, "   exp: %" PRId64 "\n", *jwt->exp);
    } else {
        fprintf(stream, "   exp: NULL\n");
    }
    if (jwt->nbf) {
        fprintf(stream, "   nbf: %" PRId64 "\n\n", *jwt->nbf);
    } else {
        fprintf(stream, "   nbf: NULL\n\n");
    }
    fprintf(stream, "   iss: %s\n", str(jwt->iss));
    fprintf(stream, "   sub: %s\n", str(jwt->sub));
    fprintf(stream, "   jti: %s\n", str(jwt->jti));
    fprintf(stream, "   aud: ");
    if (0 == jwt->aud.count) {
        fprintf(stream, "NULL\n");
    } else {
        const char *comma = "";
        for (int i = 0; i < jwt->aud.count; i++) {
            fprintf(stream, "%s%s", comma, jwt->aud.names[i]);
            comma = ", ";
        }
        fprintf(stream, "\n");
    }

    fprintf(stream,
            "\nprivate claims\n"
            "---------------------\n");
    priv(stream, jwt->private_claims);
    fprintf(stream, "=====================\n");
}


/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/
static const char *str(const char *s)
{
    if (NULL == s) {
        return "NULL";
    }

    return s;
}

static void priv(FILE *stream, cJSON *list)
{
    if (list) {
        char *text = NULL;

        text = cJSON_Print(list);
        fprintf(stream, "%s\n", text);
        cJSON_free(text);
    } else {
        fprintf(stream, "(none)\n");
    }
    fprintf(stream, "=====================\n");
}
