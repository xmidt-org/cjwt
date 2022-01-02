// SPDX-FileCopyrightText: 2017-2022 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

#include <cjson/cJSON.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <trower-base64/base64.h>

#include "cjwt.h"
#include "jws.h"
#include "utils.h"

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
/* none */

/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/
struct alg_map {
    cjwt_alg_t alg;
    const char *text;
};

/*----------------------------------------------------------------------------*/
/*                            File Scoped Variables                           */
/*----------------------------------------------------------------------------*/
const struct alg_map the_alg_map[] = {
    { .alg = alg_none,  .text = "none"},
    {.alg = alg_es256, .text = "ES256"},
    {.alg = alg_es384, .text = "ES384"},
    {.alg = alg_es512, .text = "ES512"},
    {.alg = alg_hs256, .text = "HS256"},
    {.alg = alg_hs384, .text = "HS384"},
    {.alg = alg_hs512, .text = "HS512"},
    {.alg = alg_ps256, .text = "PS256"},
    {.alg = alg_ps384, .text = "PS384"},
    {.alg = alg_ps512, .text = "PS512"},
    {.alg = alg_rs256, .text = "RS256"},
    {.alg = alg_rs384, .text = "RS384"},
    {.alg = alg_rs512, .text = "RS512"}
};

/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
/* none */

/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/

static int alg_to_enum(const char *alg_str, cjwt_alg_t *alg)
{
    for (size_t i = 0; i < sizeof(the_alg_map) / sizeof(struct alg_map); i++) {
        if (!strcmp(alg_str, the_alg_map[i].text)) {
            *alg = the_alg_map[i].alg;
            return 0;
        }
    }

    return -1;
}

const char *alg_to_string(cjwt_alg_t alg)
{
    for (size_t i = 0; i < sizeof(the_alg_map) / sizeof(struct alg_map); i++) {
        if (alg == the_alg_map[i].alg) {
            return the_alg_map[i].text;
        }
    }

    return "unknown";
}

static void delete_public_claims(cJSON *json)
{
    const char *claims[] = { "iss",
                             "sub",
                             "aud",
                             "jti",
                             "exp",
                             "nbf",
                             "iat" };

    for (size_t i = 0; i < sizeof(claims) / sizeof(char *); i++) {
        cJSON_DeleteItemFromObjectCaseSensitive(json, claims[i]);
    }
}


static cjwt_code_t process_string(const cJSON *json, const char *name, char **dest)
{
    const cJSON *val = cJSON_GetObjectItemCaseSensitive(json, name);

    if (val) {
        if (val->type != cJSON_String) {
            return CJWTE_PAYLOAD_EXPECTED_STRING;
        }

        *dest = cjwt_strdup(val->valuestring);
        if (!(*dest)) {
            return CJWTE_OUT_OF_MEMORY;
        }
    }

    return CJWTE_OK;
}

static cjwt_code_t process_time(const cJSON *json, const char *name, int64_t **dest)
{
    const cJSON *val = cJSON_GetObjectItemCaseSensitive(json, name);

    if (val) {
        if (val->type == cJSON_Number) {
            *dest = malloc(sizeof(int64_t));
            if (!(*dest)) {
                return CJWTE_OUT_OF_MEMORY;
            }

            **dest = val->valueint;
        } else {
            return CJWTE_PAYLOAD_EXPECTED_NUMBER;
        }
    }

    return CJWTE_OK;
}

static cjwt_code_t process_aud(const cJSON *json, cjwt_t *cjwt)
{
    const cJSON *tmp = NULL;
    const cJSON *aud = NULL;

    aud = cJSON_GetObjectItemCaseSensitive(json, "aud");

    if (!aud) {
        return CJWTE_OK;
    }

    if (cJSON_Array == aud->type) {
        cjwt->aud.count = cJSON_GetArraySize(aud);
        cjwt->aud.names = calloc(cjwt->aud.count, sizeof(char *));

        if (!cjwt->aud.names) {
            return CJWTE_OUT_OF_MEMORY;
        }

        for (int i = 0; i < cjwt->aud.count; i++) {
            tmp = cJSON_GetArrayItem(aud, i);

            if (tmp->type != cJSON_String) {
                return CJWTE_PAYLOAD_EXPECTED_STRING;
            }

            cjwt->aud.names[i] = cjwt_strdup(tmp->valuestring);
            if (!cjwt->aud.names[i]) {
                return CJWTE_OUT_OF_MEMORY;
            }
        }
    } else if (cJSON_String == aud->type) {
        cjwt->aud.count = 1;
        cjwt->aud.names = calloc(cjwt->aud.count, sizeof(char *));

        if (!cjwt->aud.names) {
            return CJWTE_OUT_OF_MEMORY;
        }

        cjwt->aud.names[0] = cjwt_strdup(aud->valuestring);
        if (!cjwt->aud.names[0]) {
            return CJWTE_OUT_OF_MEMORY;
        }
    } else {
        return CJWTE_PAYLOAD_EXPECTED_STRING;
    }

    return CJWTE_OK;
}

static cjwt_code_t process_payload(cjwt_t *cjwt, const char *payload, size_t len)
{
    cjwt_code_t rv     = CJWTE_OK;
    size_t decoded_len = 0;
    char *decoded      = NULL;
    cJSON *json        = NULL;

    decoded = (char *) b64url_decode_with_alloc((const uint8_t *) payload, len,
                                                &decoded_len);
    if (!decoded) {
        return CJWTE_PAYLOAD_INVALID_BASE64;
    }

    json = cJSON_ParseWithLength(decoded, decoded_len);
    if (!json) {
        free(decoded);
        return CJWTE_PAYLOAD_INVALID_JSON;
    }

    rv |= process_string(json, "iss", &cjwt->iss);
    rv |= process_string(json, "sub", &cjwt->sub);
    rv |= process_string(json, "jti", &cjwt->jti);

    rv |= process_time(json, "exp", &cjwt->exp);
    rv |= process_time(json, "nbf", &cjwt->nbf);
    rv |= process_time(json, "iat", &cjwt->iat);

    rv |= process_aud(json, cjwt);

    /* The private_claims either is assigned the json blob or deletes it. */
    delete_public_claims(json);

    if (cJSON_GetArraySize(json)) {
        cjwt->private_claims = json;
    } else {
        cJSON_Delete(json);
    }

    free(decoded);
    return rv;
}


static cjwt_code_t process_header_json(cjwt_t *cjwt, uint32_t options,
                                       cJSON *json)
{
    const cJSON *alg = NULL;
    const cJSON *typ = NULL;

    alg = cJSON_GetObjectItemCaseSensitive(json, "alg");
    if (!alg) {
        return CJWTE_HEADER_MISSING_ALG;
    }

    if (alg->type != cJSON_String) {
        return CJWTE_HEADER_UNSUPPORTED_ALG;
    }

    if (0 != alg_to_enum(alg->valuestring, &cjwt->header.alg)) {
        return CJWTE_HEADER_UNSUPPORTED_ALG;
    }

    if ((alg_none == cjwt->header.alg)
        && (0 == (OPT_ALLOW_ALG_NONE & options)))
    {
        return CJWTE_HEADER_UNSUPPORTED_ALG;
    }


    typ = cJSON_GetObjectItemCaseSensitive(json, "typ");
    if (typ && (0 == (OPT_ALLOW_ANY_TYP & options))) {
        const char *s = typ->valuestring;

        if (typ->type != cJSON_String) {
            return CJWTE_HEADER_UNSUPPORTED_TYP;
        }

        if ((('J' != s[0]) && ('j' != s[0]))
            || (('W' != s[1]) && ('w' != s[1]))
            || (('T' != s[2]) && ('t' != s[2]))
            || ('\0' != s[3]))
        {
            return CJWTE_HEADER_UNSUPPORTED_TYP;
        }
    }

    cJSON_DeleteItemFromObjectCaseSensitive(json, "alg");
    cJSON_DeleteItemFromObjectCaseSensitive(json, "typ");

    if (json->next || json->prev || json->child) {
        return CJWTE_HEADER_UNSUPPORTED_UNKNOWN;
    }

    return CJWTE_OK;
}


static cjwt_code_t process_header(cjwt_t *cjwt, uint32_t options,
                                  const char *header, size_t len)
{
    cjwt_code_t rv;
    size_t decoded_len = 0;
    char *decoded      = NULL;
    cJSON *json        = NULL;

    decoded = (char *) b64url_decode_with_alloc((const uint8_t *) header, len,
                                                &decoded_len);
    if (!decoded) {
        return CJWTE_HEADER_INVALID_BASE64;
    }

    json = cJSON_ParseWithLength(decoded, decoded_len);
    if (!json) {
        free(decoded);
        return CJWTE_HEADER_INVALID_JSON;
    }

    rv = process_header_json(cjwt, options, json);

    cJSON_Delete(json);
    free(decoded);

    return rv;
}

static cjwt_code_t verify_signature(const cjwt_t *jwt,
                                    const uint8_t *full, size_t full_len,
                                    const char *enc_sig, size_t enc_sig_len,
                                    const uint8_t *key, size_t key_len)
{
    cjwt_code_t rv = CJWTE_OK;
    struct sig_input in;
    uint8_t *sig;
    size_t sig_len;

    sig = b64url_decode_with_alloc((const uint8_t *) enc_sig,
                                   enc_sig_len, &sig_len);
    if (!sig) {
        return CJWTE_SIGNATURE_INVALID_BASE64;
    }

    in.full.data = full;
    in.full.len  = full_len;
    in.key.data  = key;
    in.key.len   = key_len;
    in.sig.len   = sig_len;
    in.sig.data  = sig;


    rv = jws_verify_signature(jwt, &in);

    free(sig);
    return rv;
}


static cjwt_code_t verify_time_windows(const cjwt_t *jwt, uint32_t options,
                                       int64_t time, int64_t skew)
{
    if (OPT_ALLOW_ANY_TIME == (OPT_ALLOW_ANY_TIME & options)) {
        return CJWTE_OK;
    }

    if (jwt->nbf && ((time + skew) < *(jwt->nbf))) {
        return CJWTE_TIME_BEFORE_NBF;
    }

    if (jwt->exp && (*(jwt->exp) < (time - skew))) {
        return CJWTE_TIME_AFTER_EXP;
    }

    return CJWTE_OK;
}


/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/


/**
 * validates jwt token and extracts data
 */
cjwt_code_t cjwt_decode(const char *encoded, size_t enc_len, uint32_t options,
                        const uint8_t *key, size_t key_len,
                        int64_t time, int64_t skew, cjwt_t **jwt)
{
    cjwt_code_t rv = CJWTE_OK;
    struct split_jwt sections;
    const struct section *header  = NULL;
    const struct section *payload = NULL;
    cjwt_t *out                   = NULL;

    if (!encoded || !jwt || !enc_len) {
        return CJWTE_INVALID_PARAMETERS;
    }

    if (split(encoded, enc_len, &sections)) {
        return CJWTE_HEADER_MISSING;
    }

    /* JWS has 3 sections, JWE has 5, only JWS is supported today. */
    if (3 != sections.count) {
        return CJWTE_INVALID_SECTIONS;
    }

    header  = &sections.sections[0];
    payload = &sections.sections[1];

    if (!header->len) {
        return CJWTE_HEADER_MISSING;
    }

    if (!payload->len) {
        return CJWTE_PAYLOAD_MISSING;
    }


    out = calloc(1, sizeof(cjwt_t));
    if (!out) {
        return CJWTE_OUT_OF_MEMORY;
    }

    rv = process_header(out, options, header->data, header->len);
    if (rv) {
        goto invalid;
    }

    if (out->header.alg != alg_none) {
        const struct section *sig = &sections.sections[2];
        size_t signed_len         = 0;

        if (0 == sig->len) {
            rv = CJWTE_SIGNATURE_MISSING;
            goto invalid;
        }
        signed_len = header->len + payload->len + 1;

        rv = verify_signature(out, (const uint8_t *) encoded, signed_len,
                              sig->data, sig->len, key, key_len);
        if (rv) {
            goto invalid;
        }
    }

    rv = process_payload(out, payload->data, payload->len);
    if (rv) {
        goto invalid;
    }

    rv = verify_time_windows(out, options, time, skew);

invalid:

    if (rv) {
        cjwt_destroy(out);
    } else {
        *jwt = out;
    }

    return rv;
}


/**
 * cleanup jwt object
 */
void cjwt_destroy(cjwt_t *jwt)
{
    if (jwt) {
        if (jwt->iss) {
            free(jwt->iss);
        }

        if (jwt->sub) {
            free(jwt->sub);
        }

        if (jwt->jti) {
            free(jwt->jti);
        }

        if (jwt->exp) {
            free(jwt->exp);
        }

        if (jwt->nbf) {
            free(jwt->nbf);
        }

        if (jwt->iat) {
            free(jwt->iat);
        }

        for (int i = 0; i < jwt->aud.count; i++) {
            if (jwt->aud.names[i]) {
                free(jwt->aud.names[i]);
            }
        }

        if (jwt->aud.names) {
            free(jwt->aud.names);
        }

        if (jwt->private_claims) {
            cJSON_Delete(jwt->private_claims);
        }

        free(jwt);
    }
}


cjwt_code_t cjwt_alg_string_to_enum(const char *s, size_t len, cjwt_alg_t *alg)
{
    char buf[6];
    int found = 0;

    if (!s || !len || !alg) {
        return CJWTE_INVALID_PARAMETERS;
    }

    if (SIZE_MAX == len) {
        len = strlen(s);
    }

    if ((4 != len) && (5 != len)) {
        return CJWTE_UNKNOWN_ALG;
    }

    memcpy(buf, s, len);
    buf[len] = '\0';

    found = alg_to_enum(buf, alg);

    return (0 == found) ? CJWTE_OK : CJWTE_UNKNOWN_ALG;
}
