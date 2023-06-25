/* SPDX-FileCopyrightText: 2021-2022 Comcast Cable Communications Management, LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>

#include "cjwt.h"
#include "jws.h"

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
/* none */

/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/
cjwt_code_t verify_hmac(const EVP_MD *sha, const struct sig_input *in)
{
    cjwt_code_t rv     = CJWTE_SIGNATURE_VALIDATION_FAILED;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY *pkey     = NULL;
    uint8_t buff[EVP_MAX_MD_SIZE];
    size_t size = sizeof(buff);

    if (INT_MAX < in->key.len) {
        return CJWTE_KEY_TOO_LARGE;
    }

    md_ctx = EVP_MD_CTX_new();
    pkey   = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, in->key.data, (int) in->key.len);

    if (md_ctx && pkey
        && (1 == EVP_DigestSignInit(md_ctx, NULL, sha, NULL, pkey))
        && (1 == EVP_DigestSignUpdate(md_ctx, in->full.data, in->full.len))
        && (1 == EVP_DigestSignFinal(md_ctx, buff, &size))
        && (in->sig.len == size)
        && (0 == CRYPTO_memcmp(in->sig.data, buff, size)))
    {
        rv = CJWTE_OK;
    }

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(md_ctx);
    return rv;
}

int add_padding(int type, EVP_PKEY_CTX *ctx, int padding)
{
    if (EVP_PKEY_EC == type) {
        return 1;
    }

    return EVP_PKEY_CTX_set_rsa_padding(ctx, padding);
}

int calc_sig(int type, const struct sig_input *in, uint8_t **sig, int *len)
{
    int rv               = 0; /* Match the other openssl symantics for consistency */
    ECDSA_SIG *ecdsa_sig = NULL;
    BIGNUM *pr           = NULL;
    BIGNUM *ps           = NULL;
    int new_sig_len      = 0;
    uint8_t *new_sig     = NULL;

    if (EVP_PKEY_RSA == type) {
        *sig = (uint8_t *) in->sig.data;
        *len = in->sig.len;
        return 1;
    }

    ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL) {
        return 0;
    }

    /* Read out the r,s numbers from the signature for later.
     * We must convert from this format into DEC because that's
     * all openssl supports. */
    pr = BN_bin2bn(in->sig.data, (int) in->sig.len / 2, NULL);
    ps = BN_bin2bn(in->sig.data + in->sig.len / 2, (int) in->sig.len / 2, NULL);

    if (1 == ECDSA_SIG_set0(ecdsa_sig, pr, ps)) {
        new_sig_len = i2d_ECDSA_SIG(ecdsa_sig, &new_sig);
        if (0 <= new_sig_len) {
            /* We don't own the memory now, don't free it. */
            pr = NULL;
            ps = NULL;

            if (0 < new_sig_len) {
                *sig    = new_sig;
                *len    = new_sig_len;
                new_sig = NULL; /* Passed back now, so don't free the buffer. */
                rv      = 1;
            }
        }
    }

    OPENSSL_free(new_sig);
    ECDSA_SIG_free(ecdsa_sig);
    BN_free(ps);
    BN_free(pr);

    return rv;
}

cjwt_code_t verify_most(const EVP_MD *sha, const struct sig_input *in, int type, int padding)
{
    cjwt_code_t rv         = CJWTE_SIGNATURE_VALIDATION_FAILED;
    EVP_MD_CTX *md_ctx     = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey         = NULL;
    BIO *keybio            = NULL;
    int sig_len            = 0;
    uint8_t *sig           = NULL;

    if ((0 == in->key.len) || (NULL == in->key.data)) {
        return CJWTE_SIGNATURE_MISSING_KEY;
    }

    /* Read the RSA key in from a PEM encoded blob of memory */
    keybio = BIO_new_mem_buf(in->key.data, (int) in->key.len);
    if (!keybio) {
        return CJWTE_OUT_OF_MEMORY;
    }

    pkey = PEM_read_bio_PUBKEY(keybio, NULL, NULL, NULL);
    if (!pkey) {
        rv = CJWTE_SIGNATURE_INVALID_KEY;
        goto done;
    }

    if (type != EVP_PKEY_id(pkey)) {
        rv = CJWTE_SIGNATURE_INVALID_KEY;
        goto done;
    }

    md_ctx = EVP_MD_CTX_create();

    if (md_ctx
        && (1 == calc_sig(type, in, &sig, &sig_len))
        && (1 == EVP_DigestVerifyInit(md_ctx, &pkey_ctx, sha, NULL, pkey))
        && (0 < add_padding(type, pkey_ctx, padding))
        && (1 == EVP_DigestVerifyUpdate(md_ctx, in->full.data, in->full.len))
        && (1 == EVP_DigestVerifyFinal(md_ctx, sig, sig_len)))
    {
        rv = CJWTE_OK;
    }

done:

    if (sig != in->sig.data) OPENSSL_free(sig);

    BIO_free(keybio);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(md_ctx);

    return rv;
}


/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
cjwt_code_t jws_verify_signature(const cjwt_t *jwt, const struct sig_input *in)
{
    switch (jwt->header.alg) {
        case alg_es256:
            return verify_most(EVP_sha256(), in, EVP_PKEY_EC, 0);
        case alg_es384:
            return verify_most(EVP_sha384(), in, EVP_PKEY_EC, 0);
        case alg_es512:
            return verify_most(EVP_sha512(), in, EVP_PKEY_EC, 0);

        case alg_hs256:
            return verify_hmac(EVP_sha256(), in);
        case alg_hs384:
            return verify_hmac(EVP_sha384(), in);
        case alg_hs512:
            return verify_hmac(EVP_sha512(), in);

        case alg_ps256:
            return verify_most(EVP_sha256(), in, EVP_PKEY_RSA, RSA_PKCS1_PSS_PADDING);
        case alg_ps384:
            return verify_most(EVP_sha384(), in, EVP_PKEY_RSA, RSA_PKCS1_PSS_PADDING);
        case alg_ps512:
            return verify_most(EVP_sha512(), in, EVP_PKEY_RSA, RSA_PKCS1_PSS_PADDING);

        case alg_rs256:
            return verify_most(EVP_sha256(), in, EVP_PKEY_RSA, RSA_PKCS1_PADDING);
        case alg_rs384:
            return verify_most(EVP_sha384(), in, EVP_PKEY_RSA, RSA_PKCS1_PADDING);
        case alg_rs512:
            return verify_most(EVP_sha512(), in, EVP_PKEY_RSA, RSA_PKCS1_PADDING);

        default:
            break;
    }

    return CJWTE_SIGNATURE_UNSUPPORTED_ALG;
}
