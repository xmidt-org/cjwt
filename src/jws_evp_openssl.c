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

    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    return rv;
}


cjwt_code_t verify_es(const EVP_MD *sha, const struct sig_input *in)
{
    cjwt_code_t rv       = CJWTE_SIGNATURE_VALIDATION_FAILED;
    EVP_MD_CTX *md_ctx   = NULL;
    EVP_PKEY_CTX *ctx    = NULL;
    EVP_PKEY *pkey       = NULL;
    EC_KEY *ec           = NULL;
    BIO *keybio          = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    BIGNUM *pr           = NULL;
    BIGNUM *ps           = NULL;
    int new_sig_len      = 0;
    uint8_t *new_sig     = NULL;
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int dig_len = 0;

    if ((0 == in->key.len) || (NULL == in->key.data)) {
        return CJWTE_SIGNATURE_MISSING_KEY;
    }

    if (INT_MAX < in->sig.len) {
        return CJWTE_SIGNATURE_KEY_TOO_LARGE;
    }

    /* Read the ECDSA key in from a PEM encoded blob of memory */
    keybio = BIO_new_mem_buf(in->key.data, (int) in->key.len);
    if (!keybio) {
        return CJWTE_OUT_OF_MEMORY;
    }

    ec = PEM_read_bio_EC_PUBKEY(keybio, &ec, NULL, NULL);
    BIO_free(keybio);
    if (!ec) {
        return CJWTE_SIGNATURE_INVALID_KEY;
    }

    pkey      = EVP_PKEY_new();
    md_ctx    = EVP_MD_CTX_new();
    ecdsa_sig = ECDSA_SIG_new();

    /* Read out the r,s numbers from the signature for later.
     * We must convert from this format into DEC because that's
     * all openssl supports. */
    pr = BN_bin2bn(in->sig.data, (int) in->sig.len / 2, NULL);
    ps = BN_bin2bn(in->sig.data + in->sig.len / 2, (int) in->sig.len / 2, NULL);

    /* Setup the pkey */
    if (pkey && ec && (1 == EVP_PKEY_assign_EC_KEY(pkey, ec))) {
        /* pkey owns the ec memory, don't free it. */
        ec  = NULL;
        ctx = EVP_PKEY_CTX_new(pkey, NULL);
    }

    if (md_ctx && pkey && ecdsa_sig && ctx
        /* Setup the sha digest buffer */
        && (1 == EVP_DigestInit_ex(md_ctx, sha, NULL))
        && (1 == EVP_DigestUpdate(md_ctx, in->full.data, in->full.len))
        && (1 == EVP_DigestFinal_ex(md_ctx, digest, &dig_len))
        /* Rebuild the signature in DEC format */
        && (1 == ECDSA_SIG_set0(ecdsa_sig, pr, ps)))
    {
        new_sig_len = i2d_ECDSA_SIG(ecdsa_sig, &new_sig);
    }

    if (0 < new_sig_len) {
        pr = NULL; /* We don't own the memory, don't free it. */
        ps = NULL; /* We don't own the memory, don't free it. */
    }

    if (ctx && new_sig && (0 < new_sig_len)
        && (1 == EVP_PKEY_verify_init(ctx))
        && (1 == EVP_PKEY_verify(ctx, new_sig, new_sig_len, digest, dig_len)))
    {
        rv = CJWTE_OK;
    }

    if (new_sig) OPENSSL_free(new_sig);
    if (ps) BN_free(ps);
    if (pr) BN_free(pr);
    if (ecdsa_sig) ECDSA_SIG_free(ecdsa_sig);
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (ec) EC_KEY_free(ec);

    return rv;
}


cjwt_code_t verify_rsa(const EVP_MD *sha, const struct sig_input *in, int padding)
{
    cjwt_code_t rv         = CJWTE_SIGNATURE_VALIDATION_FAILED;
    EVP_MD_CTX *md_ctx     = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey         = NULL;
    RSA *rsa               = NULL;
    BIO *keybio            = NULL;

    if ((0 == in->key.len) || (NULL == in->key.data)) {
        return CJWTE_SIGNATURE_MISSING_KEY;
    }

    /* Read the RSA key in from a PEM encoded blob of memory */
    keybio = BIO_new_mem_buf(in->key.data, (int) in->key.len);
    if (!keybio) {
        return CJWTE_OUT_OF_MEMORY;
    }

    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    BIO_free(keybio);
    if (!rsa) {
        return CJWTE_SIGNATURE_INVALID_KEY;
    }

    pkey   = EVP_PKEY_new();
    md_ctx = EVP_MD_CTX_create();

    if (md_ctx && pkey
        && (1 == EVP_PKEY_assign_RSA(pkey, rsa))
        && (1 == EVP_DigestInit_ex(md_ctx, sha, NULL))
        && (1 == EVP_DigestVerifyInit(md_ctx, &pkey_ctx, sha, NULL, pkey))
        && (0 < EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding))
        && (1 == EVP_DigestVerifyUpdate(md_ctx, in->full.data, in->full.len))
        && (1 == EVP_DigestVerifyFinal(md_ctx, in->sig.data, in->sig.len)))
    {
        rv = CJWTE_OK;
    }

    if (pkey) EVP_PKEY_free(pkey);
    if (md_ctx) EVP_MD_CTX_free(md_ctx);

    return rv;
}


/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
cjwt_code_t jws_verify_signature(const cjwt_t *jwt, const struct sig_input *in)
{
    switch (jwt->header.alg) {
        case alg_es256:
            return verify_es(EVP_sha256(), in);
        case alg_es384:
            return verify_es(EVP_sha384(), in);
        case alg_es512:
            return verify_es(EVP_sha512(), in);

        case alg_hs256:
            return verify_hmac(EVP_sha256(), in);
        case alg_hs384:
            return verify_hmac(EVP_sha384(), in);
        case alg_hs512:
            return verify_hmac(EVP_sha512(), in);

        case alg_ps256:
            return verify_rsa(EVP_sha256(), in, RSA_PKCS1_PSS_PADDING);
        case alg_ps384:
            return verify_rsa(EVP_sha384(), in, RSA_PKCS1_PSS_PADDING);
        case alg_ps512:
            return verify_rsa(EVP_sha512(), in, RSA_PKCS1_PSS_PADDING);

        case alg_rs256:
            return verify_rsa(EVP_sha256(), in, RSA_PKCS1_PADDING);
        case alg_rs384:
            return verify_rsa(EVP_sha384(), in, RSA_PKCS1_PADDING);
        case alg_rs512:
            return verify_rsa(EVP_sha512(), in, RSA_PKCS1_PADDING);

        default:
            break;
    }

    return CJWTE_SIGNATURE_UNSUPPORTED_ALG;
}
