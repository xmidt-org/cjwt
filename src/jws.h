/* SPDX-FileCopyrightText: 2021-2022 Comcast Cable Communications Management, LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __JWS_H__
#define __JWS_H__

#include <stddef.h>
#include <stdint.h>

#include "cjwt.h"

struct sig_section {
    const uint8_t *data;
    size_t len;
};

struct sig_input {
    struct sig_section full;
    struct sig_section sig;
    struct sig_section key;
};

cjwt_code_t jws_verify_signature(const cjwt_t *jwt, const struct sig_input *in);

#endif
