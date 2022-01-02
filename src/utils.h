/* SPDX-FileCopyrightText: 2021-2022 Comcast Cable Communications Management, LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <stddef.h>
#include <stdlib.h>

struct section {
    const char *data;
    size_t len;
};

struct split_jwt {
    size_t count;
    struct section sections[5];
};

int split(const char *full, size_t len, struct split_jwt *split);

char *cjwt_strdup(const char *s);

#endif
