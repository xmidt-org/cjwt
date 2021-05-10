/* SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC */
/* SPDX-FileCopyrightText: 2021 Weston Schmidt */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __B64_H__
#define __B64_H__

#include <stddef.h>
#include <stdint.h>

/**
 *  Takes the url base64 encoded buffer specified and converts it to the bytes
 *  it represents and returns the bytes in a newly allocated buffer.  The new
 *  size is returned via the out_len parameter if it is specified.
 *
 *  @note The resulting buffer is 1 byte longer & that byte contains a '\0' to
 *        accomidate code that does not honor lengths.
 *
 *  @param in       the url base64 encoded buffer to decode
 *  @param in_len   the number of bytes to process
 *  @param out_len  the number of valid bytes returned in the buffer if not NULL
 *
 *  @return the buffer with the data or NULL if there is an error
 */
uint8_t* b64_url_decode( const char *in, size_t in_len, size_t *out_len );

#endif

