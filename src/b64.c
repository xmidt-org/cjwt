/* SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>
#include <stdlib.h>

#include "b64.h"

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
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
uint8_t* b64_url_decode( const char *in, size_t in_len, size_t *out_len )
{
    // -1 = invalid
    // -2 = padding
    static const int8_t map[256] = {
        -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,    /* 0x00-0x0f */
        -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,    /* 0x10-0x1f */
        -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,62,-1,-1,    /* 0x20-0x2f */
        52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-2,-1,-1,    /* 0x30-0x3f */
        -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,    /* 0x40-0x4f */
        15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,63,    /* 0x50-0x5f */
        -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,    /* 0x60-0x6f */
        41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1,    /* 0x70-0x7f */
        -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,    /* 0x80-0x8f */
        -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,    /* 0x90-0x9f */
        -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,    /* 0xa0-0xaf */
        -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,    /* 0xb0-0xbf */
        -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,    /* 0xc0-0xcf */
        -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,    /* 0xd0-0xdf */
        -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,    /* 0xe0-0xef */
        -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,    /* 0xf0-0xff */
    };
    uint32_t bits = 0;
    int bit_count = 0;
    size_t padding = 0;
    size_t decoded_len = 0;
    size_t remainder;
    uint8_t *out = NULL;

    if( !in || (in_len < 2) ) {
        return NULL;
    }

    if( '=' == in[in_len - 1] ) {
        padding++;
        if( '=' == in[in_len - 2] ) {
            padding++;
        }

        /* If there is padding then it should only pad to ensure the string
         * has a multiple of 4.  Anything else is an error. */
        if( 0 != (0x03 & in_len) ) {
            return NULL;
        }
    }

    in_len -= padding;

    /* This order of operations prevents overflow for really large numbers */
    decoded_len = (in_len / 4) * 3;
    remainder = 0x3 & in_len;

    /* Remainder mapping:
     *  Remainder | Extra bytes represented
     *  ----------+------------------------
     *          0 | 0
     *          1 | invalid, exit with size 0
     *          2 | 1
     *          3 | 2
     */

    if( 1 == remainder ) {
        return NULL;
    } else if( 0 < remainder ) {
        remainder--;
    }

    decoded_len += remainder;

    /* The +1 is a hack for now to give a character for a trailing '\0'
     * in the event that lengths are not honored. */
    out = malloc( decoded_len + 1 );
    if( !out ) {
        return NULL;
    }

    /* The other part of the hack. */
    out[decoded_len] = '\0';

    for( size_t i = 0, j = 0; i < in_len; i++ ) {
        int8_t val;

        val = map[(uint8_t) in[i]];
        if( val < 0 ) {
            free( out );
            return NULL;
        }
        bits = (bits << 6) | val;
        bit_count += 6;

        if( 8 <= bit_count ) {
            out[j] = (uint8_t) (0x0ff & (bits >> (bit_count - 8)));
            j++;
            bit_count -= 8;
        }
    }

    if( out_len ) {
        *out_len = decoded_len;
    }

    return out;
}

/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/
/* none */
