/* SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC */
/* SPDX-License-Identifier: Apache-2.0 */

#include <string.h>

#include "utils.h"

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
int split( const char *full, size_t len, struct split_jwt *split )
{
    size_t dots[6] = { 0, len, len, len, len, len };

    memset( split, 0, sizeof(struct split_jwt) );

    split->count = 1;
    for( size_t i = 0; i < len; i++ ) {
        if( '.' == full[i] ) {
            if( 4 < split->count ) {
                /* Too many sections */
                return -1;
            }
            dots[split->count] = i;
            split->count++;
        }
    }

    if( 1 == split->count ) {
        return -1;
    }

    split->sections[0].data = full;
    split->sections[0].len = dots[1];

    for( size_t i = 1; i < split->count; i++ ) {
        split->sections[i].data = &full[dots[i] + 1];
        split->sections[i].len = dots[i+1] - dots[i] - 1;
    }

    return 0;
}

/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/
/* none */

