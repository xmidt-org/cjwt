/* SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC */
/* SPDX-License-Identifier: Apache-2.0 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CUnit/Basic.h>

#include "../src/b64.h"


struct test_vector {
    const char *in;
    size_t in_len;
    const char *out;
    size_t out_len;
};

void test_b64_url_decode()
{
    struct test_vector tests[] = {
        /* Simple NULL, string length tests */
        {   .in = NULL,
            .in_len = 0,
            .out = NULL,
            .out_len = 0,
        },
        {   .in = "asdf123",
            .in_len = 0,
            .out = NULL,
            .out_len = 0,
        },

        /* The length must be at least 2 */
        {   .in = "a",
            .in_len = 1,
            .out = NULL,
            .out_len = 0,
        },

        /* Every character must be valid */
        {   .in = "asdf1\xffjj",
            .in_len = 8,
            .out = NULL,
            .out_len = 0,
        },
        {   .in = "asdf1=jj",
            .in_len = 8,
            .out = NULL,
            .out_len = 0,
        },

        /* Protect against a bogus empty string */
        {   .in = "==",
            .in_len = 2,
            .out = NULL,
            .out_len = 0,
        },

        /* Invalid, safely fail. */
        {   .in = "b==",
            .in_len = 3,
            .out = NULL,
            .out_len = 0,
        },

        /* Invalid, padding. */
        {   .in = "ba=",
            .in_len = 3,
            .out = NULL,
            .out_len = 0,
        },
        {   .in = "bad==",
            .in_len = 5,
            .out = NULL,
            .out_len = 0,
        },
        {   .in = "bad4==",
            .in_len = 6,
            .out = NULL,
            .out_len = 0,
        },
        {   .in = "bad4=",
            .in_len = 5,
            .out = NULL,
            .out_len = 0,
        },


        /* Disallow other forms. */
        {   .in = "ab+d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as/d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as,d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as,d", .in_len = 4, .out = NULL, .out_len = 0, },

        /* Disallow other printable charcters. */
        {   .in = "as d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as!d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as\"d",.in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as#d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as$d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as%d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as&d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as'd", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as(d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as)d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as*d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as.d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as:d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as;d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as<d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as>d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as?d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as@d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as[d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as\\d",.in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as]d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as^d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as`d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as{d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as|d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as}d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as~d", .in_len = 4, .out = NULL, .out_len = 0, },

        /* Disallow other non-printable charcters. */
        {   .in = "as\x00d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as\x01d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as\x02d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as\x03d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as\x04d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as\x05d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as\x06d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as\x07d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as\x08d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as\x09d", .in_len = 4, .out = NULL, .out_len = 0, },
        {   .in = "as\x0ad", .in_len = 4, .out = NULL, .out_len = 0, },

        /* A remainder of 1 is never valid */
        {   .in = "TWFub",
            .in_len = 5,
            .out = NULL,
            .out_len = 0,
        },

        /* Simple valid examples */
        {   .in = "TWFu",
            .in_len = 4,
            .out = "Man",
            .out_len = 3,
        },
        {   .in = "TWE=",
            .in_len = 4,
            .out = "Ma",
            .out_len = 2,
        },
        {   .in = "TQ==",
            .in_len = 4,
            .out = "M",
            .out_len = 1,
        },

        /* The padding '=' is optional for the URL variant. */
        {   .in = "TWE",
            .in_len = 3,
            .out = "Ma",
            .out_len = 2,
        },
        {   .in = "TQ",
            .in_len = 2,
            .out = "M",
            .out_len = 1,
        },

        /* A longer sample text. */
        {   .in = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24s"
                  "IGJ1dCBieSB0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmlt"
                  "YWxzLCB3aGljaCBpcyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBw"
                  "ZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGludWVkIGFuZCBp"
                  "bmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRz"
                  "IHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=",
            .in_len = 360,
            .out = "Man is distinguished, not only by his reason, but by this "
                   "singular passion from other animals, which is a lust of "
                   "the mind, that by a perseverance of delight in the "
                   "continued and indefatigable generation of knowledge, "
                   "exceeds the short vehemence of any carnal pleasure.",
            .out_len = 269,
        },

        /* Use every character to ensure they all map properly */
        {   .in = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                  "abcdefghijklmnopqrstuvwxyz"
                  "0123456789-_",
            .in_len = 64,
            .out = "\x00\x10\x83\x10\x51\x87\x20\x92\x8b\x30"
                   "\xd3\x8f\x41\x14\x93\x51\x55\x97\x61\x96"
                   "\x9b\x71\xd7\x9f\x82\x18\xa3\x92\x59\xa7"
                   "\xa2\x9a\xab\xb2\xdb\xaf\xc3\x1c\xb3\xd3"
                   "\x5d\xb7\xe3\x9e\xbb\xf3\xdf\xbf",
            .out_len = 48,
        },

    };

    for( size_t i = 0; i < sizeof(tests)/sizeof(struct test_vector); i++ ) {
        uint8_t *got;
        size_t got_len = 0xffff0;

        got = b64_url_decode( tests[i].in, tests[i].in_len, &got_len );

        if( !tests[i].out ) {
            CU_ASSERT_FATAL( NULL == got );
            CU_ASSERT_FATAL( 0xffff0 == got_len );
        } else {
            CU_ASSERT_FATAL( NULL != got );

            CU_ASSERT_FATAL( tests[i].out_len == got_len );
            if( 0 < tests[i].out_len ) {
                for( size_t j = 0; j < tests[i].out_len; j++ ) {
                    CU_ASSERT( (uint8_t) tests[i].out[j] == got[j] );
                }

                free( got );
            }
        }

        /* Run the test again with no length */
        got = b64_url_decode( tests[i].in, tests[i].in_len, NULL );
        if( !tests[i].out ) {
            CU_ASSERT_FATAL( NULL == got );
        } else {
            CU_ASSERT_FATAL( NULL != got );

            if( 0 < tests[i].out_len ) {
                for( size_t j = 0; j < tests[i].out_len; j++ ) {
                    CU_ASSERT( (uint8_t) tests[i].out[j] == got[j] );
                }

                free( got );
            }
        }
    }
}


void add_suites( CU_pSuite *suite )
{
    *suite = CU_add_suite( "b64_url_decode tests", NULL, NULL );
    CU_add_test( *suite, "General Tests", test_b64_url_decode );
}


/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
int main( void )
{
    unsigned rv = 1;
    CU_pSuite suite = NULL;

    if( CUE_SUCCESS == CU_initialize_registry() ) {
        add_suites( &suite );

        if( NULL != suite ) {
            CU_basic_set_mode( CU_BRM_VERBOSE );
            CU_basic_run_tests();
            printf( "\n" );
            CU_basic_show_failures( CU_get_failure_list() );
            printf( "\n\n" );
            rv = CU_get_number_of_tests_failed();
        }

        CU_cleanup_registry();
    }

    if( 0 != rv ) {
        return 1;
    }
    return 0;
}
