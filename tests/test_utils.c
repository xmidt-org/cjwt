/* SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC */
/* SPDX-License-Identifier: Apache-2.0 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CUnit/Basic.h>

#include "../src/utils.h"


struct test_vector {
    const char *full;
    size_t len;
    int rv;
    struct split_jwt goal;
};

void test_split()
{
    struct test_vector tests[] = {
        {   .full = "abcdefghijkl",
            .len  = 12,
            .rv   = -1,
        },
        {   .full = "a.b.c.d.e.fghijkl",
            .len  = 17,
            .rv   = -1,
        },
        {   .full = "abcd.efg",
            .len  = 8,
            .rv   = 0,
            .goal = {
                .count = 2,
                .sections = {
                    { .data = "abcd", .len = 4 },
                    { .data = "efg",  .len = 3 },
                    { .data = NULL,   .len = 0 },
                    { .data = NULL,   .len = 0 },
                    { .data = NULL,   .len = 0 },
                },
            },
        },
        {   .full = "abcd.efg.hij",
            .len  = 12,
            .rv   = 0,
            .goal = {
                .count = 3,
                .sections = {
                    { .data = "abcd", .len = 4 },
                    { .data = "efg",  .len = 3 },
                    { .data = "hij",  .len = 3 },
                    { .data = NULL,   .len = 0 },
                    { .data = NULL,   .len = 0 },
                },
            },
        },
        {   .full = "abcd.efg.hij.klm",
            .len  = 16,
            .rv   = 0,
            .goal = {
                .count = 4,
                .sections = {
                    { .data = "abcd", .len = 4 },
                    { .data = "efg",  .len = 3 },
                    { .data = "hij",  .len = 3 },
                    { .data = "klm",  .len = 3 },
                    { .data = NULL,   .len = 0 },
                },
            },
        },
        {   .full = "abcd.efg.hij.klm.op",
            .len  = 19,
            .rv   = 0,
            .goal = {
                .count = 5,
                .sections = {
                    { .data = "abcd", .len = 4 },
                    { .data = "efg",  .len = 3 },
                    { .data = "hij",  .len = 3 },
                    { .data = "klm",  .len = 3 },
                    { .data = "op",   .len = 2 },
                },
            },
        },
        {   .full = "abcd.efg..klm.op",
            .len  = 16,
            .rv   = 0,
            .goal = {
                .count = 5,
                .sections = {
                    { .data = "abcd", .len = 4 },
                    { .data = "efg",  .len = 3 },
                    { .data = "",     .len = 0 },
                    { .data = "klm",  .len = 3 },
                    { .data = "op",   .len = 2 },
                },
            },
        },
        {   .full = "....",
            .len  = 4,
            .rv   = 0,
            .goal = {
                .count = 5,
                .sections = {
                    { .data = "",     .len = 0 },
                    { .data = "",     .len = 0 },
                    { .data = "",     .len = 0 },
                    { .data = "",     .len = 0 },
                    { .data = "",     .len = 0 },
                },
            },
        },
        {   .full = "d....g",
            .len  = 6,
            .rv   = 0,
            .goal = {
                .count = 5,
                .sections = {
                    { .data = "d",    .len = 1 },
                    { .data = "",     .len = 0 },
                    { .data = "",     .len = 0 },
                    { .data = "",     .len = 0 },
                    { .data = "g",    .len = 1 },
                },
            },
        },
        {   .full = "dog.",
            .len  = 4,
            .rv   = 0,
            .goal = {
                .count = 2,
                .sections = {
                    { .data = "dog",  .len = 3 },
                    { .data = "",     .len = 0 },
                    { .data = "",     .len = 0 },
                    { .data = "",     .len = 0 },
                    { .data = "",     .len = 0 },
                },
            },
        },
    };

    for( size_t i = 0; i < sizeof(tests)/sizeof(struct test_vector); i++ ) {
        struct split_jwt got;
        int rv;

        rv = split( tests[i].full, tests[i].len, &got );

        CU_ASSERT( rv == tests[i].rv );
        if( 0 == tests[i].rv ) {
            CU_ASSERT_FATAL( got.count == tests[i].goal.count );

            for( size_t j = 0; j < got.count; j++ ) {
                CU_ASSERT( got.sections[j].len == tests[i].goal.sections[j].len );

                for( size_t k = 0; k < tests[i].goal.sections[j].len; k++ ) {
                    CU_ASSERT( got.sections[j].data[k] == tests[i].goal.sections[j].data[k] );
                }
            }
        }
    }
}


void add_suites( CU_pSuite *suite )
{
    *suite = CU_add_suite( "Utils tests", NULL, NULL );
    CU_add_test( *suite, "split() Tests", test_split );
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
