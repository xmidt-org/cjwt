/* SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC */
/* SPDX-License-Identifier: Apache-2.0 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CUnit/Basic.h>

#include "cjwt.h"

void test_print( void )
{
    cjwt_t jwt = {
        .header.alg = alg_rs512,
        .iss = (char*) "Issuer Claim",
        .sub = (char*) "Sub Claim",
        .jti = (char*) "JTI Claim",
        .aud.count = 2,
        .aud.names = (char*[2]) { "Aud Item", "foo" },
        .exp = (int64_t[1]) {   100 },
        .nbf = (int64_t[1]) {  2000 },
        .iat = (int64_t[1]) { 40000 },
        .private_claims = cJSON_CreateObject(),
    };

    /* This is generally a debugging tool & validating the output is
     * less of a priority than not crashing. */

    cjwt_print( stdout, NULL );

    cjwt_print( stdout, &jwt );

    cJSON_Delete( jwt.private_claims );
    memset( &jwt, 0, sizeof(cjwt_t) );

    cjwt_print( stdout, &jwt );
}


void add_suites( CU_pSuite *suite )
{
    *suite = CU_add_suite( "Print tests", NULL, NULL );
    CU_add_test( *suite, "cjwt_print() Tests", test_print );
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
