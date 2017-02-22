/**
 * Copyright 2017 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <stdio.h>

#include "cjwt.h"

void cjwt_test_HS256()
{
    printf( "\n\n======================================================\n\n" );
    printf( "Testcase : cjwt_test_HS256\n" );
    printf( "------------------------------------------------------\n\n" );
    const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3Mi"
                         "OiJmaWxlcy5jeXBocmUuY29tIiwic3ViIjoidXNlcjAif"
                         "Q.dLFbrHVViu1e3VD1yeCd9aaLNed-bfXhSsF0Gh56fBg";
    unsigned char key256[32] = "012345678901234567890123456789XY";
    int key_len = sizeof( key256 );
    cjwt_t *jwt = NULL;
    int result = cjwt_decode( token, 0, &jwt,
                              key256, key_len );
    result = cjwt_destroy( &jwt );
    printf( "\n------------------------------------------------------\n" );
    printf( "Result : %s\n", result ? "Failed" : "Passed" );
    printf( "======================================================\n\n" );
    return;
}

void cjwt_test_HS384()
{
    printf( "\n\n======================================================\n\n" );
    printf( "Testcase : cjwt_test_HS384\n" );
    printf( "------------------------------------------------------\n\n" );
    const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9."
                         "eyJpc3MiOiJmaWxlcy5jeXBocmUuY29tIiwic"
                         "3ViIjoidXNlcjAifQ.xqea3OVgPEMxsCgyikr"
                         "R3gGv4H2yqMyXMm7xhOlQWpA-NpT6n2a1d7TD"
                         "GgU6LOe4";
    const unsigned char key384[48] = "aaaabbbbccccddddeeeeffffg"
                                     "ggghhhhiiiijjjjkkkkllll";
    int key_len = sizeof( key384 );
    cjwt_t *jwt  = NULL;
    int result = cjwt_decode( token, 0, &jwt,
                              key384, key_len );
    result = cjwt_destroy( &jwt );
    printf( "\n------------------------------------------------------\n" );
    printf( "Result : %s\n", result ? "Failed" : "Passed" );
    printf( "======================================================\n\n" );
    return;
}

void cjwt_test_HS512()
{
    printf( "\n\n======================================================\n\n" );
    printf( "Testcase : cjwt_test_HS512\n" );
    printf( "------------------------------------------------------\n\n" );
    const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3Mi"
                         "OiJmaWxlcy5jeXBocmUuY29tIiwic3ViIjoidXNlcjAif"
                         "Q.u-4XQB1xlYV8SgAnKBof8fOWOtfyNtc1ytTlc_vHo0U"
                         "lh5uGT238te6kSacnVzBbC6qwzVMT1806oa1Y8_8EOg";
    unsigned char key512[64] = "012345678901234567890123456789XY"
                               "012345678901234567890123456789XY";
    int key_len = sizeof( key512 );
    cjwt_t *jwt = NULL;
    int result = cjwt_decode( token, 0, &jwt,
                              key512, key_len );
    result = cjwt_destroy( &jwt );
    printf( "\n------------------------------------------------------\n" );
    printf( "Result : %s\n", result ? "Failed" : "Passed" );
    printf( "======================================================\n\n" );
    return;
}

int main( int argc, char *argv[] )
{
    cjwt_test_HS256();
	cjwt_test_HS384();
	cjwt_test_HS512();
    return 0;
}
