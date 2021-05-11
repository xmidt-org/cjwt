// SPDX-FileCopyrightText: 2017-2021 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <CUnit/Basic.h>

#include <cjson/cJSON.h>
#include "../src/cjwt.h"

typedef struct {
    int expected;
    const char *jwt_file_name;
    bool is_key_in_file;
    const char *key;
    unsigned int options;
    const char *decode_test_name;
} test_case_t;

test_case_t test_list[] = {
    {       0, "jwtn.txt",          false, "", OPT_ALLOW_ALG_NONE, "No Alg claims on on"       },
    {       0, "jwtnx.txt",         false, "", OPT_ALLOW_ALG_NONE, "No Alg claims off on"      },
    {       0, "jwtny.txt",         false, "", OPT_ALLOW_ALG_NONE, "No Alg claims off off"     },
    { ENOTSUP, "jwtn.txt",          false, "",                  0, "No Alg claims on on"       },
    { ENOTSUP, "jwtnx.txt",         false, "",                  0, "No Alg claims off on"      },
    { ENOTSUP, "jwtny.txt",         false, "",                  0, "No Alg claims off off"     },
    {  EINVAL, "jwtia.txt",         false, "test_passwd1",      0, "HS256 invalid jwt"         },
    {  EINVAL, "jwtib.txt",         false, "test_passwd1",      0, "HS256 invalid jwt"         },
    {  EINVAL, "jwtic.txt",         false, "test_passwd1",      0, "HS256 invalid jwt"         },
    {  EINVAL, "jwtid.txt",         false, "test_passwd1",      0, "HS256 invalid jwt"         },
    {  EINVAL, "jwtie.txt",         false, "test_passwd1",      0, "HS256 invalid jwt"         },
    {  EINVAL, "jwtif.txt",         false, "test_passwd1",      0, "HS256 invalid jwt"         },
    {       0, "jwt1.txt",          false, "test_passwd1",      0, "HS256 claims on on"        },
    {  EINVAL, "jwt1.txt",          false, "test_passbad",      0, "HS256 claims on on"        },
    {       0, "jwt2.txt",          false, "test_passwd2",      0, "HS384 claims on on"        },
    {  EINVAL, "jwt2.txt",          false, "test_passbad",      0, "HS384 claims on on"        },
    {       0, "jwt3.txt",          false, "test_passwd3",      0, "HS512 claims on on"        },
    {  EINVAL, "jwt3.txt",          false, "test_passbad",      0, "HS512 claims on on"        },
    {       0, "jwt5.txt",          true,  "pubkey5.pem",       0, "RS384 claims on on"        },
    {  EINVAL, "jwt5.txt",          true,  "badkey4.pem",       0, "RS384 claims on on"        },
    {       0, "jwt4.txt",          true,  "pubkey4.pem",       0, "RS256 claims on on"        },
    {  EINVAL, "jwt4.txt",          true,  "badkey4.pem",       0, "RS256 claims on on"        },
    {       0, "jwt6.txt",          true,  "pubkey6.pem",       0, "RS512 claims on on"        },
    {  EINVAL, "jwt6.txt",          true,  "badkey6.pem",       0, "RS512 claims on on"        },
    {       0, "jwt1x.txt",         false, "test_passwd1",      0, "HS256 claims off on"       },
    {  EINVAL, "jwt1x.txt",         false, "test_prasswd1",     0, "HS256 claims off on"       },
    {       0, "jwt2x.txt",         false, "test_passwd2",      0, "HS384 claims off on"       },
    {  EINVAL, "jwt2x.txt",         false, "twest_passwd2",     0, "HS384 claims off on"       },
    {       0, "jwt3x.txt",         false, "test_passwd3",      0, "HS512 claims off on"       },
    {  EINVAL, "jwt3x.txt",         false, "test_passwd3...",   0, "HS512 claims off on"       },
    {       0, "jwt4x.txt",         true,  "pubkey4.pem",       0, "RS256 claims off on"       },
    {  EINVAL, "jwt4x.txt",         true,  "pubkey5.pem",       0, "RS256 claims off on"       },
    {       0, "jwt5x.txt",         true,  "pubkey5.pem",       0, "RS384 claims off on"       },
    {  EINVAL, "jwt5x.txt",         true,  "badkey5.pem",       0, "RS384 claims off on"       },
    {       0, "jwt6x.txt",         true,  "pubkey6.pem",       0, "RS512 claims off on"       },
    {  EINVAL, "jwt6x.txt",         true,  "badkey6.pem",       0, "RS512 claims off on"       },
    {       0, "jwt1y.txt",         false, "test_passwd1",      0, "HS256 claims off off"      },
    {  EINVAL, "jwt1y.txt",         false, "tast_passwd1",      0, "HS256 claims off off"      },
    {       0, "jwt2y.txt",         false, "test_passwd2",      0, "HS384 claims off off"      },
    {  EINVAL, "jwt2y.txt",         false, "test..passwd2",     0, "HS384 claims off off"      },
    {       0, "jwt3y.txt",         false, "test_passwd3",      0, "HS512 claims off off"      },
    {  EINVAL, "jwt3y.txt",         false, "tteesstt_passwd3",  0, "HS512 claims off off"      },
    {       0, "jwt4y.txt",         true,  "pubkey4.pem",       0, "RS256 claims off off"      },
    {  EINVAL, "jwt4y.txt",         true,  "badkey4.pem",       0, "RS256 claims off off"      },
    {       0, "jwt5y.txt",         true,  "pubkey5.pem",       0, "RS384 claims off off"      },
    {  EINVAL, "jwt5y.txt",         true,  "pubkey6.pem",       0, "RS384 claims off off"      },
    {       0, "jwt6y.txt",         true,  "pubkey6.pem",       0, "RS512 claims off off"      },
    {  EINVAL, "jwt6y.txt",         true,  "pubkey5.pem",       0, "RS512 claims off off"      },
    {       0, "jwt1l.txt",         false, "test_passwd1",      0, "HS256 claims long"         },
    {  EINVAL, "jwt1l.txt",         false, "test_keyword1",     0, "HS256 claims long"         },
    {       0, "jwt2l.txt",         false, "test_passwd2",      0, "HS384 claims long"         },
    {  EINVAL, "jwt2l.txt",         false, "test_passwd1",      0, "HS384 claims long"         },
    {       0, "jwt3l.txt",         false, "test_passwd3",      0, "HS512 claims long"         },
    {  EINVAL, "jwt3l.txt",         false, "passwd3",           0, "HS512 claims long"         },
    {       0, "jwt4l.txt",         true,  "pubkey4.pem",       0, "RS256 claims long"         },
    {  EINVAL, "jwt4l.txt",         true,  "badkey4.pem",       0, "RS256 claims long"         },
    {       0, "jwt5l.txt",         true,  "pubkey5.pem",       0, "RS384 claims long"         },
    {  EINVAL, "jwt5l.txt",         true,  "badkey5.pem",       0, "RS384 claims long"         },
    {       0, "jwt6l.txt",         true,  "pubkey6.pem",       0, "RS512 claims long"         },
    {  EINVAL, "jwt6l.txt",         true,  "badkey6.pem",       0, "RS512 claims long"         },
    {       0, "jwt2.txt",          false, "test_passwd2",      0, "HS384 claims on on"        },
    {       0, "jwt3.txt",          false, "test_passwd3",      0, "HS512 claims on on"        },
    {       0, "jwt8_hs256.txt",    true,  "key8_hs256.pem",    0, "HS256 claims on on"        },
    {       0, "jwt9_hs384.txt",    true,  "key9_hs384.pem",    0, "HS384 claims on on"        },
    {       0, "jwt10_hs512.txt",   true,  "key10_hs512.pem",   0, "HS512 claims on on"        },
    {  EINVAL, "jwt11.txt",         false, "incorrect_key",     0, "RS256 claims all"          },
    {  EINVAL, "jwt12.txt",         false, "incorrect_key",     0, "RS256 claims all"          },
	{  EINVAL, "jwt13.txt",         false, "incorrect_key",     0, "RS256 claims all"          },
	{ ENOTSUP, "jwtbadalg.txt",     false, "incorrect_key",     0, "Invalid/unsupported alg."  }
};

#define _NUM_TEST_CASES ( sizeof(test_list) / sizeof(test_case_t) )

int open_input_file( const char *fname )
{
    char cwd[1024];

    if( getcwd( cwd, sizeof( cwd ) ) != NULL ) {
        strcat( cwd, "/../../tests/inputs/" );
    } else {
        perror( "getcwd() error" );
		return -1;
    }

	if( (fname==NULL) || ((strlen(cwd) + strlen(fname))>sizeof(cwd)))
	{
		perror( "file name too long error" );
		return -1;
    }	
	strcat( cwd, fname );	
    int fd = open( cwd, O_RDONLY );

    if( fd < 0 ) {
        printf( "File %s open error\n", fname );
    }

    return fd;
}

ssize_t read_file( const char *fname, char *buf, size_t buflen )
{
    ssize_t nbytes = 0;
    int fd = open_input_file( fname );

    if( fd < 0 ) {
        return fd;
    }

    nbytes = read( fd, buf, buflen );

    if( nbytes < 0 ) {
        printf( "Read file %s error\n", fname );
        close( fd );
        return nbytes;
    }

    close( fd );
    return nbytes;
}

static unsigned int pass_cnt = 0;
static unsigned int fail_cnt = 0;

void test_case (unsigned _i )
{
    const char *jwt_fname;
    const char *key_str;
    const char *decode_test_name;
    int expected;
    int key_len;
    ssize_t jwt_bytes;
    int result = 0;
    cjwt_t *jwt = NULL;
    char jwt_buf[65535];
    char pem_buf[8192];
    jwt_fname = test_list[_i].jwt_file_name;
    key_str = test_list[_i].key;
    key_len = strlen( key_str );
    expected = test_list[_i].expected;
    decode_test_name = test_list[_i].decode_test_name;

    if( key_len == 0 ) {
        key_str = NULL;
    } else if( test_list[_i].is_key_in_file ) {
        key_len = read_file( key_str, pem_buf, sizeof( pem_buf ) );

        if( key_len >= 0 ) {
            key_str = ( const char * ) pem_buf;
        } else {
            printf( "Error reading pem file\n" );
            CU_ASSERT ( 0 == 1 );
            fail_cnt += 1;
            return;
        }
    }

    if( expected ) {
        printf( "\n--- Test %s expected good\n", decode_test_name );
    } else {
        printf( "\n--- Test %s expected bad\n", decode_test_name );
    }
    printf ("key in file %d, keylen = %d\n", test_list[_i].is_key_in_file,
        key_len);

    memset( jwt_buf, 0, sizeof(jwt_buf) );
    printf( "--- Input jwt : %s \n", jwt_fname );
    jwt_bytes = read_file( jwt_fname, jwt_buf, sizeof( jwt_buf ) );

    if( jwt_bytes > 0 ) {
        result = cjwt_decode( jwt_buf, jwt_bytes, test_list[_i].options, &jwt, ( const uint8_t * )key_str, key_len );
    } else {
        result = jwt_bytes;
    }

    if( expected == result ) {
        printf( "--- PASSED: %s\n", decode_test_name );
        pass_cnt += 1;
    } else {
        printf( "\e[01;31m--- FAILED: %s (%d != %d)\e[00m\n", decode_test_name, expected, result );
        fail_cnt += 1;
    }

    cjwt_destroy( jwt );
    CU_ASSERT ( expected == result );
}


void test_cjwt (void)
{
  unsigned i;
  for (i=0; i<_NUM_TEST_CASES; i++)
    test_case (i);
}


void add_suites( CU_pSuite *suite )
{
    printf ("--------Start of Test Cases Execution ---------\n");
    *suite = CU_add_suite( "tests", NULL, NULL );
    CU_add_test( *suite, "Test cjwt", test_cjwt );
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
            printf ( "\n" );
            CU_basic_show_failures( CU_get_failure_list() );
            printf ( "\n\n" );
            rv = CU_get_number_of_tests_failed();
        }

        CU_cleanup_registry();

    }

    return rv;
}


