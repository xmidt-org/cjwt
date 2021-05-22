# SPDX-FileCopyrightText: 2016-2021 Comcast Cable Communications Management, LLC
# SPDX-License-Identifier: Apache-2.0

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-error=missing-field-initializers -W -g -fprofile-arcs -ftest-coverage -O0")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -W  -g -fprofile-arcs -ftest-coverage -O0")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage -O0")

if(NOT DISABLE_VALGRIND)
set (MEMORY_CHECK valgrind --leak-check=full --show-reachable=yes --error-exitcode=1 -v)
endif ()

link_directories ( ${LIBRARY_DIR} )

add_test(NAME test_utils COMMAND ${MEMORY_CHECK} ./test_utils)
add_executable(test_utils test_utils.c ../src/utils.c)
target_link_libraries (test_utils ${CUNIT_LIBRARIES})



add_test(NAME test_cjwt COMMAND ${MEMORY_CHECK} ./test_cjwt)
add_executable(test_cjwt test_cjwt.c
                         ../src/cjwt.c
                         ../src/jws_evp_openssl.c
                         ../src/utils.c)

target_link_libraries (test_cjwt ${CUNIT_LIBRARIES}
                                 ${CJSON_LIBRARIES}
                                 ${TROWER_LIBRARIES}
                                 ${OPENSSL_LIBRARIES}
                                 -lm
                                 gcov
                                 rt)
add_test(NAME test_cjwt_new COMMAND ${MEMORY_CHECK} ./test_cjwt_new)
add_executable(test_cjwt_new test_cjwt_new.c
                         ../src/cjwt.c
                         ../src/jws_evp_openssl.c
                         ../src/utils.c)

target_link_libraries (test_cjwt_new ${CUNIT_LIBRARIES}
                                     ${CJSON_LIBRARIES}
                                     ${TROWER_LIBRARIES}
                                     ${OPENSSL_LIBRARIES}
                                     -lm
                                     gcov
                                     rt)
