# SPDX-FileCopyrightText: 2016-2021 Comcast Cable Communications Management, LLC
# SPDX-License-Identifier: Apache-2.0

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-error=missing-field-initializers -W -g -fprofile-arcs -ftest-coverage -O0")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -W  -g -fprofile-arcs -ftest-coverage -O0")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage -O0")

if(NOT DISABLE_VALGRIND)
set (MEMORY_CHECK valgrind --leak-check=full --show-reachable=yes --error-exitcode=1 -v)
endif ()

find_package (Threads)

link_directories ( ${LIBRARY_DIR} )

add_test(NAME test_cjwt COMMAND ${MEMORY_CHECK} ./test_cjwt)
add_executable(test_cjwt test_cjwt.c ../src/cjwt.c)

target_link_libraries (test_cjwt ${CUNIT_LIBRARIES})
target_link_libraries (test_cjwt ${CJSON_LIBRARIES})
target_link_libraries (test_cjwt ${TROWER_LIBRARIES})
target_link_libraries (test_cjwt ${OPENSSL_LIBRARIES})
target_link_libraries (test_cjwt -lm)
target_link_libraries (test_cjwt gcov)
target_link_libraries (test_cjwt rt)
