# Copyright 2016 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-error=missing-field-initializers -W -g -fprofile-arcs -ftest-coverage -O0")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -W  -g -fprofile-arcs -ftest-coverage -O0")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage -O0")

find_package (Threads)

link_directories ( ${LIBRARY_DIR} )

add_test(NAME cjwt_test COMMAND cjwt_test WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/.. )
add_executable(cjwt_test cjwt_test.c ../src/cjwt.c)

target_link_libraries (cjwt_test gcov -lssl -lcrypto -lpthread -ltrower-base64 -lcjson -lcheck -lrt -lm)
			
