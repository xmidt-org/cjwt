#   Copyright 2010-2016 Comcast Cable Communications Management, LLC
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

cmake_minimum_required(VERSION 2.8.7)

project(cjwt)
include(ExternalProject)
include(CTest)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Werror -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Werror -Wall")

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
set(CMAKE_MACOSX_RPATH 1)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -undefined dynamic_lookup")
endif()

set(INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/_install)
set(PREFIX_DIR ${CMAKE_CURRENT_BINARY_DIR}/_prefix)
set(INCLUDE_DIR ${INSTALL_DIR}/include)
set(LIBRARY_DIR ${INSTALL_DIR}/lib${LIB_SUFFIX})
#set(LIBRARY_DIR ${INSTALL_DIR}/lib)
#set(LIBRARY_DIR64 ${INSTALL_DIR}/lib64)

include_directories(${INCLUDE_DIR}
                    ${INCLUDE_DIR}/cjson
                    ${INCLUDE_DIR}/trower-base64)
include_directories (SYSTEM /usr/include
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
                            /usr/local/opt/openssl/include
endif()
)
link_directories ( ${LIBRARY_DIR} )

if (NOT BUILD_YOCTO)

# base64 external dependency
ExternalProject_Add(trower-base64
    PREFIX ${PREFIX_DIR}/trower-base64
    GIT_REPOSITORY https://github.com/Comcast/trower-base64.git
    GIT_TAG "v1.1.2"
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR} -DBUILD_TESTING=OFF)
add_library(libtrower-base64 STATIC SHARED IMPORTED)
add_dependencies(libtrower-base64 trower-base64)

# cJSON external dependency
ExternalProject_Add(cJSON
    PREFIX ${PREFIX_DIR}/cJSON
    GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
    GIT_TAG "aafb64a1c549b7b927e339df6d35b1d5059dc235"
    CMAKE_ARGS += -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR} -DBUILD_TESTING=OFF
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    CMAKE_ARGS += -DCMAKE_MACOSX_RPATH=true
endif()
)
add_library(libcjson STATIC IMPORTED)
add_dependencies(libcjson cjson)

endif ()

add_subdirectory(src)

# Unit tests
if (BUILD_TESTING)
	add_subdirectory(tests)
endif (BUILD_TESTING)
