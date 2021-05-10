# SPDX-FileCopyrightText: 2016-2021 Comcast Cable Communications Management, LLC
# SPDX-License-Identifier: Apache-2.0

target_sources(cjwt
    PRIVATE
        cjwt.c
        b64.c
)

configure_file(cjwtver.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/cjwtver.h)

install (FILES
         ${CMAKE_CURRENT_BINARY_DIR}/cjwtver.h
         ${CMAKE_CURRENT_SOURCE_DIR}/cjwt.h
         DESTINATION include/cjwt)

set_target_properties(cjwt PROPERTIES
        OUTPUT_NAME cjwt)

install(TARGETS cjwt
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
       )

