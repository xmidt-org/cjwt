#   Copyright 2016-2021 Comcast Cable Communications Management, LLC
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
target_sources(cjwt
    PRIVATE
        cjwt.c
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

