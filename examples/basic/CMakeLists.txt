# SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
# SPDX-License-Identifier: Apache-2.0

add_executable(hs_example hs_example.c)

target_link_libraries (hs_example cjwt)
target_link_libraries (hs_example ${CJSON_LIBRARIES})
target_link_libraries (hs_example ${TROWER_LIBRARIES})
target_link_libraries (hs_example ${OPENSSL_LIBRARIES})



add_executable(rs_example rs_example.c)

target_link_libraries (rs_example cjwt)
target_link_libraries (rs_example ${CJSON_LIBRARIES})
target_link_libraries (rs_example ${TROWER_LIBRARIES})
target_link_libraries (rs_example ${OPENSSL_LIBRARIES})



add_executable(es_example es_example.c)

target_link_libraries (es_example cjwt)
target_link_libraries (es_example ${CJSON_LIBRARIES})
target_link_libraries (es_example ${TROWER_LIBRARIES})
target_link_libraries (es_example ${OPENSSL_LIBRARIES})
