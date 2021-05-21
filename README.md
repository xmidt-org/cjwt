<!--
SPDX-FileCopyrightText: 2017-2021 Comcast Cable Communications Management, LLC
SPDX-License-Identifier: Apache-2.0
-->
# cjwt

A C JWT Implementation

[![Build Status](https://github.com/xmidt-org/cjwt/workflows/CI/badge.svg)](https://github.com/xmidt-org/cjwt/actions)
[![codecov.io](http://codecov.io/github/xmidt-org/cjwt/coverage.svg?branch=main)](http://codecov.io/github/xmidt-org/cjwt?branch=main)
[![Coverity](https://img.shields.io/coverity/scan/11926.svg)]("https://scan.coverity.com/projects/comcast-cjwt)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=xmidt-org_cjwt&metric=alert_status)](https://sonarcloud.io/dashboard?id=xmidt-org_cjwt)
[![Language Grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/xmidt-org/cjwt.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/xmidt-org/cjwt/context:cpp)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/xmidt-org/cjwt/blob/main/LICENSES/Apache-2.0.txt)
[![GitHub release](https://img.shields.io/github/release/xmidt-org/cjwt.svg)](CHANGELOG.md)

`cjwt` is a small JWT handler designed to allow consumers of JWTs of the JWS variant
the ability to securely and easily get claims and data from a JWT.  This particular
JWT implementation uses [cJSON](https://github.com/DaveGamble/cJSON) and is designed to support multiple different
crypto libraries in the future.

**If you haven't adopted `cjwt` yet, it's recommended to wait a bit to use the new 1.1.x API.**

### API

The API is meant to be fairly small & leverage what cJSON already provides nicely.

[Here are the details](https://github.com/xmidt-org/cjwt/blob/main/src/cjwt.h)

Basically there is a `cjwt_decode()` function that decodes successfully or fails
with a broad error code (in the 1.0.x releases) or with a more detailed reason
in the newer 1.1.x releases.

The other function is a `cjwt_destroy()` function.

Otherwise you get a simple to work with C struct.

### Dependencies

- [cJSON](https://github.com/DaveGamble/cJSON)
- [openssl](https://github.com/openssl/openssl)
- [trower-base64](https://github.com/xmidt-org/trower-base64)


## Opinionated Default Secure

To help adopters not make costly security mistakes, cjwt tries to default to
secure wherever possible.  If you **must** use an insecure feature there are
option flags that let you do so, but use them sparingly and with care.


# Building and Testing Instructions

```
mkdir build
cd build
cmake ..
make all test coverage
firefox index.html
```
