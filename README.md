# cjwt

A C JWT Implementation

[![Build Status](https://github.com/xmidt-org/cjwt/workflows/CI/badge.svg)](https://github.com/xmidt-org/cjwt/actions)
[![codecov.io](http://codecov.io/github/xmidt-org/cjwt/coverage.svg?branch=main)](http://codecov.io/github/xmidt-org/cjwt?branch=main)
[![Coverity](https://img.shields.io/coverity/scan/11926.svg)]("https://scan.coverity.com/projects/comcast-cjwt)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=xmidt-org_cjwt&metric=alert_status)](https://sonarcloud.io/dashboard?id=xmidt-org_cjwt)
[![Language Grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/xmidt-org/cjwt.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/xmidt-org/cjwt/context:cpp)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/xmidt-org/cjwt/blob/main/LICENSE.txt)
[![GitHub release](https://img.shields.io/github/release/xmidt-org/cjwt.svg)](CHANGELOG.md)


# Building and Testing Instructions

```
mkdir build
cd build
cmake ..
make
make test
make coverage
firefox index.html
```

# Coding Formatter Settings

Please format pull requests using the following command to keep the style consistent.

```
astyle -A10 -S -f -U -p -D -c -xC90 -xL
```
