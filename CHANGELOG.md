<!--
SPDX-FileCopyrightText: 2017-2021 Comcast Cable Communications Management, LLC
SPDX-License-Identifier: Apache-2.0
-->
# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v2.3.0]
- Fix for CVE-2024-54150: https://github.com/xmidt-org/cjwt/commit/096ab3e37f73c914b716e7259589179f363265fd
- When using HSxxx signing types, the new option `OPT_ALLOW_ONLY_HS_ALG` is required.
  This ensures that public/private keys can't be mistakenly accepted as symmetric
  algorithem ciphers.

## [v2.2.1]
- Bump the version to trigger a full release.

## [v2.2.0]
- Add support for openssl v3 as well as v1 APIs.
- Add support for private jwt headers and the `kid` standard header.
- Require meson 0.60.3 or newer.

## [v2.1.1]
- Fix a few compiler warnings in the example code.

## [v2.1.0]
- Add string to alg type mapping function.
- Allow use of `num_algorithms`.

## [v2.0.1]
- Upgrade the build system to use meson.
- Improve the CI pipeline.

## [v2.0.0]
- Update the interface to not use strlen() for lengths but expect them to be
  passed in.  This reduces the likelihood of this library being exploited by
  a long string.
- Add the cjwt_printf() function to the interface.
- Remove the alg mapping function that was mistakenly provided in the 1.x.x API.
- Add a few worked examples.

## [v1.0.4]
- Move to use internal base64 decoding with stricter processing rules
- Major refactor to use a specified length and not '\0' terminated strings internally.
- A number of failures that may not have been detected now have tests and are covered.
- Bridge the new implementation to use the existing API.

## [v1.0.3]
- Move to use Github Actions for building
- Improve the cmake files to support the new build system better
- Bump to a known new version

## [1.0.2]

It is unclear what is exactly in 1.0.0 through 1.0.2.

### Added
- Valgrind checking and fixes.
- Algorithms that are unsupported now are not mapped to alg=none to prevent untrusted
  accidental acceptance of JWT.

### Changed
- Fixed memory leaks.
- Updated the CONTRIBUTION document.
- Updated the cjwt_decode() documentation to be accurate and consistent.

## [1.0.1]
### Added
- First stable release

[Unreleased]: https://github.com/xmidt-org/cjwt/compare/v2.2.1...HEAD
[v2.2.1]: https://github.com/xmidt-org/cjwt/compare/v2.2.1...v2.2.0
[v2.2.0]: https://github.com/xmidt-org/cjwt/compare/v2.2.0...v2.1.1
[v2.1.1]: https://github.com/xmidt-org/cjwt/compare/v2.1.1...v2.1.0
[v2.1.0]: https://github.com/xmidt-org/cjwt/compare/v2.0.1...v2.1.0
[v2.0.1]: https://github.com/xmidt-org/cjwt/compare/v2.0.0...v2.0.1
[v2.0.0]: https://github.com/xmidt-org/cjwt/compare/v1.0.4...v2.0.0
[v1.0.4]: https://github.com/xmidt-org/cjwt/compare/v1.0.3...v1.0.4
[v1.0.3]: https://github.com/xmidt-org/cjwt/compare/1.0.2...v1.0.3
[1.0.2]: https://github.com/xmidt-org/cjwt/compare/1.0.1...1.0.2
[1.0.1]: https://github.com/xmidt-org/cjwt/compare/5d07465b61c7787e1ae8491c320a93cf3a1f531c...1.0.1
