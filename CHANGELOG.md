# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Valgrind checking and fixes.
- Algorithms that are unsupported now are not mapped to alg=none to prevent untrusted
  accidental acceptance of JWT.
- Removed the OPT_ALLOW_ANY_TIME option.
- Added a valid implementation for OPT_ALLOW_ALG_NONE and OPT_ALLOW_ALG_NONE_IGNORE_SIG.
- Only allow `alg_none` to be returned if an option is passed in.

### Changed
- Fixed memory leaks.
- Updated the CONTRIBUTION document.
- Updated the cjwt_decode() documentation to be accurate and consistent.
- Fixed the processing of the `aud` claim.
- Fixed the possibly of an unknown algorithm slipping by without being caught.
- Improved code documentation.
- Improved code coverage.
- Reduced many failure paths.
- Improved testing of return codes.
- Improved validation testing of returned JWT struct contents.
- Improved the order of validation to reduce possible errors/failures.

## [1.0.1]
### Added
- First stable release

[Unreleased]: https://github.com/xmidt-org/cjwt/compare/1.0.1...HEAD
[1.0.1]: https://github.com/xmidt-org/cjwt/compare/5d07465b61c7787e1ae8491c320a93cf3a1f531c...1.0.1
