# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.3] - 8th of November 2022

### Changed
- Exclude tests from the packages

## [1.0.2] - 4th of November 2022

### Changed
- Increased the minimum version of protobuf to 3.20.3 after reports that earlier versions cause issues
- Disabled protobuf's deterministic serialization in an attempt to achieve PyPy3 compatibility

## [1.0.1] - 3rd of November 2022

### Added
- Python 3.11 to the list of supported versions

### Changed
- Replaced usages of the walrus operator to correctly support Python 3.7 and 3.8 as advertized
- Fixed a bug in the way the authentication tag was calculated during decryption of the AEAD implementation

## [1.0.0] - 1st of November 2022

### Added
- Initial release.

[Unreleased]: https://github.com/Syndace/python-twomemo/compare/v1.0.3...HEAD
[1.0.3]: https://github.com/Syndace/python-twomemo/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Syndace/python-twomemo/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Syndace/python-twomemo/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Syndace/python-twomemo/releases/tag/v1.0.0
