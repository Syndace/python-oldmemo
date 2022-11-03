# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 3rd of November 2022

### Added
- Python 3.11 to the list of supported versions

### Changed
- Replaced usages of the walrus operator to correctly support Python 3.7 and 3.8 as advertized
- Fixed a bug in the way the authentication tag was calculated during decryption of the AEAD implementation

## [1.0.0] - 1st of November 2022

### Added
- Initial release.

[Unreleased]: https://github.com/Syndace/python-twomemo/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/Syndace/python-twomemo/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Syndace/python-twomemo/releases/tag/v1.0.0
