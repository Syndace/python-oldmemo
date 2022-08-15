[![PyPI](https://img.shields.io/pypi/v/Twomemo.svg)](https://pypi.org/project/Twomemo/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/Twomemo.svg)](https://pypi.org/project/Twomemo/)
[![Build Status](https://travis-ci.org/Syndace/python-twomemo.svg?branch=main)](https://travis-ci.org/Syndace/python-twomemo)
[![Documentation Status](https://readthedocs.org/projects/python-twomemo/badge/?version=latest)](https://python-twomemo.readthedocs.io/en/latest/?badge=latest)

# python-twomemo #

Backend implementation for [python-omemo](https://github.com/Syndace/python-omemo), equipping python-omemo with support for OMEMO under the namespace `urn:xmpp:omemo:2` (casually/jokingly referred to as "twomemo").

## Installation ##

python-twomemo depends on two system libraries, [libxeddsa](https://github.com/Syndace/libxeddsa)>=2,<3 and [libsodium](https://download.libsodium.org/doc/).

Install the latest release using pip (`pip install twomemo`) or manually from source by running `pip install .` (recommended) or `python setup.py install` in the cloned repository. The installation requires libsodium and the Python development headers to be installed. If a locally installed version of libxeddsa is available, [python-xeddsa](https://github.com/Syndace/python-xeddsa) (a dependency of [python-x3dh](https://github.com/Syndace/python-x3dh)) tries to use that. Otherwise it uses prebuilt binaries of the library, which are available for Linux, MacOS and Windows for the amd64 architecture, and potentially for MacOS arm64 too. Set the `LIBXEDDSA_FORCE_LOCAL` environment variable to forbid the usage of prebuilt binaries.

## Protobuf ##

Install `protoc`. Then, in the root directory of this repository, run:

```sh
$ pip install protobuf mypy mypy-protobuf types-protobuf
$ protoc --python_out=twomemo/ --mypy_out=twomemo/ twomemo.proto
```

This will generate `twomemo/twomemo_pb2.py` and `twomemo/twomemo_pb2.pyi`.

## Testing, Type Checks and Linting ##

python-twomemo uses [pytest](https://docs.pytest.org/en/latest/) as its testing framework, [mypy](http://mypy-lang.org/) for static type checks and both [pylint](https://pylint.pycqa.org/en/latest/) and [Flake8](https://flake8.pycqa.org/en/latest/) for linting. All tests/checks can be run locally with the following commands:

```sh
$ pip install --upgrade pytest pytest-asyncio mypy pylint flake8 mypy-protobuf types-protobuf
$ mypy --strict twomemo/ setup.py tests/
$ pylint twomemo/ setup.py tests/
$ flake8 twomemo/ setup.py tests/
$ pytest
```

## Getting Started ##

Refer to the documentation on [readthedocs.io](https://python-twomemo.readthedocs.io/en/latest/), or build/view it locally in the `docs/` directory. To build the docs locally, install the requirements listed in `docs/requirements.txt`, e.g. using `pip install -r docs/requirements.txt`, and then run `make html` from within the `docs/` directory. The documentation can then be found in `docs/_build/html/`.
