[![PyPI](https://img.shields.io/pypi/v/Oldmemo.svg)](https://pypi.org/project/Oldmemo/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/Oldmemo.svg)](https://pypi.org/project/Oldmemo/)
[![Build Status](https://github.com/Syndace/python-oldmemo/actions/workflows/test-on-push.yml/badge.svg)](https://github.com/Syndace/python-oldmemo/actions/workflows/test-on-push.yml)
[![Documentation Status](https://readthedocs.org/projects/python-oldmemo/badge/?version=latest)](https://python-oldmemo.readthedocs.io/)

# python-oldmemo #

Backend implementation for [python-omemo](https://github.com/Syndace/python-omemo), equipping python-omemo with support for OMEMO under the namespace `eu.siacs.conversations.axolotl` (casually/jokingly referred to as "oldmemo").

This repository is based on [python-twomemo](https://github.com/Syndace/python-twomemo) and will be rebased on top of new commits to that repository regularly, so expect commit hashes to be unstable. For the same reason, releases will not be tagged.

## Installation ##

python-oldmemo depends on two system libraries, [libxeddsa](https://github.com/Syndace/libxeddsa)>=2,<3 and [libsodium](https://download.libsodium.org/doc/).

Install the latest release using pip (`pip install oldmemo`) or manually from source by running `pip install .` (recommended) or `python setup.py install` in the cloned repository. The installation requires libsodium and the Python development headers to be installed. If a locally installed version of libxeddsa is available, [python-xeddsa](https://github.com/Syndace/python-xeddsa) (a dependency of [python-x3dh](https://github.com/Syndace/python-x3dh)) tries to use that. Otherwise it uses prebuilt binaries of the library, which are available for Linux, MacOS and Windows for the amd64 architecture, and potentially for MacOS arm64 too. Set the `LIBXEDDSA_FORCE_LOCAL` environment variable to forbid the usage of prebuilt binaries.

## Protobuf ##

Install `protoc`. Then, in the root directory of this repository, run:

```sh
$ pip install protobuf mypy mypy-protobuf types-protobuf
$ protoc --python_out=oldmemo/ --mypy_out=oldmemo/ oldmemo.proto
```

This will generate `oldmemo/oldmemo_pb2.py` and `oldmemo/oldmemo_pb2.pyi`.

## Type Checks and Linting ##

python-oldmemo uses [mypy](http://mypy-lang.org/) for static type checks and both [pylint](https://pylint.pycqa.org/en/latest/) and [Flake8](https://flake8.pycqa.org/en/latest/) for linting. All checks can be run locally with the following commands:

```sh
$ pip install --upgrade mypy pylint flake8 mypy-protobuf types-protobuf
$ mypy --strict oldmemo/ setup.py
$ pylint oldmemo/ setup.py
$ flake8 oldmemo/ setup.py
```

## Getting Started ##

Refer to the documentation on [readthedocs.io](https://python-oldmemo.readthedocs.io/), or build/view it locally in the `docs/` directory. To build the docs locally, install the requirements listed in `docs/requirements.txt`, e.g. using `pip install -r docs/requirements.txt`, and then run `make html` from within the `docs/` directory. The documentation can then be found in `docs/_build/html/`.
