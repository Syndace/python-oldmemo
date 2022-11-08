[![PyPI](https://img.shields.io/pypi/v/Twomemo.svg)](https://pypi.org/project/Twomemo/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/Twomemo.svg)](https://pypi.org/project/Twomemo/)
[![Build Status](https://github.com/Syndace/python-twomemo/actions/workflows/test-and-publish.yml/badge.svg)](https://github.com/Syndace/python-twomemo/actions/workflows/test-and-publish.yml)
[![Documentation Status](https://readthedocs.org/projects/python-twomemo/badge/?version=latest)](https://python-twomemo.readthedocs.io/)

# python-twomemo #

Backend implementation for [python-omemo](https://github.com/Syndace/python-omemo), equipping python-omemo with support for OMEMO under the namespace `urn:xmpp:omemo:2` (casually/jokingly referred to as "twomemo").

## Installation ##

Install the latest release using pip (`pip install twomemo`) or manually from source by running `pip install .` in the cloned repository.

## Protobuf ##

Install `protoc`. Then, in the root directory of this repository, run:

```sh
$ pip install protobuf mypy mypy-protobuf types-protobuf
$ protoc --python_out=twomemo/ --mypy_out=twomemo/ twomemo.proto
```

This will generate `twomemo/twomemo_pb2.py` and `twomemo/twomemo_pb2.pyi`.

## Type Checks and Linting ##

python-twomemo uses [mypy](http://mypy-lang.org/) for static type checks and both [pylint](https://pylint.pycqa.org/en/latest/) and [Flake8](https://flake8.pycqa.org/en/latest/) for linting. All checks can be run locally with the following commands:

```sh
$ pip install --upgrade mypy pylint flake8 mypy-protobuf types-protobuf
$ mypy --strict twomemo/ setup.py
$ pylint twomemo/ setup.py
$ flake8 twomemo/ setup.py
```

## Getting Started ##

Refer to the documentation on [readthedocs.io](https://python-twomemo.readthedocs.io/), or build/view it locally in the `docs/` directory. To build the docs locally, install the requirements listed in `docs/requirements.txt`, e.g. using `pip install -r docs/requirements.txt`, and then run `make html` from within the `docs/` directory. The documentation can then be found in `docs/_build/html/`.
