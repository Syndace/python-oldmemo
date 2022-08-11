from .version import __version__
from .project import project

from .oldmemo import Oldmemo

# Fun:
# https://github.com/PyCQA/pylint/issues/6006
# https://github.com/python/mypy/issues/10198
__all__ = [  # pylint: disable=unused-variable
    # .version
    "__version__",

    # .project
    "project",

    # .oldmemo
    "Oldmemo"
]
