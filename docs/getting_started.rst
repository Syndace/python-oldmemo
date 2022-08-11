Getting Started
===============

No further preparation is required to get started with this backend. Create an instance of :class:`~oldmemo.oldmemo.Oldmemo` and pass it to `python-omemo <https://github.com/Syndace/python-omemo>`__ to equip it with ``eu.siacs.conversations.axolotl`` capabilities.

Users of ElementTree can use the helpers in :ref:`etree` for their XML serialization/parsing, which is available after installing `xmlschema <https://pypi.org/project/xmlschema/>`_, or by using ``pip install oldmemo[xml]``. Users of a different XML framework can use the module as a reference to write their own serialization/parsing.
