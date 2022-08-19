Migration from Legacy
=====================

This backend supports migration of legacy data from ``python-omemo<1.0.0`` + ``python-omemo-backend-signal`` setups. Other legacy setups cannot be migrated by this package.

To migrate legacy data, first implement the :class:`oldmemo.migrations.LegacyStorage` interface. This interface is very similar to the ``Storage`` class of legacy ``python-omemo`` and differs from it mostly in the lack of methods to store data and the addition of methods to delete data. You should be able to reuse most of your code.

With the :class:`~oldmemo.migrations.LegacyStorage` set up, call the :func:`oldmemo.migrations.migrate` function with both the legacy storage and the new storage to perform the migration of the legacy data. You can call this function as part of your general ``python-omemo`` setup routine, the function checks whether migrations are required itself and returns instantly if not.

See the module documentation of :mod:`oldmemo.migrations` for details.
