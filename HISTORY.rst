=======
History
=======

1.1.1 (2023-01-16)
-------------------

* Move operations succeed, when a language header is set.

1.1.0 (2022-11-29)
-------------------

* Adjust objectType return value of ``users/self`` to latest UCS erratum.

1.0.13 (2022-11-09)
-------------------

* Fix error handling in base_http.py.

1.0.12 (2022-11-02)
-------------------

* Add the possibility to send an Accept-Language header with each request.

1.0.11 (2022-10-19)
-------------------

* Handle UDM REST API doing immediate moves (without redirects) for objects without subordinates.

1.0.10 (2022-10-13)
-------------------

* Pass trough UDM REST API error in ``CreateError`` and ``ModifyError`` exceptions.

1.0.9 (2022-09-15)
------------------

* Format the correlation ID as a hex value.

1.0.8 (2022-09-11)
------------------

* Send a correlation ID with each request.
* Raise version of generated client library ``openapi-client-udm`` to ``1.0.1``.

1.0.7 (2022-01-18)
------------------

* Lower required version of ``click`` library, for compatibility with ``typer<0.4.0``.

1.0.6 (2022-01-05)
------------------

* UCS 5.0 container for testing is now run using LXD.
* Fix deprecated use of ``ruamel.yaml`` in tests.

1.0.5 (2021-12-09)
------------------

* Add process wide cache for the LDAP base of each host.

1.0.4 (2021-11-15)
------------------

* Update `aiohttp <https://github.com/aio-libs/aiohttp>`_ to (at least) Version ``3.8.1``, which fixes `aiohttp not honoring "no_proxy" <https://github.com/aio-libs/aiohttp/issues/4431>`_.
* Update development and testing dependencies.

1.0.3 (2021-03-25)
------------------

* Fix handling of values that are lists of dicts (e.g. ``dnsEntryZoneAlias`` of computer objects).

1.0.2 (2021-03-25)
------------------

* Fix not sending policy modifications to server.

1.0.1 (2021-02-10)
------------------

* The script to create/update the OpenAPI client ``update_openapi_client`` has been updated to use the OpenAPI Generator version ``5.0.0``.
* The ``update_openapi_client`` script now verifies the checksum of the downloaded JAR file.

1.0.0 (2021-02-03)
------------------

* **Breaking API CHANGE**: The ``options`` attribute of UDM objects is now a dictionary. It mirrors the UDM REST APIs ``options`` attribute value. Before it was a list, which did not allow to disable default options (Bug #50974).

0.4.0 (2020-04-06)
------------------

* Add the possibility to provide credentials in the update_openapi_client script to download the schema file.

0.3.1 (2020-03-19)
------------------

* Update download URL of openapi-generator jar.

0.3.0 (2020-03-18)
------------------

* allow setting properties that only exist after enabling an option (`Bug #50972 <http://forge.univention.org/bugzilla/show_bug.cgi?id=50972>`_)

0.2.1 (2019-12-14)
------------------

* fix not detecting changes in mutable property values

0.2.0 (2019-12-10)
------------------

* ``Mapping`` and ``Iterable`` interfaces were added to the object properties class. Adds item access (``obj.props["key"]``), ``obj.props.get("key")``, ``len(obj.props)``, ``key in obj.props``, ``obj.props.keys()``, ``obj.props.values()``, ``obj.props.items()``
* documentation improvements
* HTTP basic passwords are no longer logged
* map ``options`` and ``policies`` back to original values (were being rewritten to pep8 conform keys by the OpenAPI client)

0.1.1 (2019-11-25)
------------------

* allow specifying existing JAR for open api client build
* various small fixes to handle RTD and Travis-CI

0.1.0 (2019-11-22)
------------------

* First release.
