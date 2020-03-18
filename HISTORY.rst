=======
History
=======

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
