======================
Python UDM REST Client
======================

|python| |license| |code style|

Python library to interact with the Univention `UDM REST API`_, implements the interface o the `Python UDM API`_.

* Free software: GNU Affero General Public License version 3
* Documentation: https://udm-rest-client.readthedocs.io.


Features
--------

* Asynchronous
* Automatic handling of HTTP(S) sessions
* Type annotations
* 100% test coverage (unittests + integration tests)
* Python 3.6, 3.7, 3.8


Usage
-----

The ``UDM`` context manager opens and closes a HTTP session::

    >>> from udm_rest_client.udm import UDM
    >>>
    >>> async def get_obj(mod_name, dn):
    ...     async with UDM(
    ...         "USERNAME",
    ...         "PASSWORD",
    ...         "https://FQDN.OF.UCS/univention/udm",
    ...         ssl_ca_cert="ucs-root-ca.crt"
    ...     ) as udm:
    ...         mod = udm.get(mod_name)
    ...         return await mod.get(dn)
    ...
    >>> import asyncio
    >>> obj = asyncio.run(get_obj("users/user", "uid=foo,cn=users,BASE-DN"))
    >>> print(obj)
    UdmObject('users/user', 'uid=foo,cn=users,BASE-DN')
    >>> print(obj.props.username)
    foo

There are more examples in the `docs`_ `usage` section.

If the SSL CA certificate is not available ``verify_ssl=False`` can be used in place of ``ssl_ca_cert=...``. Obviously that is not safe! The CA of any UCS server can always be downloaded from ``http://FQDN.OF.UCS/ucs-root-ca.crt``.


Installation
------------

1. Install `Python UDM REST Client` from pip::

    $ pip install udm-rest-client

2. Install the OpenAPI client library used by the udm-rest-client. It is created by software from the `OpenAPI Generator`_ project. You need to either have a local Java installation (Java 8+) or run the projects Docker container. The process is scripted::

    $ update_openapi_client --generator docker ucs.master.fqdn.or.ip  # use Docker
    $ update_openapi_client --generator java ucs.master.fqdn.or.ip  # use Java

Use ``--insecure`` to ignore SSL verification errors. See ``--help`` for more options.

**Important**:
Whenever a new UDM module is installed in the domain, it is necessary to rerun ``update_openapi_client``.
The new UDM module will otherwise not be available in the `Python UDM REST Client`.
Very few apps (like UCS\@school and Open-Xchange) install new UDM modules.
New extended attributes do `not` require to rebuild the OpenAPI client library.

Tests
-----

There are some isolated unittests, but most tests run against a real UDM REST API. A UCS Docker container is used for this. The ``Makefile`` automates downloading and starting the Docker container (1 GB) and running the tests.

Run tests with current Python interpreter::

    $ make test

Using `tox`_ the tests can be executed with all supported Python versions::

    $ make test-all

It is also possible to use an existing UCS server for the tests. Export ``UCS_HOST`` (the servers IP/FQDN), ``UCS_USERDN`` (the DN of an administrator account, usually ``uid=Administrator``) and ``UCS_PASSWORD`` (the accounts password), before starting the tests::

    $ export UCS_HOST="my.server.local"
    $ export UCS_USERDN="uid=Administrator,cn=users,dc=domain,dc=local"
    $ export UCS_PASSWORD="s3cr3t"
    $ make test

Don't forget to update the OpenAPI client library before running the test against a new server::

    $ update_openapi_client --generator <docker|java> $UCS_HOST


Logging
-------

Standard logging is used for tracking the libraries activity.
To capture the log messages for this project, subscribe to a logger named ``udm_rest_client``.

The `UDM REST API` on the UCS server logs into the file ``/var/log/univention/directory-manager-rest.log``.

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
.. _`tox`: http://tox.readthedocs.org/
.. _`UDM REST API`: https://docs.software-univention.de/developer-reference-4.4.html#udm:rest_api
.. _`Python UDM API`: https://github.com/univention/univention-corporate-server/blob/4.4-2/management/univention-directory-manager-modules/modules/univention/udm/__init__.py
.. _`OpenAPI Generator`: https://github.com/OpenAPITools/openapi-generator
.. _`docs`: https://udm-rest-client.readthedocs.io
.. |license| image:: https://img.shields.io/badge/License-AGPL%20v3-orange.svg
    :alt: GNU AGPL V3 license
    :target: https://www.gnu.org/licenses/agpl-3.0
.. |python| image:: https://img.shields.io/badge/python-3.6+-blue.svg
    :alt: Python 3.6+
    :target: https://www.python.org/
.. |code style| image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :alt: Code style: black
    :target: https://github.com/python/black
