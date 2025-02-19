######################
Python UDM REST Client
######################

|python| |license| |code style| |codecov| |docspassing|

Python library to interact with the Univention `UDM REST API`_,
implements the interface of the `Python UDM API`_.

* Free software: GNU Affero General Public License version 3
* Documentation: https://udm-rest-client.readthedocs.io


Features
========

* Asynchronous
* Automatic handling of HTTP(S) sessions
* Type annotations
* 100% test coverage (unittests + integration tests)
* Python 3.9, 3.10, 3.11


Usage
=====

The ``UDM`` context manager opens and closes a HTTP session::

    >>> import asyncio
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
    >>> obj = asyncio.run(get_obj("users/user", "uid=foo,cn=users,BASE-DN"))
    >>>
    >>> print(obj)
    UdmObject('users/user', 'uid=foo,cn=users,BASE-DN')
    >>> print(obj.props.username)
    foo

There are more examples in the `docs`_ *usage* section.

If the SSL CA certificate is not available ``verify_ssl=False`` can be used in place of ``ssl_ca_cert=...``. Obviously that is not safe! The CA of any UCS server can always be downloaded from ``http://FQDN.OF.UCS/ucs-root-ca.crt``.


Installation
============

1. Install *Python UDM REST Client* via pip from `PyPI`_::

    $ pip install udm-rest-client

   If you see a complaint about docker needing a higher version of urrlib3, upgrade::

    $ pip install --upgrade urllib3

2. Install the OpenAPI client library used by the udm-rest-client. It is created by software from the `OpenAPI Generator`_ project. You need to either have a local Java installation (Java 8+) or run the projects Docker container. The process is scripted::

    $ update_openapi_client --generator docker ucs.master.fqdn.or.ip  # use Docker
    $ update_openapi_client --generator java ucs.master.fqdn.or.ip  # use Java

Use ``--insecure`` to ignore SSL verification errors. See ``--help`` for more options.

Use ``--username`` and ``--password`` to provide credentials if access to your openapi.json is protected. This is the
default in newer versions of UCS and thus credentials are needed.

**Important**:
Whenever a new UDM module is installed in the domain, it is necessary to rerun ``update_openapi_client``.
The new UDM module will otherwise not be available in the *Python UDM REST Client*.
Very few apps (like UCS\@school and Open-Xchange) install new UDM modules.
New extended attributes do *not* require to rebuild the OpenAPI client library.

Logging
=======

Standard logging is used for tracking the library's activity.
To capture the log messages for this project, subscribe to a logger named ``udm_rest_client``.

The *UDM REST API* on the UCS server logs into the file ``/var/log/univention/directory-manager-rest.log``.

Credits
=======

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
.. _`UDM REST API`: https://docs.software-univention.de/developer-reference-4.4.html#udm:rest_api
.. _`Python UDM API`: https://github.com/univention/univention-corporate-server/blob/4.4-8/management/univention-directory-manager-modules/modules/univention/udm/__init__.py
.. _`OpenAPI Generator`: https://github.com/OpenAPITools/openapi-generator
.. _`docs`: https://udm-rest-client.readthedocs.io
.. _`PyPI`: https://pypi.org/project/udm-rest-client/
.. |license| image:: https://img.shields.io/badge/License-AGPL%20v3-orange.svg
    :alt: GNU AGPL V3 license
    :target: https://www.gnu.org/licenses/agpl-3.0
.. |python| image:: https://img.shields.io/badge/python-3.9+-blue.svg
    :alt: Python 3.9+
    :target: https://www.python.org/
.. |code style| image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :alt: Code style: black
    :target: https://github.com/psf/black
.. |codecov| image:: https://codecov.io/gh/univention/python-udm-rest-api-client/branch/master/graph/badge.svg
    :alt: Code coverage
    :target: https://codecov.io/gh/univention/python-udm-rest-api-client
.. |docspassing| image:: https://readthedocs.org/projects/udm-rest-client/badge/?version=latest
    :alt: Documentation Status
    :target: https://udm-rest-client.readthedocs.io/en/latest/?badge=latest
