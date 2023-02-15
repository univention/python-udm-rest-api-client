======================
Python UDM REST Client
======================

|python| |license| |code style| |codecov| |docspassing| |travisci| |gh Code Linting| |gh Integration tests|

Python library to interact with the Univention `UDM REST API`_, implements the interface of the `Python UDM API`_.

* Free software: GNU Affero General Public License version 3
* Documentation: https://udm-rest-client.readthedocs.io


Features
--------

* Asynchronous
* Automatic handling of HTTP(S) sessions
* Type annotations
* 100% test coverage (unittests + integration tests)
* Python 3.6, 3.7, 3.8, 3.9, 3.10, 3.11


Usage
-----

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
    >>> # Python 3.6:
    >>> loop = asyncio.get_event_loop()
    >>> obj = loop.run_until_complete(get_obj("users/user", "uid=foo,cn=users,BASE-DN"))
    >>>
    >>> # Python 3.7+:
    >>> obj = asyncio.run(get_obj("users/user", "uid=foo,cn=users,BASE-DN"))
    >>>
    >>> print(obj)
    UdmObject('users/user', 'uid=foo,cn=users,BASE-DN')
    >>> print(obj.props.username)
    foo

There are more examples in the `docs`_ *usage* section.

If the SSL CA certificate is not available ``verify_ssl=False`` can be used in place of ``ssl_ca_cert=...``. Obviously that is not safe! The CA of any UCS server can always be downloaded from ``http://FQDN.OF.UCS/ucs-root-ca.crt``.


Installation
------------

1. Install *Python UDM REST Client* via pip from `PyPI`_::

    $ pip install udm-rest-client

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

Tests
-----

There are some isolated unittests, but most tests run against a real UDM REST API. Either an existing UCS installation can be used, or a LXD container started.

Run tests with the current Python interpreter::

    $ make test

Using `tox`_ the tests can be executed with all supported Python versions::

    $ make test-all

Using the UCS LXD container is automated in the ``Makefile``. It has commands to download and start the LXD image (1 GB) and running the tests::

    $ make create-lxd-test-server-config
    $ make test

Initializing LXD is however left up to the developer (see https://linuxcontainers.org/lxd/). Using storage backend ``lvm``, ``btrfs`` or ``zfs`` is recommended for repeated use. To run the tests only once, the storage backend ``dir`` is the easiest to use. It is very slow though, as it requires unpacking the image every time the container is started.

The ``Makefile`` also needs ``yq`` to be installed: https://github.com/mikefarah/yq

It is also possible to use an existing UCS server for the tests. Export ``UCS_HOST`` (the servers IP/FQDN), ``UCS_USERDN`` (the DN of an administrator account, usually ``uid=Administrator,cn=users,dc=...``) and ``UCS_PASSWORD`` (the accounts password), before starting the tests::

    $ export UCS_HOST="my.server.local"
    $ export UCS_USERDN="uid=Administrator,cn=users,dc=domain,dc=local"
    $ export UCS_PASSWORD="s3cr3t"
    $ make test

Much more comfortable (especially for repeated use) is creating a file ``test_server.yaml`` in the ``tests`` directory, which will automatically be used by the tests::

    $ cp test_server_example.yaml test/test_server.yaml
    $ $EDITOR test_server.yaml

Don't forget to update the OpenAPI client library before running the test against a new server::

    $ update_openapi_client --generator <docker|java> --username Administrator --password s3cr3t $UCS_HOST

Run ``update_openapi_client --help`` to see further options.

To get the IP address of the running UCS LXD container execute::

    $ . lxd.sh ; lxd_container_ip

Logging
-------

Standard logging is used for tracking the libraries activity.
To capture the log messages for this project, subscribe to a logger named ``udm_rest_client``.

The *UDM REST API* on the UCS server logs into the file ``/var/log/univention/directory-manager-rest.log``.

Repo permissions
----------------
* GitHub: @dansan and @JuergenBS
* GitLab: @JuergenBS
* PyPI: @dansan and @SamuelYaron
* RTD: @dansan and @SamuelYaron

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
.. _`tox`: http://tox.readthedocs.org/
.. _`UDM REST API`: https://docs.software-univention.de/developer-reference-4.4.html#udm:rest_api
.. _`Python UDM API`: https://github.com/univention/univention-corporate-server/blob/4.4-8/management/univention-directory-manager-modules/modules/univention/udm/__init__.py
.. _`OpenAPI Generator`: https://github.com/OpenAPITools/openapi-generator
.. _`docs`: https://udm-rest-client.readthedocs.io
.. _`PyPI`: https://pypi.org/project/udm-rest-client/
.. |license| image:: https://img.shields.io/badge/License-AGPL%20v3-orange.svg
    :alt: GNU AGPL V3 license
    :target: https://www.gnu.org/licenses/agpl-3.0
.. |python| image:: https://img.shields.io/badge/python-3.6+-blue.svg
    :alt: Python 3.6+
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
.. |travisci| image:: https://travis-ci.com/univention/python-udm-rest-api-client.svg?branch=master
    :target: https://app.travis-ci.com/github/univention/python-udm-rest-api-client
.. |gh Code Linting| image:: https://github.com/univention/python-udm-rest-api-client/workflows/Code%20Linting/badge.svg
    :target: https://github.com/univention/python-udm-rest-api-client/actions?query=workflow%3A%22Code+Linting%22
.. |gh Integration tests| image:: https://github.com/univention/python-udm-rest-api-client/workflows/Integration%20tests/badge.svg
    :target: https://github.com/univention/python-udm-rest-api-client/actions?query=workflow%3A%22Integration+tests%22
