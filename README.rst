.. image:: https://img.shields.io/badge/renovate-enabled-brightgreen.svg
    :target: ../issues/?search=Dependency%20Dashboard

.. image:: https://img.shields.io/badge/renovate-pipeline-brightgreen.svg
    :target: ../pipelines/new?var[RUN_RENOVATE]=yes

######################
Python UDM REST Client
######################

Python library to interact with the Univention `UDM REST API`_,
implements the interface of the `Python UDM API`_.

Read the `PyPi README <PYPI_README.rst>`_ for in introduction to this Python package.

For more detailed information, read the official `docs`_.

Repo permissions
================

* **GitHub**:
   * @dansan (Daniel Tröder)
   * @JuergenBS (Sönke)
* **GitLab**: UCS developers
* **PyPI**:
   * @botner (Felix Botner)
   * @brodersen4univention (Jürn Brodersen)
   * @dansan (Daniel Tröder)
   * @jleadbetter-univention (J Leadbetter)
   * @SamualYaron (Ole Schwiegert)
   * @twenzel (Tobias Wenzel)
* **RTD**: @dansan and @SamuelYaron
   * @dansan (Daniel Tröder)
   * @SamualYaron (Ole Schwiegert)
   * @jleadbetter-univention (J Leadbetter)

Tests
=====

There are some isolated unittests, but most tests run against a real UDM REST API.
Either an existing UCS installation can be used, or a LXD container started.

Run tests with the current Python interpreter::

    make test

Using `tox`_ the tests can be executed with all supported Python versions::

    make test-all

Using the UCS LXD container is automated in the ``Makefile``.
It has commands to download and start the LXD image (1 GB) and running the tests::

    make create-lxd-test-server-config
    make test

Initializing LXD is however left up to the developer (see https://linuxcontainers.org/lxd/).
Using storage backend ``lvm``, ``btrfs`` or ``zfs`` is recommended for repeated use.
To run the tests only once, the storage backend ``dir`` is the easiest to use.
It is very slow though, as it requires unpacking the image every time the container is started.

The ``Makefile`` also needs ``yq`` to be installed: https://github.com/mikefarah/yq

It is also possible to use an existing UCS server for the tests. Export ``UCS_HOST`` (the servers IP/FQDN), ``UCS_USERDN`` (the DN of an administrator account, usually ``uid=Administrator,cn=users,dc=...``) and ``UCS_PASSWORD`` (the accounts password), before starting the tests::

    export UCS_HOST="my.server.local"
    export UCS_USERDN="uid=Administrator,cn=users,dc=domain,dc=local"
    export UCS_PASSWORD="s3cr3t"
    make test

Much more comfortable (especially for repeated use) is creating a file ``test_server.yaml`` in the ``tests`` directory,
which will automatically be used by the tests::

    cp test_server_example.yaml test/test_server.yaml
    $EDITOR test_server.yaml

Don't forget to update the OpenAPI client library before running the test against a new server::

    update_openapi_client --generator <docker|java> --username Administrator --password s3cr3t $UCS_HOST

Run ``update_openapi_client --help`` to see further options.

To get the IP address of the running UCS LXD container execute::

    . lxd.sh ; lxd_container_ip

Releases
========

Prerequisites
-------------

You need a maintainer account with permissions for the ``udm-rest-client`` for:

* `PyPI Test`_
* `PyPI`_
* `ReadTheDocs`_ (community)

For the PypI Test and PyPI accounts,
generate an API token and add it to your ``.pypirc``
with the username ``__token__``.

Install ``twine``:

.. code:: bash

   sudo apt install twine -y

Before the release
------------------

* Verify the `daily tests`_.
* Create and merge a release commit:
  * Increment the Python package version in ``udm_rest_client/__init__py`` and ``setup.py``
  * Update ``HISTORY.rst`` with changelog notes.
* Tag the release commit with the new version.

PyPI Test Release
-----------------

We want to make sure everything looks as expected on PyPI Test
before pushing to production.

* Push the package to test PyPi:

  .. code:: bash

     make release-test

* Verify the updated changelog in `PyPI Test`_.
* Do a smoke test install on a UCS\@school VM.
  Sync the ``python-udm-rest-api-client`` folder to the VM,
  ``cd`` to the folder, and then:

  .. code:: bash

     pip3 install --upgrade urllib3
     pip3 install -r requirements.txt
     pip3 install -i https://test.pypi.org/simple/ udm-rest-client

  The installation of ``requirements.txt`` is required,
  because not all needed packages have a PyPI Test version.
* Verify the installed version:

  .. code:: bash

     pip3 freeze | grep udm

PyPI Release
------------

These steps push the newest version of the ``udm-rest-client``.

* Push the package to production PyPi:

  .. code:: bash

     make release

* Verify the updated changelog in `PyPI`_.
* Do a smoke test install on a UCS\@School VM:

  .. code:: bash

     pip3 install --upgrade urllib3
     pip3 install udm-rest-client

* Verify the installed version:

  .. code:: bash

     pip3 freeze | grep udm

Read the Docs
-------------

* Visit the `ReadTheDocs`_ dashboard.
* Verify that the builds for ``latest`` and ``stable`` passed.
* Do a visual inspection of the published `docs`_,
  ``latest`` and ``stable``,
  paying particular attention that the changelog is up to date on both.


.. _`daily tests`: https://jenkins2022.knut.univention.de/job/UCSschool-5.0/job/UDM-REST-API-client-daily/
.. _`tox`: http://tox.readthedocs.org/
.. _`UDM REST API`: https://docs.software-univention.de/developer-reference-4.4.html#udm:rest_api
.. _`Python UDM API`: https://github.com/univention/univention-corporate-server/blob/4.4-8/management/univention-directory-manager-modules/modules/univention/udm/__init__.py
.. _`OpenAPI Generator`: https://github.com/OpenAPITools/openapi-generator
.. _`docs`: https://udm-rest-client.readthedocs.io
.. _`ReadTheDocs`: https://readthedocs.org/projects/udm-rest-client/
.. _`PyPI`: https://pypi.org/project/udm-rest-client/
.. _`PyPI Test`: https://test.pypi.org/project/udm-rest-client/
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
