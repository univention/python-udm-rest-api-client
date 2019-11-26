.. highlight:: shell

============
Contributing
============

Contributions are welcome, and they are greatly appreciated! Every little bit
helps, and credit will always be given.

You can contribute in many ways:

Types of Contributions
----------------------

Report Bugs
~~~~~~~~~~~

Report bugs at https://github.com/univention/python-udm-rest-api-client/issues.

If you are reporting a bug, please include:

* The operating system name and version and the Python version where the
  `Python UDM REST Client` was used.
* The UCS version of the server and installed apps (the output of
  ``univention-app info``) to which the `Python UDM REST Client` connected.
* Any details about your local setup that might be helpful in troubleshooting.
* Detailed steps to reproduce the bug.

Fix Bugs
~~~~~~~~

Look through the GitHub issues for bugs. Anything tagged with "bug" and "help
wanted" is open to whoever wants to implement it.

Additionally look at bugs in the Univention Bugzilla in the product
``Components`` with component ``udm-rest-api-client``:
http://forge.univention.org/bugzilla/buglist.cgi?component=udm-rest-api-client&product=Components&resolution=---

Implement Features
~~~~~~~~~~~~~~~~~~

Look through the GitHub issues and Univention Bugzilla for features. Anything
tagged with "enhancement" and "help wanted" is open to whoever wants to
implement it.

Write Documentation
~~~~~~~~~~~~~~~~~~~

`Python UDM REST Client` could always use more documentation, whether as part of the
official `Python UDM REST Client` docs, in docstrings, or even on the web in blog posts,
articles, and such.

Submit Feedback
~~~~~~~~~~~~~~~

The best way to send feedback is to file an issue at https://github.com/univention/python-udm-rest-api-client/issues.

If you are proposing a feature:

* Explain in detail how it would work.
* Keep the scope as narrow as possible, to make it easier to implement.
* Remember that this is a volunteer-driven project, and that contributions
  are welcome :)

Get Started!
------------

Ready to contribute? Here's how to set up `udm_rest_client` for local development.

1. Fork the `udm_rest_client` repo on GitHub.
2. Clone your fork locally::

    $ git clone git@github.com:your_name_here/udm_rest_client.git

3. Install your local copy into a virtualenv::

    $ cd udm_rest_client/
    $ python3 -m venv venv
    $ . venv/bin/activate
    $ pip install -r requirements.txt -r requirements_dev.txt -r requirements_test.txt
    $ make install

3.1 Install the OpenAPI client library using a UCS in a Docker container::

    $ make pip-install-openapi-client

3.2 Or install it using your UCS server::

    $ update_openapi_client --generator <docker|java> [--insecure] ucs.master.fqdn.or.ip

4. Create a branch for local development::

    $ git checkout -b name-of-your-bugfix-or-feature

   Now you can make your changes locally.

5. When you're done making changes, check that your changes pass the style checks and the
   tests, including testing other Python versions with tox::

    $ make lint
    $ make test
    $ make test-all

5.1 Fix format and coverage problems::

    $ make format
    $ make coverage-html

6. Commit your changes and push your branch to GitHub::

    $ git add .
    $ git commit -m "Your detailed description of your changes."
    $ git push origin name-of-your-bugfix-or-feature

7. Submit a pull request through the GitHub website.

Pull Request Guidelines
-----------------------

Before you submit a pull request, check that it meets these guidelines:

1. The pull request should include tests.
2. If the pull request adds functionality, the docs should be updated. Put
   your new functionality into a function with a docstring, and add the
   feature to the list in README.rst.
3. Make sure style and coverage requirements are met (run ``make lint``
   and ``tox``).
4. The pull request should work for Python 3.6, 3.7 and 3.8. Check
   https://travis-ci.org/dansan/udm_rest_client/pull_requests
   and make sure that the tests pass for all supported Python versions.

Tips
----

To run a subset of tests::

    $ python -m pytest tests/test_base_http.py::test_session_base_dn


Deploying
---------

A reminder for the maintainers on how to deploy.
Make sure all your changes are committed (including an entry in HISTORY.rst).
Then run::

$ bumpversion patch # possible: major / minor / patch
$ git push
$ git push --tags

Travis will then deploy to PyPI if tests pass.
