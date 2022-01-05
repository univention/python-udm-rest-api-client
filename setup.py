#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import find_packages, setup

with open("README.rst") as readme_file:
    readme = readme_file.read()

with open("HISTORY.rst") as history_file:
    history = history_file.read()

with open("requirements.txt") as requirements_file:
    requirements = requirements_file.read()

with open("requirements_test.txt") as requirements_file:
    test_requirements = requirements_file.read()

setup_requirements = ["pytest-runner"]

setup(
    author="Daniel Troeder",
    author_email="troeder@univention.de",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Software Development :: Libraries",
        "Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP",
    ],
    description="Python library to interact with the Univention UDM REST API. Implements the simple Python UDM API.",
    license="GNU Affero General Public License v3",
    long_description=readme + "\n\n" + history,
    long_description_content_type="text/x-rst",
    include_package_data=True,
    keywords="Univention UCS UDM REST",
    name="udm-rest-client",
    packages=find_packages(include=["udm_rest_client"]),
    install_requires=requirements,
    setup_requires=setup_requirements,
    test_suite="tests",
    tests_require=test_requirements,
    python_requires=">=3.6",
    scripts=["update_openapi_client"],
    url="https://github.com/univention/python-udm-rest-api-client",
    version="1.0.6",
    zip_safe=False,
)
