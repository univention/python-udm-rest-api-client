.PHONY: clean clean-test clean-pyc clean-build docs help
.DEFAULT_GOAL := help

define BROWSER_PYSCRIPT
import os
import sys
import webbrowser

try:
	from urllib import pathname2url
except:
	from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re
import sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

BROWSER := python -c "$$BROWSER_PYSCRIPT"

TEST_CONTAINER_NAME = ucs5
LXD_IMAGE_FILES_EXIST = . ./lxd.sh && lxd_image_files_exists
DOWNLOAD_LXD_IMAGE_FILES = . ./lxd.sh && download_lxd_image_files && verify_lxd_image_files
IMPORT_LXD_IMAGE = . ./lxd.sh && lxd_create_image_from_files
LXD_IS_INITIALIZED = . ./lxd.sh && lxd_is_initialized
LXD_IMAGE_EXISTS = . ./lxd.sh && lxd_image_exists
CONTAINER_IS_RUNNING = . ./lxd.sh && lxd_container_running
CONTAINER_IS_RUNNING_WITH_IP = . ./lxd.sh && lxd_container_running_with_ip
CONTAINER_IS_STOPPED = . ./lxd.sh && lxd_container_stopped
CREATE_LXD_CONTAINER = . ./lxd.sh && lxd_create_container
START_LXD_CONTAINER = . ./lxd.sh && lxd_start_container
CONTAINER_IP_CMD = . ./lxd.sh && lxd_container_ip
GET_OPENAPI_SCHEMA = . ./lxd.sh && get_openapi_schema
STOP_LXD_CONTAINER = . ./lxd.sh && lxd_stop_container
REMOVE_LXD_CONTAINER = . ./lxd.sh && lxd_remove_container
REMOVE_LXD_IMAGE = . ./lxd.sh && lxd_remove_image
YQ_IS_INSTALLED = . ./lxd.sh && yq_is_installed

OPENAPI_GENERATOR_DOCKER_IMAGE = "openapitools/openapi-generator-cli:v5.0.0"
OPENAPI_CLIENT_LIB_NAME = openapi-client-udm
OPENAPI_CLIENT_LIB_IS_INSTALLED = python3 -m pip show -q openapi-client-udm


help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

clean: clean-build clean-pyc clean-test ## remove all build, test, coverage and Python artifacts

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr docs/_build/
	rm -fr dist/
	rm -fr .eggs/
	rm -fr /tmp/openapilibbuild/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -fr {} +

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/
	rm -fr .pytest_cache
	rm -fr /tmp/openapilibbuild/

setup_devel_env: ## setup development environment (virtualenv)
	@if [ -d venv ]; then \
		echo "Directory 'venv' exists."; \
	else \
		/usr/bin/python3.8 -m venv venv; \
	fi; \
	. venv/bin/activate && \
	python3 -m pip install -U pip && \
	python3 -m pip install -r requirements.txt -r requirements_dev.txt -r requirements_test.txt; \
	echo "==> Run '. venv/bin/activate' to activate virtual env."

format: ## format source code (using pre-commits Python interpreter)
	pre-commit run -a --hook-stage manual isort-edit
	pre-commit run -a --hook-stage manual black-edit

lint-isort:
	pre-commit run -a isort

lint-black:
	pre-commit run -a black

lint-flake8:
	pre-commit run -a flake8

lint-bandit:
	pre-commit run -a bandit

lint-coverage: .coverage ## check test coverage
	coverage report --show-missing --fail-under=100

lint-pre-commit:
	pre-commit run -a

lint: lint-pre-commit lint-coverage ## run all linters and check test coverage

test: ## run tests with the current Python interpreter
	@if [ -n "$$UCS_HOST" ] && [ -n "$$UCS_USERDN" ] && [ -n "$$UCS_PASSWORD" ]; then \
		echo "Using UCS_HOST, UCS_USERDN and UCS_PASSWORD from env."; \
		export UCS_HOST UCS_USERDN UCS_PASSWORD; \
	else \
		echo "Starting UCS using LXD. Set UCS_HOST, UCS_USERDN and UCS_PASSWORD to use an existing UCS server."; \
		make create-lxd-test-server-config; \
	fi; \
	python -m pytest -l -v && rv=0 || rv=1; \
	echo "Stopping and removing the LXD container..."; \
	make stop-and-remove-lxd-container; \
	return $$rv

test-all: ## run tests with every supported Python version using tox
	@if [ -n "$$UCS_HOST" ] && [ -n "$$UCS_USERDN" ] && [ -n "$$UCS_PASSWORD" ]; then \
		echo "Using UCS_HOST, UCS_USERDN and UCS_PASSWORD from env."; \
		export UCS_HOST UCS_USERDN UCS_PASSWORD; \
	else \
		echo "Starting UCS using LXD. Set UCS_HOST, UCS_USERDN and UCS_PASSWORD to use an existing UCS server."; \
		make create-lxd-test-server-config || exit 1; \
	fi; \
	tox && rv=0 || rv=1; \
	echo "Stopping and removing the LXD container..."; \
	make stop-and-remove-lxd-container; \
	return $$rv

.coverage: *.py docs/*.py udm_rest_client/*.py tests/*.py
	@if [ -e tests/test_server.yaml ]; then \
		echo "Using configuration from tests/test_server.yaml."; \
	elif [ -n "$$UCS_HOST" ] && [ -n "$$UCS_USERDN" ] && [ -n "$$UCS_PASSWORD" ]; then \
		echo "Using UCS_HOST, UCS_USERDN and UCS_PASSWORD from env."; \
		export UCS_HOST UCS_USERDN UCS_PASSWORD; \
	else \
		echo "Starting UCS in LXD. Set UCS_HOST, UCS_USERDN and UCS_PASSWORD to test using existing UCS."; \
		make start-lxd-container; \
		export UCS_CONTAINER_IP=`$(CONTAINER_IP_CMD)`; \
	fi; \
	coverage run --source tests,udm_rest_client -m pytest

coverage: .coverage ## check code coverage with the current Python interpreter
	coverage report --show-missing

coverage-html: coverage ## generate HTML coverage report
	coverage html
	$(BROWSER) htmlcov/index.html

docs: ## generate Sphinx HTML documentation, including API docs
	rm -f docs/udm_rest_client.rst
	rm -f docs/modules.rst
	sphinx-apidoc -o docs/ udm_rest_client
	$(MAKE) -C docs clean
	$(MAKE) -C docs html

docs-open: docs ## open generated Sphinx HTML doc in browser
	$(BROWSER) docs/_build/html/index.html

servedocs: docs ## compile the docs watching for changes
	watchmedo shell-command -p '*.rst' -c '$(MAKE) -C docs html' -R -D .

release: dist ## package and upload a release to pypi
	twine upload dist/*

release-test: dist ## package and upload a release to the pypi test site
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*

dist: clean ## builds source and wheel package
	python setup.py sdist
	python setup.py bdist_wheel
	ls -l dist

install: clean ## install the package to the active Python's site-packages
	python setup.py develop

lxd-is-initialized:
	@if $(LXD_IS_INITIALIZED); then\
		echo "LXD is initialized."; \
	else \
		echo "LXD has not been initialized. Read the documentation for 'lxd init'."; \
	fi

download-lxc-container: ## download LXD container from Univention server (1 GB)
	@if $(LXD_IMAGE_FILES_EXIST); then \
		echo "LXD image files exist."; \
	else \
		echo "Downloading image files..."; \
		$(DOWNLOAD_LXD_IMAGE_FILES); \
	fi

import-lxd-image: lxd-is-initialized download-lxc-container
	@if $(LXD_IMAGE_EXISTS); then \
  		echo "LXD image exist."; \
	else \
		echo "Importing image into LXD..."; \
		$(IMPORT_LXD_IMAGE); \
	fi

yq-is-installed:
	@if ! $(YQ_IS_INSTALLED); then \
  		echo "'yq' is required. Please install it: https://github.com/mikefarah/yq"; \
  	fi

start-lxd-container: import-lxd-image yq-is-installed ## start LXD container (a joined UCS system with a running UDM REST API)
	@if $(CONTAINER_IS_RUNNING); then \
		echo "LXD container '$(TEST_CONTAINER_NAME)' is running at '`$(CONTAINER_IP_CMD)`'."; \
	elif $(CONTAINER_IS_STOPPED); then \
		echo "LXD container '$(TEST_CONTAINER_NAME)' is stopped, starting it..."; \
		$(START_LXD_CONTAINER); \
	else \
		echo "Creating and starting LXD container..."; \
		$(CREATE_LXD_CONTAINER); \
	fi
	@echo -n "Waiting for container to start..."
	@while ! ($(CONTAINER_IS_RUNNING)); do echo -n "."; sleep 1; done
	@echo -n "Waiting for IP address of container..."
	@while ! ($(CONTAINER_IS_RUNNING_WITH_IP)); do echo -n "."; sleep 1; done
	@while true; do export UCS_CONTAINER_IP=`$(CONTAINER_IP_CMD)`; [ -n "$$UCS_CONTAINER_IP" ] && break || (echo "."; sleep 1); done; \
	if [ -z "$$UCS_CONTAINER_IP" ]; then \
		echo "Cannot get IP of container."; \
		exit 1; \
	fi; \
	echo -n "Waiting for UDM REST API..."; \
	while ! ($(GET_OPENAPI_SCHEMA) --connect-timeout 1 >/dev/null); do echo -n "."; sleep 1; done; \
	echo ""; \
	echo "==> UDM REST API: http://$$UCS_CONTAINER_IP/univention/udm/"

stop-lxd-container: ## stop LXD container (not the image)
	@$(STOP_LXD_CONTAINER) && echo "Stopped container." || "Container not running."; true

stop-and-remove-lxd-container: ## stop and remove LXD container (not the image)
	@$(STOP_LXD_CONTAINER) && echo "Stopped container." || "Container not running."; true
	@$(REMOVE_LXD_CONTAINER) && echo "Removed container." || "Container does not exist."; true

remove-lxd-image: stop-and-remove-lxd-container ## stop and remove LXD container AND image
	$(REMOVE_LXD_IMAGE) && echo "Removed image." || "Image does not exist."

create-lxd-test-server-config: start-lxd-container ## start LXD container and create suitable tests/test_server.yaml
	@echo "Creating tests/test_server.yaml..."
	@sed -e "s/10.20.30.40/`$(CONTAINER_IP_CMD)`/g" -e "s/dc=example,dc=com/dc=uni,dc=dtr/g" -e "s/s3cr3t/univention/g" tests/test_server_example.yaml > tests/test_server.yaml

install-openapi-client:  ## build and install the OpenAPI client library into 'venv'
	@. venv/bin/activate; make pip-install-openapi-client

pip-install-openapi-client:  ## build and install the OpenAPI client library into currently active env
	@if $(OPENAPI_CLIENT_LIB_IS_INSTALLED); then \
		echo "OpenAPI client lib ('$(OPENAPI_CLIENT_LIB_NAME)') is installed (see 'pip list')."; \
	else \
		if [ -z "$$UCS_HOST" ]; then \
			echo "Env 'UCS_HOST' not set, starting LXD container..."; \
			make start-lxd-container; \
			UCS_HOST=`$(CONTAINER_IP_CMD)`; \
		fi; \
		./update_openapi_client --insecure --generator docker --username Administrator --password univention $$UCS_HOST; \
	fi

pip-install-openapi-client-from-test-pypi:  ## install pre-built OpenAPI client library into currently active env
	@if $(OPENAPI_CLIENT_LIB_IS_INSTALLED); then \
		echo "OpenAPI client lib ('$(OPENAPI_CLIENT_LIB_NAME)') is installed (see 'pip list')."; \
	else \
		make start-lxd-container; \
		python3 -m pip install --compile --upgrade --index-url https://test.pypi.org/simple/ openapi-client-udm; \
	fi

print-ucs-lxd-ip: start-lxd-container ## print IP address of UCS LXD container (start if not running)
	@echo `$(CONTAINER_IP_CMD)`

upload_openapi-client-to-test-pypi: clean  ## build and upload "openapi-client-udm" package to test-pypi
	if [ -z "$$UCS_HOST" ] || [ -z "$$PACKAGE_VERSION" ]; then \
  		echo "Before running this command:"; \
  		echo "export UCS_HOST=10.200.x.y; PACKAGE_VERSION=1.0.x"; echo; \
  		exit 1; \
	fi
	mkdir -pv /tmp/build
	curl -u Administrator:univention http://$$UCS_HOST/univention/udm/openapi.json > /tmp/build/udm_openapi.json
	docker run -u "`id -u`:`id -g`" -v /tmp/build:/local $(OPENAPI_GENERATOR_DOCKER_IMAGE) generate -g python-legacy --library asyncio --package-name openapi_client_udm "--additional-properties=packageVersion=$$PACKAGE_VERSION" -i /local/udm_openapi.json -o /local/python
	cd /tmp/build/python; \
	python setup.py sdist; \
	python setup.py bdist_wheel; \
	ls -l dist
	cd /tmp/build/python; \
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*
