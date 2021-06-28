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
TEST_CONTAINER_NAME = udm_rest_only
CONTAINER_IS_RUNNING = UCS_REPOS="stable"; . docker/common.sh && docker_container_running "$(TEST_CONTAINER_NAME)"
CONTAINER_IP_CMD = UCS_REPOS="stable"; . docker/common.sh && docker_container_ip $(TEST_CONTAINER_NAME)
GET_OPENAPI_SCHEMA = UCS_REPOS="stable"; . docker/common.sh && get_openapi_schema "$(TEST_CONTAINER_NAME)"
OPENAPI_BUILD_DIR  = /tmp/openapilibbuild
OPENAPI_CLIENT_LIB_NAME = openapi-client-udm
OPENAPI_CLIENT_LIB_IS_INSTALLED = python3 -m pip show -q openapi-client-udm
DOCKER_IMG_FROM_REGISTRY = docker.software-univention.de/ucs-master-amd64-joined-udm-rest-api-only:stable-4.4-8
DOCKER_IMG_FROM_REGISTRY_EXISTS = UCS_REPOS="stable"; . docker/common.sh && docker_img_exists "$(DOCKER_IMG_FROM_REGISTRY)"
DOCKER_IMG_EXISTS = UCS_REPOS="stable"; . docker/common.sh && docker_img_exists "$(DOCKER_IMG_FROM_REGISTRY)"
START_DOCKER_CONTAINER = docker run --detach --name "$(TEST_CONTAINER_NAME)" --hostname=master -p 9080:80/tcp -p 9443:443/tcp --tmpfs /run --tmpfs /run/lock "$(DOCKER_IMG_FROM_REGISTRY)"


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
		echo "Starting UCS in Docker. Set UCS_HOST and UCS_AUTH to use an existing UCS server."; \
		make start-docker-container; \
		export UCS_CONTAINER_IP=`$(CONTAINER_IP_CMD)`; \
		if [ -z "$$UCS_CONTAINER_IP" ]; then \
			echo "Cannot get IP of container. Is it running?"; \
			exit 1; \
		fi; \
	fi; \
	python -m pytest -l -v && rv=0 || rv=1; \
	echo "Stopping and removing the docker container..."; \
	make stop-and-remove-docker-container; \
	return $$rv

test-all: ## run tests with every supported Python version using tox
	@if [ -n "$$UCS_HOST" ] && [ -n "$$UCS_USERDN" ] && [ -n "$$UCS_PASSWORD" ]; then \
		echo "Using UCS_HOST, UCS_USERDN and UCS_PASSWORD from env."; \
		export UCS_HOST UCS_USERDN UCS_PASSWORD; \
	else \
		echo "Starting UCS in Docker. Set UCS_HOST and UCS_AUTH to use an existing UCS server."; \
		make start-docker-container; \
		export UCS_CONTAINER_IP=`$(CONTAINER_IP_CMD)`; \
		if [ -z "$$UCS_CONTAINER_IP" ]; then \
			echo "Cannot get IP of container. Is it running?"; \
			exit 1; \
		fi; \
	fi; \
	tox && rv=0 || rv=1; \
	echo "Stopping and removing the docker container..."; \
	make stop-and-remove-docker-container; \
	return $$rv

.coverage: *.py docs/*.py udm_rest_client/*.py tests/*.py
	@if [ -e tests/test_server.yaml ]; then \
		echo "Using configuration from tests/test_server.yaml."; \
	elif [ -n "$$UCS_HOST" ] && [ -n "$$UCS_USERDN" ] && [ -n "$$UCS_PASSWORD" ]; then \
		echo "Using UCS_HOST, UCS_USERDN and UCS_PASSWORD from env."; \
		export UCS_HOST UCS_USERDN UCS_PASSWORD; \
	else \
		echo "Starting UCS in Docker. Set UCS_HOST and UCS_AUTH to test using existing UCS."; \
		make start-docker-container; \
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

build-docker-image: ## build docker image (a joined UCS system with a running UDM REST API)
	@if $(DOCKER_IMG_EXISTS); then \
		echo "Docker image '$(DOCKER_IMG_FROM_REGISTRY)' exists."; \
	else \
		(cd docker && ./build_ucs_join_image && ./build_udm_rest_api_only_image); \
	fi

download-docker-container: ## download docker container from Univention Docker registry (1 GB)
	@if $(DOCKER_IMG_FROM_REGISTRY_EXISTS); then \
		echo "Docker image '$(DOCKER_IMG_FROM_REGISTRY)' exists."; \
	else \
		docker pull $(DOCKER_IMG_FROM_REGISTRY); \
	fi

start-docker-container: download-docker-container ## start docker container (a joined UCS system with a running UDM REST API)
	@if $(CONTAINER_IS_RUNNING); then \
		echo "Docker container '$(TEST_CONTAINER_NAME)' is running."; \
	else \
		echo "Starting docker container..."; \
		$(START_DOCKER_CONTAINER); \
	fi
	@echo "Waiting for docker container to start..."
	@while ! ($(CONTAINER_IS_RUNNING)); do echo -n "."; sleep 1; done
	@echo "Waiting for IP address of container..."
	@while true; do export UCS_CONTAINER_IP=`$(CONTAINER_IP_CMD)`; [ -n "$$UCS_CONTAINER_IP" ] && break || (echo "."; sleep 1); done; \
	if [ -z "$$UCS_CONTAINER_IP" ]; then \
		echo "Cannot get IP of container."; \
		exit 1; \
	fi; \
	echo -n "Waiting for UDM REST API"; \
	while ! ($(GET_OPENAPI_SCHEMA) --connect-timeout 1 >/dev/null); do echo -n "."; sleep 1; done; \
	echo ""; \
	echo "==> UDM REST API: http://$$UCS_CONTAINER_IP/univention/udm/"

stop-and-remove-docker-container: ## stop and remove docker container (not the image)
	docker stop --time 0 $(TEST_CONTAINER_NAME) || true
	docker rm $(TEST_CONTAINER_NAME) || true

install-openapi-client:  ## build and install the OpenAPI client library into 'venv'
	@. venv/bin/activate; make pip-install-openapi-client

pip-install-openapi-client:  ## build and install the OpenAPI client library into currently active env
	@if $(OPENAPI_CLIENT_LIB_IS_INSTALLED); then \
		echo "OpenAPI client lib ('$(OPENAPI_CLIENT_LIB_NAME)') is installed (see 'pip list')."; \
	else \
		make start-docker-container; \
		./update_openapi_client --insecure `$(CONTAINER_IP_CMD)` --generator docker --username Administrator --password univention; \
	fi

pip-install-openapi-client-from-test-pypi:  ## install pre-built OpenAPI client library into currently active env
	@if $(OPENAPI_CLIENT_LIB_IS_INSTALLED); then \
		echo "OpenAPI client lib ('$(OPENAPI_CLIENT_LIB_NAME)') is installed (see 'pip list')."; \
	else \
		make start-docker-container; \
		python3 -m pip install --compile --upgrade --index-url https://test.pypi.org/simple/ openapi-client-udm; \
	fi

print-ucs-docker-ip: start-docker-container ## print IP address of UCS docker container (start if not running)
	@echo `$(CONTAINER_IP_CMD)`
