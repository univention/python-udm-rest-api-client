# -*- coding: utf-8 -*-

"""Test connection and utility functions in `conftest` module."""

import tempfile

import faker
import pytest
import ruamel.yaml

faker = faker.Faker()


@pytest.fixture
def connection_data():
    def _func():
        return {
            "host": faker.first_name(),
            "username": faker.first_name(),
            "user_dn": f"uid={faker.first_name()},cn=users,dc={faker.first_name()}",
            "password": faker.first_name(),
        }

    return _func


def test_load_test_server_yaml(load_test_server_yaml, connection_data):
    server = connection_data()
    with tempfile.NamedTemporaryFile(mode="w") as fp:
        yaml = ruamel.yaml.YAML(typ="rt", pure=True)
        yaml.indent = 4
        yaml.dump(server, fp)
        fp.flush()
        config = load_test_server_yaml(fp.name)
        assert server == {
            "host": config.host,
            "username": config.username,
            "user_dn": config.user_dn,
            "password": config.password,
        }


def test_save_test_server_yaml(save_test_server_yaml, connection_data):
    server = connection_data()
    with tempfile.NamedTemporaryFile() as fp:
        save_test_server_yaml(**server, path=fp.name)
        fp.flush()
        fp.seek(0)
        yaml = ruamel.yaml.YAML(typ="rt", pure=True)
        config = yaml.load(fp)
        assert config == server
