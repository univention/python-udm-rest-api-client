import copy
import datetime
import logging
import os
import random
import string
from collections import namedtuple
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union
from urllib.parse import unquote

import attr
import factory
import faker
import pytest
import requests
import ruamel.yaml
from ldap3 import AUTO_BIND_TLS_BEFORE_BIND, SIMPLE, Connection, Server
from ldap3.core.exceptions import LDAPInvalidDnError
from ldap3.utils.dn import parse_dn
from urllib3.exceptions import InsecureRequestWarning

import udm_rest_client.exceptions

try:
    import openapi_client_udm.models.users_user
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "Please run 'update_openapi_client' to install the OpenAPI client "
        "library package 'openapi-client-udm'."
    ) from exc


TEST_SERVER_YAML_FILENAME = Path(__file__).parent / "test_server.yaml"
UDMServer = namedtuple("UDMServer", ["host", "username", "user_dn", "password"])
fake = faker.Faker()
logger = logging.getLogger(__name__)
UCS_LDAP_PORT = 7389
ca_cert_path: Path = None


# suppress "InsecureRequestWarning: Unverified HTTPS request is being made."
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class ContainerIpUnknown(Exception):
    ...


class BadTestServerConfig(Exception):
    ...


class NoTestServerConfig(Exception):
    ...


@pytest.fixture(scope="session")
def load_test_server_yaml():
    def _func(path: Union[str, Path] = TEST_SERVER_YAML_FILENAME) -> UDMServer:
        """
        :raises: FileNotFoundError
        :raises: TypeError
        """
        with open(path, "r") as fp:
            yaml = ruamel.yaml.YAML(typ="rt", pure=True)
            config = yaml.load(fp)
        return UDMServer(**config)

    return _func


@pytest.fixture(scope="session")
def save_test_server_yaml():
    """
    This is here only to make things simpler for developers. It's not actually
    needed in the tests.
    """

    def _func(
        host: str,
        username: str,
        user_dn: str,
        password: str,
        path: Union[str, Path] = TEST_SERVER_YAML_FILENAME,
    ) -> None:
        """
        :raises: OSError (PermissionError etc)
        """
        with open(path, "w") as fp:
            yaml = ruamel.yaml.YAML(typ="rt", pure=True)
            yaml.indent = 4
            yaml.dump(
                {
                    "host": host,
                    "username": username,
                    "user_dn": user_dn,
                    "password": password,
                },
                fp,
            )

    return _func


def _test_a_server_configuration(server: UDMServer) -> UDMServer:
    auth = (server.username, server.password)
    url = f"https://{server.host}/univention/udm/ldap/base/"
    resp = requests.get(url, auth=auth, verify=False)
    if resp.status_code != 200:
        raise udm_rest_client.exceptions.APICommunicationError(  # pragma: no cover
            resp.reason, resp.status_code
        )
    return server


@pytest.fixture(scope="session")
def test_server_configuration(load_test_server_yaml) -> UDMServer:  # noqa: C901 # pragma: no cover
    """
    Get data of server used to run tests.

    :raises: BadTestServerConfig
    :raises: NoTestServerConfig
    """
    print(f"Trying to load test server config from {TEST_SERVER_YAML_FILENAME}...")
    try:
        res = load_test_server_yaml()
        print("Testing configuration in YAML file...")
        _test_a_server_configuration(res)
    except FileNotFoundError:
        print(f"File not found: {TEST_SERVER_YAML_FILENAME}.")
    except TypeError as exc:
        raise BadTestServerConfig(f"Error in {TEST_SERVER_YAML_FILENAME}: {exc!s}") from exc
    except udm_rest_client.exceptions.APICommunicationError as exc:
        raise BadTestServerConfig(
            f"Error connecting to test server using credentials "
            f"from {TEST_SERVER_YAML_FILENAME}: [{exc.status}] {exc.reason}"
        ) from exc
    else:
        print("OK: Using configuration in YAML file.")
        return res

    print("Trying to use test server config from environment...")
    try:
        res = UDMServer(
            host=os.environ["UCS_HOST"],
            username=parse_dn(os.environ["UCS_USERDN"])[0][1],
            user_dn=os.environ["UCS_USERDN"],
            password=os.environ["UCS_PASSWORD"],
        )
        _test_a_server_configuration(res)
    except (IndexError, KeyError):
        print("Test server config not found in environment.")
    except LDAPInvalidDnError as exc:
        raise BadTestServerConfig(f"Invalid DN in environment variable 'UCS_USERDN': {exc!s}")
    except udm_rest_client.exceptions.APICommunicationError as exc:
        raise BadTestServerConfig(
            f"Error connecting to test server using credentials from the "
            f"environment: [{exc.status}] {exc.reason}"
        ) from exc
    else:
        return res

    raise NoTestServerConfig("No test server configuration found.")


@attr.s(auto_attribs=True)  # using attr instead of dataclasses to remove dependency on Python 3.7+
class UserProperties:
    username: str
    password: str
    firstname: str
    lastname: str
    birthday: str
    disabled: bool
    #  groups: list


class UserPropertiesFactory(factory.Factory):
    class Meta:
        model = UserProperties

    username = factory.LazyFunction(
        lambda: f"{fake.first_name()}.{fake.last_name()}".lower()  # noqa: E501
    )
    password = factory.Faker(
        "password",
        length=10,
        special_chars=False,
        digits=True,
        upper_case=True,
        lower_case=True,
    )
    firstname = factory.Faker("first_name")
    lastname = factory.Faker("last_name")
    birthday = factory.LazyFunction(
        lambda: fake.date_of_birth(minimum_age=6, maximum_age=65).strftime("%Y-%m-%d")
    )
    disabled = False
    #  groups = []


@attr.s(auto_attribs=True)
class User:
    dn: str
    options: dict
    policies: dict
    position: str
    props: UserProperties
    superordinate: str
    uri: str
    uuid: str


class UserFactory(factory.Factory):
    class Meta:
        model = User

    dn = ""
    options = {}
    position = "cn=users,{base_dn}"
    policies = {}
    props = factory.SubFactory(UserPropertiesFactory)
    superordinate = None
    uri = factory.Faker("url")
    uuid = factory.Faker("uuid4")


class UsersUserUdmObjectFactory(factory.Factory):
    class Meta:
        model = udm_rest_client.base_http.UdmObject

    dn = ""
    uri = factory.Faker("url")
    uuid = factory.Faker("uuid4")
    options = factory.Dict({"default": True})
    policies = factory.List([factory.Faker("user_name")])
    superordinate = None
    position = ""
    props = factory.Dict({})

    @classmethod
    def _create(cls, model_class, user_data: User, *args, **kwargs):
        obj = model_class()
        for k, v in kwargs.items():
            setattr(obj, k, v)
        obj._udm_module = udm_rest_client.base_http.UdmModule(
            "users/user",
            udm_rest_client.base_http.Session("username", "password", "url"),
        )
        obj.position = user_data.position
        obj.dn = user_data.dn
        obj.props = user_data.props
        return obj


@pytest.fixture(scope="session")
def user_class() -> Type[User]:
    return User


@pytest.fixture
def fake_user(base_dn):
    def _func() -> User:
        user = UserFactory()
        user.position = user.position.format(base_dn=base_dn)
        user.dn = f"uid={user.props.username},{user.position}"
        return user

    return _func


@pytest.fixture(scope="session")
def ucs_ca_file_path():
    global ca_cert_path
    ucs_ca_ori_filename = "ucs-root-ca.crt"

    def _func(host) -> Optional[Path]:
        global ca_cert_path
        ca_cert_path = Path("/tmp/", f"{os.getpid()}_{host}_{ucs_ca_ori_filename}")
        resp = requests.get(f"http://{host}/{ucs_ca_ori_filename}")
        resp.raise_for_status()
        with open(ca_cert_path, "w") as fp:
            fp.write(resp.text)
        return ca_cert_path

    yield _func
    ca_cert_path.unlink()


@pytest.fixture(scope="session")
def udm_kwargs(test_server_configuration, ucs_ca_file_path) -> Dict[str, Any]:
    res = {
        "username": test_server_configuration.username,
        "password": test_server_configuration.password,
        "url": f"https://{test_server_configuration.host}/univention/udm",
        "safe_chars_for_path_param": "/",
        "ssl_ca_cert": str(ucs_ca_file_path(test_server_configuration.host)),
    }
    if not any(c in string.ascii_letters for c in test_server_configuration.host):
        # it's an IP address, don't try to verify the certificate even if we have the CA
        res["verify_ssl"] = False
    return res


@pytest.fixture(scope="session")
def ldap_connection_credentials(test_server_configuration) -> Dict[str, Any]:
    return {
        "bind_dn": test_server_configuration.user_dn,
        "bind_pw": test_server_configuration.password,
        "host": test_server_configuration.host,
        "port": UCS_LDAP_PORT,
    }


@pytest.fixture
def random_name() -> Callable[[], str]:
    return fake.first_name


@pytest.fixture
def ldap_connection(ldap_connection_credentials):
    defaults = {
        "host": ldap_connection_credentials["host"],
        "port": ldap_connection_credentials["port"],
        "get_info": "ALL",
        "user": ldap_connection_credentials["bind_dn"],
        "password": ldap_connection_credentials["bind_pw"],
        "auto_bind": AUTO_BIND_TLS_BEFORE_BIND,
        "authentication": SIMPLE,
    }

    def _func(
        server_kwargs: Dict[str, Any] = None, connection_kwargs: Dict[str, Any] = None
    ) -> Connection:
        server_kwargs = server_kwargs or {}
        for k in ("host", "port", "get_info"):
            server_kwargs[k] = server_kwargs.get(k, defaults[k])
        connection_kwargs = connection_kwargs or {}
        for k in ("user", "password", "auto_bind", "authentication"):
            connection_kwargs[k] = server_kwargs.get(k, defaults[k])
        connection_kwargs["server"] = Server(**server_kwargs)
        return Connection(**connection_kwargs)

    return _func


@lru_cache(maxsize=1)
def _get_base_dn(ldap_connection):
    with ldap_connection(connection_kwargs={"read_only": True}) as conn:
        return [c for c in conn.server.info.naming_contexts if c != "cn=translog"][0]


@pytest.fixture
def base_dn(ldap_connection) -> str:
    return _get_base_dn(ldap_connection)


@pytest.fixture
def user_resource_kwargs(fake_user):
    def _func() -> Dict[str, Any]:
        user_as_dict = attr.asdict(fake_user())
        user_as_dict["properties"] = user_as_dict.pop("props")
        return user_as_dict

    return _func


@pytest.fixture(scope="session")
def http_headers_read():
    return {"Accept": "application/json"}


@pytest.fixture(scope="session")
def http_headers_write():
    return {"Accept": "application/json", "Content-Type": "application/json"}


@pytest.fixture
def user_created_via_http(http_headers_write, udm_kwargs, user_resource_kwargs, delete_user_via_http):
    created_user_dns = []
    auth = (udm_kwargs["username"], udm_kwargs["password"])
    url = f"{udm_kwargs['url']}/users/user/"
    if udm_kwargs.get("verify_ssl", True):
        verify_ssl = udm_kwargs.get("ssl_ca_cert", False)  # pragma: no cover
    else:
        verify_ssl = False

    def _func(**user_kwargs) -> Tuple[str, str, Dict[str, Any]]:
        data = user_resource_kwargs()
        data.update(user_kwargs)

        resp = requests.post(url, headers=http_headers_write, json=data, auth=auth, verify=verify_ssl)
        print(resp.reason)
        try:
            print(resp.json())
        except (AttributeError, ValueError):  # pragma: no cover
            print(resp.text)
        assert resp.status_code in (201, 204)
        obj_url = resp.headers["Location"]
        dn = unquote(obj_url.rsplit("/", 1)[-1])
        created_user_dns.append(dn)
        return dn, obj_url, data

    yield _func

    for dn in created_user_dns:
        delete_user_via_http(dn)


@pytest.fixture
def modify_user_via_http(base_dn, http_headers_write, udm_kwargs):
    auth = (udm_kwargs["username"], udm_kwargs["password"])

    def _func(dn: str, user: User) -> None:
        url = f"{udm_kwargs['url']}/users/user/{dn}"
        data = dict((k, v) for k, v in attr.asdict(user).items() if v and k not in ("dn", "uri", "uuid"))
        properties = data.pop("props", {})
        data["properties"] = dict((k, v) for k, v in properties.items() if v)
        if udm_kwargs.get("verify_ssl", True):
            verify_ssl = udm_kwargs.get("ssl_ca_cert", False)  # pragma: no cover
        else:
            verify_ssl = False

        resp = requests.patch(url, headers=http_headers_write, json=data, auth=auth, verify=verify_ssl)
        assert resp.status_code == 204

    return _func


@pytest.fixture
def delete_user_via_http(base_dn, http_headers_read, udm_kwargs):
    auth = (udm_kwargs["username"], udm_kwargs["password"])
    if udm_kwargs.get("verify_ssl", True):
        verify_ssl = udm_kwargs.get("ssl_ca_cert", False)  # pragma: no cover
    else:
        verify_ssl = False

    def _func(dn: str) -> None:
        url = f"{udm_kwargs['url']}/users/user/{dn}"
        resp = requests.delete(url, headers=http_headers_read, auth=auth, verify=verify_ssl)
        assert resp.status_code in (204, 404)

    return _func


def pytest_generate_tests(metafunc):
    if "serialize_obj_data" in metafunc.fixturenames:
        an_int = fake.pyint()
        a_float = fake.pyfloat()
        a_date: datetime.date = fake.date_object()
        a_dict: Dict[str, Any] = fake.pydict(10, True, int, str, bool, float)
        a_dict["dict"] = {"nested_bool": fake.pybool(), "nested_int": fake.pyint()}
        a_dict["date"] = fake.date_object()
        a_dict["none"] = None
        a_dict["_ignoreme"] = fake.pyint()
        a_dict_exp = copy.deepcopy(a_dict)
        a_dict_exp["date"] = a_dict_exp["date"].strftime("%Y-%m-%d")
        del a_dict_exp["_ignoreme"]
        a_list: List[Any] = fake.pylist(10, True, int, str, bool, float)
        a_list.insert(2, fake.date_object())
        a_list_exp = copy.deepcopy(a_list)
        a_list_exp[2] = a_list_exp[2].strftime("%Y-%m-%d")
        a_tuple = fake.pytuple(10, True, int, str, bool, float)
        user = UserFactory()
        user.position = user.position.format(base_dn="dc=base,dc=dn")
        user.dn = f"uid={user.props.username},{user.position}"
        a_udm_obj = UsersUserUdmObjectFactory(user_data=user)
        an_api_obj = openapi_client_udm.models.users_user.UsersUser(
            dn=f"uid={fake.user_name()},{user.position}",
            object_type="users/user",
            properties={fake.first_name(): fake.last_name()},
            uri=fake.url(),
            uuid=fake.uuid4(),
        )
        test_data = [
            (None, None),
            (False, False),
            (True, True),
            (an_int, an_int),
            (a_float, a_float),
            (a_date, a_date.strftime("%Y-%m-%d")),
            (a_dict, a_dict_exp),
            (a_list, a_list_exp),
            (a_tuple, list(a_tuple)),
            (a_udm_obj, a_udm_obj.uri),
            (an_api_obj, an_api_obj.to_dict()),
            (Path("/tmp"), ValueError),
        ]
        random.shuffle(test_data)
        ids = [
            f"bool ({val_in})" if type(val_in) is bool else type(val_in).__name__
            for val_in, val_out in test_data
        ]
        metafunc.parametrize("serialize_obj_data", test_data, ids=ids)


@pytest.fixture
def new_cn(base_dn, http_headers_read, http_headers_write, udm_kwargs):
    """Create a new container"""
    created_cn_dns = []
    auth = (udm_kwargs["username"], udm_kwargs["password"])
    url = f"{udm_kwargs['url']}/container/cn/"
    if udm_kwargs.get("verify_ssl", True):
        verify_ssl = udm_kwargs.get("ssl_ca_cert", False)  # pragma: no cover
    else:
        verify_ssl = False

    def _func(**cn_kwargs) -> Tuple[str, str, Dict[str, str]]:
        data = {"properties": {"name": fake.city()}, "position": base_dn}
        data.update(cn_kwargs)
        resp = requests.post(url, headers=http_headers_write, json=data, auth=auth, verify=verify_ssl)
        print(resp.reason)
        try:
            print(resp.json())
        except (AttributeError, ValueError):  # pragma: no cover
            print(resp.text)
        assert resp.status_code in (201, 204)
        obj_url = resp.headers["Location"]
        dn = unquote(obj_url.rsplit("/", 1)[-1])
        created_cn_dns.append(dn)
        assert dn == f"cn={data['properties']['name']},{data['position']}"
        return dn, obj_url, data

    yield _func

    for dn in created_cn_dns:
        url = f"{url}{dn}"
        resp = requests.delete(url, headers=http_headers_read, auth=auth, verify=verify_ssl)
        assert resp.status_code in (204, 404)
