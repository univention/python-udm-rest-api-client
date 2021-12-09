# -*- coding: utf-8 -*-

"""Tests for `udm_rest_client.base_http` module."""

import copy
import datetime
import inspect
import io
import logging
import re
import sys
import warnings
from unittest.mock import MagicMock, patch
from urllib.parse import unquote

import attr
import faker
import pytest
from ldap3 import NO_ATTRIBUTES

import udm_rest_client.base_http as base_http
from udm_rest_client.base_http import _ldap_base_cache
from udm_rest_client.exceptions import (
    APICommunicationError,
    ConfigurationError,
    CreateError,
    DeletedError,
    MethodNotSupportedError,
    ModifyError,
    MoveError,
    NoObject,
    NotYetSavedError,
    UnknownModuleType,
)
from udm_rest_client.udm import UDM

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-5s [%(module)s.%(funcName)s:%(lineno)d] %(message)s",
)
logger = logging.getLogger(__name__)
fake = faker.Faker()
PY38 = sys.version_info >= (3, 8)


def test_is_api_model():
    from openapi_client_udm.models.appcenter_app import AppcenterApp

    assert base_http._is_api_model(AppcenterApp) is True
    assert base_http._is_api_model(UDM) is False


@pytest.mark.asyncio
async def test_dn_property_encoder_checks_module_name(random_name):
    dn = random_name()
    str_prop = base_http.DnPropertyEncoder(random_name(), dn, random_name(), random_name()).decode()
    assert str(str_prop) == dn
    with pytest.raises(UnknownModuleType):
        await str_prop.obj


@pytest.mark.parametrize("input_data,expected", [(None, None), ("", None)], ids=["None", "''"])
def test_dn_property_encoder_handles_empty_dn(random_name, input_data, expected):
    dn = input_data
    str_prop = base_http.DnPropertyEncoder(random_name(), dn, random_name(), random_name()).decode()
    assert str_prop is None


@pytest.mark.asyncio
async def test_deepcopy_object(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)
    assert obj.dn == dn
    assert obj.uri == url
    assert obj.position == user["position"]
    assert obj.props.firstname == user["properties"]["firstname"]
    assert obj.props.lastname == user["properties"]["lastname"]
    assert obj.props.birthday == user["properties"]["birthday"]

    obj2 = copy.deepcopy(obj)
    assert isinstance(obj, base_http.UdmObject)
    assert isinstance(obj2, base_http.UdmObject)
    assert isinstance(obj.dn, str)
    assert isinstance(obj2.dn, str)
    assert isinstance(obj.options, dict)
    assert isinstance(obj2.options, dict)
    assert isinstance(obj.policies, dict)
    assert isinstance(obj2.policies, dict)
    assert isinstance(obj.position, str)
    assert isinstance(obj2.position, str)
    assert isinstance(obj.props, base_http.UdmObjectProperties)
    assert isinstance(obj2.props, base_http.UdmObjectProperties)
    assert isinstance(obj.superordinate, (str, type(None)))
    assert isinstance(obj2.superordinate, (str, type(None)))
    for k in ("dn", "options", "policies", "position", "superordinate"):
        assert getattr(obj, k) == getattr(obj2, k)
    for k, v in obj.props._to_dict().items():
        assert getattr(obj.props, k) == getattr(obj2.props, k)


@pytest.mark.asyncio
async def test_good_credentials(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)
        assert obj.props.firstname == user["properties"]["firstname"]


@pytest.mark.asyncio
async def test_bad_credentials(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()
    bad_kwargs = udm_kwargs.copy()
    bad_kwargs["password"] = f"A{udm_kwargs['password']}B"
    async with UDM(**bad_kwargs) as udm:
        mod = udm.get("users/user")
        with pytest.raises(APICommunicationError) as exc_info:
            await mod.get(dn)
        assert exc_info.value.status == 401


def test_serialize_obj(serialize_obj_data):
    # pytest.mark.parametrize done in conftest.pytest_generate_tests()
    test_input, expected = serialize_obj_data

    if inspect.isclass(expected) and issubclass(expected, Exception):
        with pytest.raises(expected):
            base_http._serialize_obj(test_input)
    else:
        result = base_http._serialize_obj(test_input)
        assert result == expected


@pytest.mark.asyncio
async def test_openapi_class(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        for name in ("groups/group", "shares/share", "users/user"):
            mod = udm.get(name)
            kls = mod.session.openapi_class(name)
            assert inspect.isclass(kls)
            assert kls.__name__.endswith("Api")


@pytest.mark.asyncio
async def test_udm_module_module_unknown(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        for name in (f"groups/{fake.pystr()}", fake.pystr()):
            with pytest.raises(UnknownModuleType):
                udm.get(name)


@pytest.mark.asyncio
async def test_udm_openapi_class_unknown(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        for name in (f"groups/{fake.pystr()}", fake.pystr()):
            with pytest.raises(UnknownModuleType):
                udm.session.openapi_class(name)


@pytest.mark.asyncio
async def test_operation_not_supported(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        for name in ("dns/dns", "settings/lock", "users/self"):
            mod = udm.get(name)
            with pytest.raises(MethodNotSupportedError):
                await mod.new()


@pytest.mark.asyncio
async def test_openapi_method(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        for name in ("groups/group", "shares/share", "users/user"):
            mod = udm.get(name)
            kls = mod.session.openapi_class(name)
            name_snake_case = "_".join(s.lower() for s in name.split("/"))
            for meth in base_http.METHOD_NAMES.values():
                assert hasattr(kls, meth.format(name_snake_case))


@pytest.mark.asyncio
async def test_get(random_name):
    val = random_name()

    async def _func():  # pragma: no-cover-py-gte-38
        return val

    with patch.object(base_http.UdmModule, "_load_udm_object") as load_mock:
        if PY38:  # pragma: no-cover-py-lt-38
            load_mock.return_value = val
        else:  # pragma: no-cover-py-gte-38
            load_mock.return_value = _func()
        foo = await base_http.UdmModule("users/user", MagicMock()).get("foo")
        assert foo == val


@pytest.mark.asyncio
async def test_get_none():
    with pytest.raises(ValueError):
        await base_http.UdmModule("users/user", MagicMock()).get(None)


@pytest.mark.asyncio
async def test_dn_property_encoder(random_name):
    val = random_name()

    async def _func():  # pragma: no-cover-py-gte-38
        return val

    property_name = random_name()
    dn = random_name()
    session = MagicMock()
    udm_module = "users/user"
    with patch.object(base_http.UdmModule, "_load_udm_object") as load_mock:
        if PY38:  # pragma: no-cover-py-lt-38
            load_mock.return_value = val
        else:  # pragma: no-cover-py-gte-38
            load_mock.return_value = _func()
        str_prop = base_http.DnPropertyEncoder(property_name, dn, session, udm_module).decode()
        assert hasattr(str_prop, "obj")
        obj = await str_prop.obj
        load_mock.assert_called_with(dn)
        assert obj == val


@pytest.mark.asyncio
async def test_session_base_dn(base_dn, udm_kwargs):
    base_dn_via_ldap = base_dn

    async with UDM(**udm_kwargs) as udm:
        base_dn_via_http = await udm.session.base_dn

    assert base_dn_via_http == base_dn_via_ldap


@pytest.mark.asyncio
async def test_new_user(base_dn, udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.new()
    assert obj.dn is None
    assert obj.uri == ""
    assert obj.position == f"cn=users,{base_dn}"
    assert obj.props.firstname is None
    assert obj.props.groups == []
    assert obj.props.primaryGroup == f"cn=Domain Users,cn=groups,{base_dn}"
    assert obj.props.shell == "/bin/bash"


@pytest.mark.asyncio
async def test_get_user(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)
    assert obj.dn == dn
    assert obj.uri == url
    assert "policies/umc" in obj.policies
    assert obj.position == user["position"]
    assert obj.props.firstname == user["properties"]["firstname"]
    assert obj.props.lastname == user["properties"]["lastname"]
    assert obj.props.birthday == user["properties"]["birthday"]


@pytest.mark.asyncio
async def test_get_no_object(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()
    dn_parts = dn.split(",")
    wrong_dn = f"{dn_parts[0]}a,{','.join(dn_parts[1:])}"

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        with pytest.raises(NoObject):
            await mod.get(wrong_dn)


@pytest.mark.asyncio
async def test_dn_property_encoder_user_group_obj(user_created_via_http, udm_kwargs, base_dn):
    dn, url, user = user_created_via_http()

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)
        assert obj.dn == dn
        assert obj.uri == url
        primary_group = obj.props.primaryGroup
        assert str(primary_group).startswith("cn=")
        assert str(primary_group).endswith(base_dn)
        assert hasattr(primary_group, "obj")
        primary_group_obj = await primary_group.obj
        assert isinstance(primary_group_obj, base_http.UdmObject)
        assert primary_group_obj.dn == str(primary_group)
        assert dn in primary_group_obj.props.users


@pytest.mark.asyncio
async def test_reload_user(
    user_created_via_http, modify_user_via_http, udm_kwargs, user_class, random_name
):
    dn, url, user = user_created_via_http()

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)
        assert obj.dn == dn
        assert obj.uri == url
        assert obj.position == user["position"]
        assert obj.props.firstname == user["properties"]["firstname"]
        assert obj.props.lastname == user["properties"]["lastname"]
        assert obj.props.birthday == user["properties"]["birthday"]

        user_mod_data = user_class(
            dn="",
            options=None,
            policies=None,
            position=None,
            props={"firstname": random_name(), "lastname": random_name()},
            superordinate=None,
            uri="",
            uuid="",
        )
        modify_user_via_http(dn, user_mod_data)

        res = await obj.reload()
        assert res is obj
        assert obj.dn == dn
        assert obj.uri == url
        assert obj.position == user["position"]
        assert obj.props.firstname == user_mod_data.props["firstname"]
        assert obj.props.lastname == user_mod_data.props["lastname"]
        assert obj.props.birthday == user["properties"]["birthday"]

        obj_new = await mod.get(dn)
        assert obj_new.dn == obj.dn
        assert obj_new.uri == obj.uri
        assert obj_new.position == obj.position
        assert obj_new.props.firstname == obj.props.firstname
        assert obj_new.props.lastname == obj.props.lastname
        assert obj_new.props.birthday == obj.props.birthday


@pytest.mark.asyncio
async def test_reload_new_obj(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.new()
        assert obj.dn is None
        assert obj.uri == ""
        with pytest.raises(NotYetSavedError):
            await obj.reload()


@pytest.mark.asyncio
async def test_create_user(fake_user, udm_kwargs):
    user_data = fake_user()
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.new()
        obj.policies = user_data.policies
        obj.superordinate = user_data.superordinate
        obj.position = user_data.position
        obj.options = user_data.options
        for k, v in attr.asdict(user_data.props).items():
            setattr(obj.props, k, v)
        assert obj.dn is None
        assert obj.uri == ""

        res = await obj.save()

        assert res is obj
        assert obj.dn not in (None, "")
        assert obj.uri not in (None, "")

        obj_new = await mod.get(obj.dn)
        assert obj_new.dn == obj.dn
        assert obj_new.position == obj.position
        assert obj_new.props.firstname == obj.props.firstname
        assert obj_new.props.lastname == obj.props.lastname
        assert obj_new.props.birthday == obj.props.birthday

        await obj.delete()


@pytest.mark.asyncio
async def test_creating_obj_with_bad_property_value(fake_user, udm_kwargs):
    user_data = fake_user()
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.new()
        obj.policies = user_data.policies
        obj.superordinate = user_data.superordinate
        obj.position = user_data.position
        obj.options = user_data.options
        for k, v in attr.asdict(user_data.props).items():
            setattr(obj.props, k, v)
        obj.props.birthday = fake.pystr()
        with pytest.raises(CreateError):
            await obj.save()


@pytest.mark.asyncio
async def test_modify_user(fake_user, user_created_via_http, udm_kwargs):
    old_user_dn, old_user_url, old_user_data = user_created_via_http()
    new_user_data = fake_user()
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(old_user_dn)
        assert obj.dn == old_user_dn
        assert obj.uri == old_user_url
        assert obj.position == old_user_data["position"]
        assert obj.props.firstname == old_user_data["properties"]["firstname"]
        assert obj.props.lastname == old_user_data["properties"]["lastname"]
        assert obj.props.birthday == old_user_data["properties"]["birthday"]

        obj.policies = new_user_data.policies
        modify_props = attr.asdict(new_user_data.props)
        del modify_props["username"]  # not testing move here
        for k, v in modify_props.items():
            setattr(obj.props, k, v)
        res = await obj.save()
        assert res is obj
        assert obj.dn == old_user_dn
        assert obj.uri == old_user_url
        policies = {
            "policies/desktop": [],
            "policies/pwhistory": [],
            "policies/umc": [],
        }
        assert obj.policies == policies
        for k, v in modify_props.items():
            if k == "password":
                v = None
            assert getattr(obj.props, k) == v

        obj_new = await mod.get(old_user_dn)
        assert obj_new.dn == old_user_dn
        assert obj_new.uri == old_user_url
        assert obj_new.policies == policies
        for k, v in modify_props.items():
            if k == "password":
                v = None
            assert getattr(obj_new.props, k) == v


@pytest.mark.asyncio
async def test_add_attribute_of_previously_deactivated_option(
    http_headers_write, test_server_configuration, udm_kwargs
):
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("shares/share")
        obj = await mod.new()
        obj.options = {"samba": True}
        obj.props.name = fake.first_name()
        obj.props.host = "file.example.com"
        obj.props.path = f"/home/share{fake.first_name()}"
        await obj.save()

        obj_new = await mod.get(obj.dn)
        assert obj_new.props.name == obj.props.name
        if obj.options.get("nfs") is True:
            # handle http://forge.univention.org/bugzilla/show_bug.cgi?id=50974
            print("NFS enabled by default :/")
            import requests

            auth = (udm_kwargs["username"], udm_kwargs["password"])
            if udm_kwargs.get("verify_ssl", True):
                verify_ssl = udm_kwargs.get("ssl_ca_cert", False)  # pragma: no cover
            else:
                verify_ssl = False
            resp = requests.patch(
                obj_new.uri,
                headers=http_headers_write,
                auth=auth,
                verify=verify_ssl,
                json={"options": {"samba": True, "nfs": False}},
            )
            print(resp.reason)
            try:
                print(resp.json())
            except (AttributeError, ValueError):  # pragma: no cover
                print(resp.text)
            assert resp.status_code in (201, 204)
            obj_new = await mod.get(obj.dn)
        assert obj_new.options.get("samba") is True
        assert obj_new.options.get("nfs") is False
        assert not hasattr(obj_new.props, "root_squash")

        obj_new.options["nfs"] = True
        obj_new.props.root_squash = True
        await obj_new.save()

        obj_new2 = await mod.get(obj_new.dn)
        assert obj_new2.options.get("nfs") is True
        assert hasattr(obj_new2.props, "root_squash")
        assert obj.props.root_squash is True


@pytest.mark.asyncio
async def test_move_user_no_props_changed(new_cn, user_created_via_http, udm_kwargs):
    old_user_dn, old_user_url, old_user_data = user_created_via_http()
    cn_dn, cn_obj_url, cn_data = new_cn()
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(old_user_dn)
        assert obj.dn == old_user_dn
        assert obj.uri == old_user_url
        assert obj.position == old_user_data["position"]
        assert obj.props.firstname == old_user_data["properties"]["firstname"]

        obj.position = cn_dn
        res = await obj.save()
        assert res is obj
        assert obj.dn != old_user_dn
        assert obj.dn == f"uid={obj.props.username},{cn_dn}"
        assert obj.uri != old_user_url

        assert unquote(obj.uri) == old_user_url.rsplit("/", 1)[0] + "/" + obj.dn

        obj_new = await mod.get(obj.dn)
        assert obj_new.dn == obj.dn
        assert obj_new.uri == obj.uri
        assert obj_new.position == cn_dn
        assert obj.props.firstname == old_user_data["properties"]["firstname"]


@pytest.mark.asyncio
async def test_move_and_modify_user(new_cn, user_created_via_http, udm_kwargs):
    old_user_dn, old_user_url, old_user_data = user_created_via_http()
    cn_dn, cn_obj_url, cn_data = new_cn()
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(old_user_dn)
        assert obj.dn == old_user_dn
        assert obj.uri == old_user_url
        assert obj.position == old_user_data["position"]
        assert obj.props.firstname == old_user_data["properties"]["firstname"]

        obj.position = cn_dn
        new_description = fake.text(max_nb_chars=50)
        obj.props.description = new_description
        new_lastname = fake.last_name()
        obj.props.lastname = new_lastname
        res = await obj.save()
        assert res is obj
        assert obj.dn != old_user_dn
        assert obj.dn == f"uid={obj.props.username},{cn_dn}"
        assert obj.uri != old_user_url

        assert unquote(obj.uri) == old_user_url.rsplit("/", 1)[0] + "/" + obj.dn

        obj_new = await mod.get(obj.dn)
        assert obj_new.dn == obj.dn
        assert obj_new.uri == obj.uri
        assert obj_new.position == cn_dn
        assert obj.props.firstname == old_user_data["properties"]["firstname"]
        assert obj.props.lastname == new_lastname
        assert obj.props.description == new_description


@pytest.mark.asyncio
async def test_move_multiple_objects(base_dn, new_cn, user_created_via_http, udm_kwargs):
    top_cn_dn, top_cn_obj_url, top_cn_data = new_cn()
    old_cn_dn, old_cn_obj_url, old_cn_data = new_cn(position=top_cn_dn)
    cn_name = old_cn_data["properties"]["name"]
    users = dict((num, user_created_via_http(position=old_cn_dn)) for num in range(20))
    with patch.object(base_http, "MIN_FOLLOW_REDIRECT_SLEEP_TIME", 3.0):
        async with UDM(**udm_kwargs) as udm:
            mod_user = udm.get("users/user")
            for dn, url, data in users.values():
                user_obj = await mod_user.get(dn)
                assert user_obj.position == old_cn_dn

            mod_cn = udm.get("container/cn")
            cn_obj = await mod_cn.get(old_cn_dn)
            assert cn_obj.dn == old_cn_dn
            assert cn_obj.dn != base_dn

            cn_obj.position = base_dn
            await cn_obj.save()

            assert cn_obj.dn == f"cn={cn_name},{base_dn}"

            for dn, url, data in users.values():
                query = dn.split(",", 1)[0]
                async for obj in mod_user.search(query):
                    assert old_cn_dn not in obj.dn
                    assert obj.position == cn_obj.dn
                    assert obj.dn == f"uid={data['properties']['username']},{cn_obj.dn}"


@pytest.mark.asyncio
async def test_move_error(base_dn, random_name, user_created_via_http, udm_kwargs):
    old_user_dn, old_user_url, old_user_data = user_created_via_http()
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(old_user_dn)
        assert obj.dn == old_user_dn
        assert obj.uri == old_user_url
        obj.position = f"cn={random_name},{base_dn}"
        with pytest.raises(MoveError):
            await obj.save()


@pytest.mark.asyncio
async def test_delete_user(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)
        assert obj.dn == dn
        assert obj.props.firstname == user["properties"]["firstname"]

        res = await obj.delete()
        assert res is None
        assert obj.dn == dn

        with pytest.raises(DeletedError):
            await obj.reload()

        with pytest.raises(DeletedError):
            await obj.save()

        # nothing should happen
        await obj.delete()


@pytest.mark.asyncio
async def test_delete_unsaved_user(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.new()
        with pytest.raises(NotYetSavedError):
            await obj.delete()


@pytest.mark.asyncio
async def test_delete_non_existent_user_is_ignored(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj1 = await mod.get(dn)
        obj2 = await mod.get(dn)
        await obj1.delete()
        with pytest.raises(NoObject):
            await mod.get(dn)
        await obj2.delete()


@pytest.mark.asyncio
async def test_saving_stale_obj_fails(user_created_via_http, udm_kwargs, random_name):
    # scenario: a different channel was used to delete or rename the obj on
    # the server directly after saving it, so that a reload() fails, then it
    # should not be possible to save() again
    dn, url, user = user_created_via_http()

    async def _func():
        pass

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)
        assert obj.dn == dn
        assert obj.uri == url
        assert obj.props.firstname == user["properties"]["firstname"]
        # OK, got a valid object from LDAP, now modify it but skip the reload
        obj.props.firstname = random_name()
        obj.reload = _func
        await obj.save()
        obj.props.firstname = random_name()

        with warnings.catch_warnings(record=True) as caught_warnings:
            await obj.save()
        assert base_http.StaleObjectWarning in [w.category for w in caught_warnings]


@pytest.mark.asyncio
async def test_saving_obj_with_bad_property_value(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)
        assert obj.dn == dn
        assert obj.uri == url
        assert obj.props.firstname == user["properties"]["firstname"]
        # OK, got a valid object from LDAP, now modify it but skip the reload
        obj.props.birthday = fake.pystr()
        with pytest.raises(ModifyError):
            await obj.save()


@pytest.mark.asyncio
async def test_to_dict_user(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)
        assert obj.dn == dn
        assert obj.props.lastname == user["properties"]["lastname"]
        assert obj.props.birthday == user["properties"]["birthday"]
        obj.props.birthday = datetime.date(1987, 6, 1)
        dict_repr = obj.to_dict()
        for k in ("dn", "options", "policies", "position", "superordinate", "uuid"):
            assert dict_repr[k] == getattr(obj, k)
        for k, v in dict_repr["props"].items():
            if k == "birthday":
                assert v == obj.props.birthday.strftime("%Y-%m-%d")
                continue
            assert v == getattr(obj.props, k)


@pytest.mark.asyncio
async def test_search_existing_user(user_created_via_http, udm_kwargs):
    dn, url, data = user_created_via_http()
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        query = dn.split(",", 1)[0]
        async for obj in mod.search(query):
            assert obj.dn == dn
            assert obj.uri == url
            assert obj.position == data["position"]
            assert obj.props.firstname == data["properties"]["firstname"]
            assert obj.props.lastname == data["properties"]["lastname"]


@pytest.mark.asyncio
async def test_search_at_dn(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        with pytest.raises(ValueError):
            [_ async for _ in mod.search(base=dn, scope=fake.pystr())]
        async for obj in mod.search(base=dn, scope="base"):
            assert obj.dn == dn
            assert obj.uri == url
            assert obj.position == user["position"]
            assert obj.props.firstname == user["properties"]["firstname"]
            assert obj.props.lastname == user["properties"]["lastname"]


@pytest.mark.asyncio
async def test_search_not_existing_user(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        query = f"uid={fake.user_name()}"
        assert [obj async for obj in mod.search(query)] == []


@pytest.mark.asyncio
async def test_search_all_users(base_dn, ldap_connection, udm_kwargs):
    with ldap_connection(connection_kwargs={"read_only": True}) as conn:
        logger.info("Successful LDAP login.")
        conn.search(
            search_base=base_dn,
            search_filter="(univentionObjectType=users/user)",
            attributes=[NO_ATTRIBUTES],
        )
    dns_via_ldap = {result.entry_dn for result in conn.entries}

    dns_via_udm_http = set()
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        async for obj in mod.search():
            dns_via_udm_http.add(obj.dn)

    assert any(dn.startswith("uid=Administrator") for dn in dns_via_udm_http)
    assert dns_via_ldap == dns_via_udm_http


@pytest.mark.asyncio
async def test_meta():
    mod = UDM("A", "B", "C").get("shares/share")
    assert isinstance(mod.meta, base_http.UdmModuleMetadata)
    assert mod.meta.used_api_version in base_http.UdmModule.meta.supported_api_versions


@pytest.mark.asyncio
async def test_object_repr(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        mod_name = "users/user"
        mod = udm.get(mod_name)
        mod_repr = repr(mod)
        assert mod_repr == f"UdmModule({mod_name!r})"
        meta_repr = repr(mod.meta)
        assert meta_repr.startswith("UdmModuleMetadata(")
        assert "supported_api_versions" in meta_repr
        async for obj in mod.search():
            obj_repr = repr(obj)
            assert obj_repr == f"UdmObject({mod_name!r}, {obj.dn!r})"
            props_repr = repr(obj.props)
            assert props_repr.startswith("UdmObjectProperties(")
            assert "username" in props_repr
            assert "firstname" in props_repr
            assert len(props_repr.split("\n")) > 10
            break


def test_session_warn_min_client_tasks():
    for i in range(-10, 10):
        with warnings.catch_warnings(record=True) as w:
            udm = UDM("A", "B", "https://foo.bar/baz", max_client_tasks=i)
            assert udm.session.max_client_tasks >= 4
            assert (
                udm.session.openapi_client_config.connection_pool_maxsize >= udm.session.max_client_tasks
            )
            if i < 4:
                assert len(w) == 1
                assert issubclass(w[-1].category, base_http.BadSettingsWarning)
                assert "max_client_tasks" in str(w[-1].message)


def test_session_warn_min_connection_pool_maxsize():
    for i in range(4, 10):
        with warnings.catch_warnings(record=True) as w:
            udm = UDM(
                "A",
                "B",
                "https://foo.bar/baz",
                max_client_tasks=i,
                connection_pool_maxsize=i - 1,
            )
            assert (
                udm.session.openapi_client_config.connection_pool_maxsize >= udm.session.max_client_tasks
            )
            assert len(w) == 1
            assert issubclass(w[-1].category, base_http.BadSettingsWarning)
            assert "connection_pool_maxsize" in str(w[-1].message)


def test_session_warn_insecure_request():
    for i in range(4, 10):
        with warnings.catch_warnings(record=True) as w:
            UDM("A", "B", "http://foo.bar/baz")
            assert len(w) == 1
            assert issubclass(w[-1].category, base_http.InsecureRequestWarning)
            assert "unencrypted" in str(w[-1].message)


def test_session_with_bad_arg():
    with pytest.raises(ConfigurationError):
        UDM("A", "B", "C", foo="bar")


def test_session_openapi_model():
    session = UDM("A", "B", "C").session
    assert session.openapi_model("users/user").__name__ == "UsersUser"
    with pytest.raises(UnknownModuleType):
        session.openapi_model(f"{fake.pystr()}/{fake.pystr()}")


@pytest.mark.asyncio
async def test_udm_obj_by_dn_no_univention_type(udm_kwargs, base_dn):
    dn = f"cn=backup,{base_dn}"
    async with UDM(**udm_kwargs) as udm:
        with pytest.raises(NoObject):
            await udm.obj_by_dn(dn)


@pytest.mark.asyncio
async def test_udm_obj_by_dn_good_dn(udm_kwargs, user_created_via_http):
    dn, url, user = user_created_via_http()
    async with UDM(**udm_kwargs) as udm:
        obj = await udm.obj_by_dn(dn)
    assert obj.dn == dn
    assert obj.uri == url
    assert obj.position == user["position"]
    assert obj.props.firstname == user["properties"]["firstname"]
    assert obj.props.lastname == user["properties"]["lastname"]


@pytest.mark.asyncio
async def test_session_get_json_bad_url(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        url = f"{udm_kwargs['url']}/{fake.user_name()}/{fake.user_name()}"
        with pytest.raises(NoObject):
            await udm.session.get_json(url, ssl=False)


@pytest.mark.asyncio
async def test_session_get_json_no_password_in_log(udm_kwargs):
    logger = logging.getLogger(base_http.logger.name)
    logger.setLevel(logging.DEBUG)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-5s %(module)s.%(funcName)s:%(lineno)d  %(message)s"
        )
    )
    logger.addHandler(handler)
    txt = fake.pystr()
    logger.debug(txt)
    handler.flush()
    stream.seek(0)
    stream_content = stream.read()
    assert txt in stream_content
    stream_index = stream.tell()

    with patch.object(base_http, "logger", logger):
        async with UDM(**udm_kwargs) as udm:
            _ldap_base_cache.pop(udm.session.openapi_client_config.host, None)  # clear cache
            await udm.session.base_dn
    handler.flush()
    logger.removeHandler(handler)
    stream.seek(stream_index)
    stream_content = stream.read()
    assert "base_http.get_json" in stream_content
    assert "ldap/base" in stream_content
    assert "application/json" in stream_content
    m = re.match(r".*(auth.: \(.*?\))", stream_content)
    assert m
    assert m.groups()
    auth_txt = m.groups()[0]
    assert udm.session.openapi_client_config.username in auth_txt
    assert udm.session.openapi_client_config.password not in auth_txt


@pytest.mark.asyncio
async def test_bad_module_name(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        with pytest.raises(UnknownModuleType):
            await udm.get(f"{fake.pystr()}")


@pytest.mark.asyncio
async def test_get_users_self_redirects_to_users_user(udm_kwargs, test_server_configuration):
    administrator_dn = test_server_configuration.user_dn

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/self")
        obj = await mod.get(administrator_dn)
    assert obj.dn == administrator_dn
    assert obj.props.username == "Administrator"
    assert obj._udm_module.name == "users/user"


@pytest.mark.asyncio
async def test_modify_users_self_redirects_to_users_user(
    udm_kwargs, test_server_configuration, random_name
):
    administrator_dn = test_server_configuration.user_dn
    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/self")
        obj = await mod.get(administrator_dn)
        assert obj.dn == administrator_dn
        assert obj.props.username == "Administrator"
        assert obj._udm_module.name == "users/user"

        obj._udm_module = mod
        new_fn = f"Admin {random_name()}"
        obj.props.firstname = new_fn
        res = await obj.save()
        assert res is obj
        assert obj.dn == administrator_dn
        assert obj.props.username == "Administrator"
        assert obj._udm_module.name == "users/user"

        mod = udm.get("users/user")
        obj = await mod.get(administrator_dn)
        assert obj.props.firstname == new_fn


@pytest.mark.asyncio
async def test_obj_eq(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj2 = await mod.get(dn)

    assert obj == obj2

    for attri in ("uri", "uuid"):
        ori_val = getattr(obj, attri)
        setattr(obj, attri, fake.pystr())
        assert obj != obj2
        setattr(obj, attri, ori_val)
        assert obj == obj2
