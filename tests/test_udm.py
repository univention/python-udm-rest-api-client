# -*- coding: utf-8 -*-

"""Tests for `udm_rest_client.udm` module."""

import asyncio
import logging
import random

import pytest

from udm_rest_client.base_http import UdmModule
from udm_rest_client.exceptions import UnknownModuleType
from udm_rest_client.udm import UDM

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-5s [%(name)s.%(funcName)s:%(lineno)d] %(message)s",
)
logger = logging.getLogger(__name__)
BAD_MODULE_NAMES = ("policies/admin_user", "policies/thinclient", "settings/data")


@pytest.mark.asyncio
async def test_session_closes_on_context_exit(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        assert not udm.session.session.closed
    with pytest.raises(RuntimeError):
        print(udm.session.session)


@pytest.mark.asyncio
async def test_repeated_session_open(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        udm.session.open()


@pytest.mark.asyncio
async def test_get_module(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        for name in ("groups/group", "shares/share", "users/user"):
            mod = udm.get(name)
            assert isinstance(mod, UdmModule)
            assert mod.name == name


@pytest.mark.asyncio
async def test_get_module_bad_module_name(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        with pytest.raises(UnknownModuleType):
            udm.get("unkn/own")


@pytest.mark.asyncio
async def test_obj_by_dn(base_dn, ldap_connection, udm_kwargs):
    async def load_obj_by_dn(udm, result):
        dn = result.entry_dn
        object_type = result["univentionObjectType"].value
        uuid = result["entryUUID"].value

        obj = await udm.obj_by_dn(dn)
        assert obj.dn == dn
        assert obj._udm_module.name == object_type
        assert obj.uuid == uuid
        return obj

    with ldap_connection(connection_kwargs={"read_only": True}) as conn:
        logger.info("Successful LDAP login.")
        conn.search(
            search_base=base_dn,
            search_filter="(&" "(univentionObjectType=*)" "(!(univentionObjectFlag=functional))" ")",
            attributes=["univentionObjectType", "univentionObjectFlag", "entryUUID"],
        )
    all_objs = {}
    async with UDM(**udm_kwargs) as udm:
        # test one object per udm module
        for result in conn.entries:
            object_type = result["univentionObjectType"].value
            if object_type not in BAD_MODULE_NAMES and "://" not in result.entry_dn:  # Bug #50175
                all_objs.setdefault(object_type, []).append(result)
        module_names = [str(m) for m in all_objs.keys()]
        # ignore for now: Bug 54064 - UDM REST API does not handle nagios/service objects
        # HTTP 500 - RuntimeError: Object was not opened
        module_names = [m for m in module_names if m != "nagios/service"]
        random.shuffle(module_names)
        logger.info("Reading %d objects of different UDM module types...", len(module_names))
        entries = [random.choice(all_objs[module_name]) for module_name in module_names]
        objs = await asyncio.gather(*(load_obj_by_dn(udm, entry) for entry in entries))
        for entry, obj in zip(entries, objs):
            assert entry.entry_dn == obj.dn


def test_version():
    assert UDM("A", "B", "C").version(23).api_version == 23


@pytest.mark.asyncio
async def test_modules_list(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        modules_list = await udm.modules_list()
        assert set(modules_list).issuperset({"appcenter/app", "groups/group", "users/user"})


@pytest.mark.asyncio
async def test_unknown_modules(udm_kwargs):
    async with UDM(**udm_kwargs) as udm:
        modules_list = await udm.unknown_modules()
        # work around Bug 54063 - UDM REST API doesn't handle ms/* (MS group policy) objects / modules
        modules_list = [x for x in modules_list if not x.startswith("ms/")]
        # if this fails, you probably have to rebuild the OpenAPI client lib: ./update_openapi_client ...
        assert modules_list == []
