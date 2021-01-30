import random

import attr
import faker
import pytest

from udm_rest_client.udm import UDM

fake = faker.Faker()


@pytest.mark.asyncio
async def test_base_obj_eq(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj2 = await mod.get(dn)

    assert obj == obj2

    for attri in ("dn", "policies", "position", "superordinate"):
        ori_val = getattr(obj, attri)
        setattr(obj, attri, fake.pystr())
        assert obj != obj2
        setattr(obj, attri, ori_val)
        assert obj == obj2

    opt = fake.pystr()
    obj.options[opt] = fake.pystr()
    assert obj != obj2
    del obj.options[opt]
    assert obj == obj2

    attri = "firstname"
    ori_val = getattr(obj.props, "firstname")
    setattr(obj.props, attri, fake.pystr())
    assert obj != obj2
    setattr(obj.props, attri, ori_val)
    assert obj == obj2

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("groups/group")
        async for obj3 in mod.search():
            break
        assert obj3
    assert obj != obj3


@pytest.mark.asyncio
async def test_base_obj_props_eq(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj2 = await mod.get(dn)

    assert obj == obj2

    for attri in ("firstname", "lastname", "username", "birthday"):
        ori_val = getattr(obj.props, attri)
        setattr(obj.props, attri, fake.pystr())
        assert obj != obj2
        setattr(obj.props, attri, ori_val)
        assert obj == obj2

    setattr(obj.props, "_underscore", fake.pystr())
    assert obj.props == obj2.props
    assert obj == obj2

    missing_attr = random.choice(list(obj.props.keys()))
    delattr(obj.props, missing_attr)
    assert obj.props != obj2.props
    assert obj != obj2


@pytest.mark.asyncio
async def test_base_obj_props_in(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)
    for attri in ("firstname", "lastname", "username", "birthday"):
        assert attri in obj.props
    assert fake.pystr() not in obj.props


@pytest.mark.asyncio
async def test_base_obj_props_getitem(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)
    assert user["properties"]["lastname"] == obj.props["lastname"]
    assert user["properties"]["lastname"] == obj.props.get("lastname")
    with pytest.raises(KeyError):
        _ = obj.props[fake.pystr()]


@pytest.mark.asyncio
async def test_base_obj_props_setitem(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)
    new_val = fake.pystr()
    obj.props["lastname"] = new_val
    assert obj.props.lastname == new_val
    with pytest.raises(TypeError):
        obj.props[fake.pystr()] = fake.pystr()


@pytest.mark.asyncio
async def test_base_obj_props_iter_items_keys_values_len(user_created_via_http, udm_kwargs):
    dn, url, user = user_created_via_http()

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)
    keys_exp = [k for k in obj.props.__dict__.keys() if not k.startswith("_")]
    assert set(keys_exp) == set(obj.props.keys())  # keys
    assert set(keys_exp) == set(k for k in obj.props)  # iter
    assert len(keys_exp) == len(obj.props)  # len
    for k in keys_exp:
        assert getattr(obj.props, k) in obj.props.values()  # values
        assert (k, getattr(obj.props, k)) in obj.props.items()  # items


@pytest.mark.asyncio
async def test_base_obj_props_update(user_created_via_http, fake_user, udm_kwargs):
    dn, url, user = user_created_via_http()
    new_user = fake_user()

    async with UDM(**udm_kwargs) as udm:
        mod = udm.get("users/user")
        obj = await mod.get(dn)
    keys_exp = [k for k in obj.props.__dict__.keys() if not k.startswith("_")]
    new_values = attr.asdict(new_user.props)
    kv = list(new_values.items())[0]
    kwargs = dict([kv])
    del new_values[kv[0]]
    obj.props.update(new_values, **kwargs)
    for k in keys_exp:
        if hasattr(new_user.props, k):
            assert getattr(obj.props, k) == getattr(new_user.props, k)
    assert getattr(obj.props, kv[0]) == kv[1]
