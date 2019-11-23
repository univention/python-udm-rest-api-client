=====
Usage
=====

To use Python UDM REST Client in a project, first get the UCS servers CA certificate (from ``http://FQDN.OF.UCS/ucs-root-ca.crt``), then run::

    from udm_rest_client.udm import UDM

    async def change_properties(dn, **changes):
        async with UDM(
                "USERNAME",
                "PASSWORD",
                "https://FQDN.OF.UCS/univention/udm",
                ssl_ca_cert="ucs-root-ca.crt"
        ) as udm:
            mod = udm.get("users/user")
            obj = await mod.get(dn)
            for property, value in changes.items():
                setattr(obj.props, property, value)
            await obj.save()

    import asyncio
    asyncio.run(change_properties(
        "uid=a.user,cn=users,BASE-DN",
        firstname="newfn",
        lastname="newln",
        password="password123",
    ))

Move a user::

    async with UDM(...) as udm:
        mod = udm.get("users/user")
        user_obj = await mod.get("uid=foo,cn=users,...")
        user_obj.position = "ou=office,..."
        await user_obj.save()
        print(user_obj.dn)  # new DN ("uid=foo,ou=office,...")
