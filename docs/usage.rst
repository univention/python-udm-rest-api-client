=====
Usage
=====

To use Python UDM REST Client in a project, first get the UCS servers CA certificate (from ``http://FQDN.OF.UCS/ucs-root-ca.crt``).
Then use the ``UDM`` context manager to open a HTTPS session and authenticate.

Change some properties
----------------------

Open the session, get the current LDAP object, change some attributes and save the changes back to LDAP::

    import asyncio
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

    async def main():
        await change_properties(
            "uid=a.user,cn=users,BASE-DN",
            firstname="newfn",
            lastname="newln",
            password="password123",
        )

    asyncio.run(main())

The class of the ``props`` attribute also has a dict-like interface.
So the following two lines are equivalent::

    obj.props.firstname = "Alice"
    obj.props["firstname"] = "Alice"

The ``for`` loop above could also have been written like this::

    for property, value in changes.items():
        obj.props[property] = value

Or could simply be replaced by::

    obj.props.update(changes)

Move an object
--------------

Moving an object means changing its position in LDAP.
That happens whenever the DN changes.
The DN is created from the name of the object concatenated with the subtree in which the object is located.
So both changing a users ``username`` (or a groups ``name``) attribute as well as changing an objects ``position`` attribute initiates a move.

Behind the scenes the *Python UDM REST Client* will execute two modification on the UDM REST API: it will first apply the move and then any changes to the other properties in ``props``. But in the frontend it is sufficient to make the desired changes to the object and ``save()`` once::

    async with UDM(...) as udm:
        mod = udm.get("users/user")
        user_obj = await mod.get("uid=foo,cn=users,...")
        user_obj.position = "ou=office,..."
        user_obj.props.firstname = "bar"
        await user_obj.save()
        print(user_obj.dn)  # new DN ("uid=foo,ou=office,...")

Options
-------

The ``options`` of an UDM object correspond approximately to LDAP objectClasses.
They are used to enable/disable attributes of LDAP objects and with that features.
For example UDM ``shares/share`` objects support automatic creation of CIFS and NFS shares.
By default shares for both protocols will be created.
To disable the creation of an NFS share, the ``option`` has to be disabled.

.. note::
    In version 1.0.0 there was a **breaking API change**: The ``options`` attribute of UDM objects is now a *dictionary*. It mirrors the UDM REST APIs ``options`` attribute value. Before it was a *list*, which did not allow to disable default options.

The following example code removes the NFS feature from a share object::

    async with UDM(...) as udm:
        mod = udm.get("shares/share")
        share_obj = await mod.get("cn=documents,cn=shares,...")
        print(share_obj.options)
        {'samba': True, 'nfs': True}
        print(share_obj.props)
        UdmObjectProperties({
            ...
            'nfs_hosts': [],
            'root_squash': True,
            'sambaBlockSize': None,
            ...})
        share_obj.options["nfs"] = False
        await share_obj.save()

        print(share_obj.options)
        {'samba': True, 'nfs': False}
        print(share_obj.props)
        UdmObjectProperties({
            # no more NFS properties
            'sambaBlockSize': None,
            ...})
