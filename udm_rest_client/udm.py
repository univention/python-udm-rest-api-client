# -*- coding: utf-8 -*-
#
# Copyright 2019 Univention GmbH
#
# http://www.univention.de/
#
# All rights reserved.
#
# The source code of this program is made available
# under the terms of the GNU Affero General Public License version 3
# (GNU AGPL V3) as published by the Free Software Foundation.
#
# Binary versions of this program provided by Univention to you as
# well as other copyrighted, protected or trademarked materials like
# Logos, graphics, fonts, specific documentations and configurations,
# cryptographic keys etc. are subject to a license agreement between
# you and Univention.
#
# This program is provided in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License with the Debian GNU/Linux or Univention distribution in file
# /usr/share/common-licenses/AGPL-3; if not, see
# <http://www.gnu.org/licenses/>.

"""
UDM REST API Client library

Python library to interact with the Univention `UDM REST API`, implementing
the interface of the `simple Python UDM API` [1].

The API consists of UDM modules and UDM object.
UDM modules are factories for UDM objects.
UDM objects manipulate LDAP objects on the UCS server.

Usage::

    async with UDM("myuser", "s3cr3t", "https://FQ.DN/univention/udm/") as udm:
        user_mod = udm.get('users/user')

        obj = user_mod.get(dn)
        obj.props.firstname = 'foo'  # modify property
        obj.position = 'cn=users,cn=example,dc=com'  # move LDAP object
        obj.save()  # apply changes and reload object from LDAP

        obj = user_mod.get(dn)
        obj.delete()  # delete object

        async for obj in udm.get('users/user').search('uid=a*'):
            print(obj.props.firstname, obj.props.lastname)


[1] https://docs.software-univention.de/developer-reference-4.4.html#udm:rest_api
"""

from typing import Sequence
from urllib.parse import urljoin

from .base_http import Session, UdmModule, UdmObject, _camel_case_name

try:
    import openapi_client_udm.rest
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "Please run 'update_openapi_client' to install the OpenAPI client "
        "library package 'openapi-client-udm'."
    ) from exc

# that code doesn't work when something goes wrong:
try:
    del openapi_client_udm.rest.RESTClientObject.__del__
except AttributeError:  # pragma: no cover
    pass


class UDM:
    """
    Factory for creating :py:class:`udm_rest_client.UdmModule` objects::

        from udm_rest_client import UDM

        async def func():
            async with UDM("myuser", "s3cr3t", "https://FQ.DN/univention/udm/") as udm:
                group_mod = udm.get('groups/group')
                obj = await group_mod.get(dn)
                # obj is of type udm_rest_client.base_http.UdmObject

    HTTP(S) sessions will be closed upon existing the asynchronous context manager.
    It is recommended to make as many operations as possible in the same session.
    """

    def __init__(
        self,
        username: str,
        password: str,
        url: str,
        max_client_tasks: int = 10,
        **kwargs,
    ):
        """
        Use the provided data to connect to the UDM REST API. Additional
        settings for the HTTP client can be passed through `kwargs`:

        * debug (bool, False): debug switch
        * verify_ssl (bool, True): enable/disable verifying SSL certificate
        * ssl_ca_cert (str, None): custom certificate file to verify the peer
        * cert_file (str, None): client certificate file
        * key_file (str, None): client key file
        * assert_hostname (bool, True): enable/disable SSL hostname verification
        * connection_pool_maxsize (int, 100): limit of simultaneous connections
            opened by aiohttp (None means no-limit). `max_client_tasks` should
            be used instead, as it will instead limit the number of parallel
            tasks waiting for HTTP connection and prevent client timeouts.
        * proxy (str, None): Proxy URL
        * proxy_headers (dict, None): Proxy headers to add to requests sent
            through a proxy
        * retries (int, 3): override urllib3 default for retries on connection
            errors

        :param str username: username to use for UDM REST API connection
        :param str password: password of user for UDM REST API connection
        :param str url: URL of UDM REST API (e.g. `https://FQ.DN/univention/udm/`)
        :param int max_client_tasks: max. number of tasks starting parallel
            connections to open to the UDM REST API; minimum is 4; to few
            connections will lower performance, to many connections will lead
            to timeouts
        :param kwargs: attributes to set on the HTTP client configuration
            object (:py:class:`openapi_client_udm.configuration.Configuration`)
        :raises univention.udm.exceptions.APICommunicationError: Invalid
            credentials, server down, etc.
        """
        self.session = Session(username, password, url, max_client_tasks, **kwargs)
        self._api_version = 2

    async def __aenter__(self):
        self.session.open()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()

    def version(self, api_version: int) -> "UDM":
        """
        This is not about versions of the UDM REST API. This is here only to
        provide better drop-in functionality when using this lib instead of the
        UDM Python API on a UCS system. It is not required to use this method.

        :param int api_version: ignored
        :return: self
        :rtype: udm_rest_client.UDM
        """
        self._api_version = api_version
        return self

    def get(self, name: str) -> UdmModule:
        """
        Context manager of type :py:class:`udm_rest_client.UdmModule` to work with UDM objects
        of type `name` (e.g. `users/user`). Exiting the context manager
        automatically closes the :py:class:`aiohttp.ClientSession`. Usage
        example::

            async with udm.get("users/user") as user_mod:
                user_obj = await user_mod.get($DN)

        :param str name: UDM module name (e.g. `users/user`)
        :return: instance of :py:class:`udm_rest_client.UdmModule`
        :rtype: udm_rest_client.UdmModule
        """
        return UdmModule(name, self.session)

    async def obj_by_dn(self, dn: str) -> UdmObject:
        """
        Load a UDM object without knowing the UDM module type.

        :param str dn: DN of the object to load
        :return: :py:class:`udm_rest_client.UdmObject` instance
        :rtype: udm_rest_client.UdmObject
        :raises univention.udm.exceptions.NoObject: if no object is found at `dn`
        :raises univention.udm.exceptions.ImportError: if the Python module for
            the specific UDM module type could not be loaded
        """
        object_type = await self.session.get_object_type(dn)
        return await self.get(object_type).get(dn)

    @property
    def api_version(self):
        """Here only for backwards compatibility."""
        return self._api_version

    async def modules_list(self) -> Sequence[str]:
        """
        Get the list of UDM modules the server knows.

        :return: list of UDM module names
        :rtype: list(str)
        """
        url = urljoin(self.session.openapi_client_config.host + "/", "navigation/")
        body = await self.session.get_json(url)
        return sorted(ot["name"] for ot in body["_links"]["udm:object-types"])

    async def unknown_modules(self) -> Sequence[str]:
        """
        Get the list of UDM modules the server knows, but this client doesn't.

        Unknown UDM modules cannot be used with this client library.
        When the list is non-empty, the package `openapi-client-udm` must be
        rebuilt to use them.

        :return: list of UDM modules known by the server but not this client
        :rtype: list(str)
        """
        return [
            name
            for name in await self.modules_list()
            if not hasattr(openapi_client_udm, f"{_camel_case_name(name)}Api")
        ]
