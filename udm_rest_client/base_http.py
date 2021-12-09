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
Base classes for (simplified) UDM modules and objects using the UDM REST API
(instead of the low level Python UDM API).
"""

import asyncio
import copy
import datetime
import inspect
import json
import logging
import re
import time
import warnings
from collections.abc import MutableMapping, MutableSequence
from functools import lru_cache
from typing import Any, AsyncIterator, Dict, List, Pattern, Tuple, TypeVar, Union, cast
from urllib.parse import SplitResult, unquote, urljoin, urlsplit

import aiohttp
from async_property import async_cached_property, async_property

from .base import (
    BaseModule,
    BaseModuleMeta,
    BaseModuleMetadata,
    BaseObject,
    BaseObjectProperties,
    LdapMapping,
)
from .exceptions import (
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

try:
    import openapi_client_udm
    from openapi_client_udm.exceptions import ApiException
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "Please run 'update_openapi_client' to install the OpenAPI client "
        "library package 'openapi-client-udm'."
    ) from exc


if False:  # pylint: disable=using-constant-test
    # prevent cyclic import, used only by mypy
    from .udm import UDM  # pylint: disable=unused-import  # noqa: F401


METHOD_NAMES = {
    "create": "udm_{}_object_create_with_http_info",
    "get": "udm_{}_object_with_http_info",
    "modify": "udm_{}_object_modify_with_http_info",
    "new": "udm_{}_object_template_with_http_info",
    "remove": "udm_{}_object_remove_with_http_info",
    "search": "udm_{}_object_search_with_http_info",
    "update": "udm_{}_object_update_with_http_info",
}
MIN_FOLLOW_REDIRECT_SLEEP_TIME = 1.0
logger = logging.getLogger(__name__)
_ldap_base_cache: Dict[str, str] = {}

ApiModule = TypeVar("ApiModule")  # openapi_client_udm.SharesShareApi etc
ApiModel = TypeVar("ApiModel")  # openapi_client_udm.SharesShare etc


class UdmRestClientWarning(Warning):
    ...


class BadSettingsWarning(UdmRestClientWarning):
    ...


class InsecureRequestWarning(UdmRestClientWarning):
    ...


class StaleObjectWarning(UdmRestClientWarning):
    ...


def _is_api_model(obj: Any) -> bool:
    if not inspect.isclass(obj):
        return False  # pragma: no cover
    module = inspect.getmodule(obj)
    return module.__package__ == "openapi_client_udm.models"


def _serialize_obj(obj: Any) -> Any:
    """Recursive JSON compatible serialization."""
    if any(isinstance(obj, x) for x in (type(None), bool, float, int, str)):
        # non-iterable base type
        return obj
    if isinstance(obj, datetime.date):
        return obj.strftime("%Y-%m-%d")
    if isinstance(obj, UdmObject):
        return obj.uri
    if isinstance(obj, dict):
        res = {}
        for k, v in obj.items():
            if str(k).startswith("_"):
                continue
            res[k] = _serialize_obj(v)
        return res
    if any(isinstance(obj, x) for x in (list, tuple)):
        return [_serialize_obj(v) for v in obj]
    if _is_api_model(type(obj)):
        return _serialize_obj(obj.to_dict())
    raise ValueError(f"Dont know how to handle object of type {type(obj)!r}.")


def _uri2module_dn(uri: str) -> Tuple[str, str]:
    """
    Extract the UDM module name and the DN in a URI.

    Very unRESTfull but saves us one request for each save(). We'll use this
    as long as no major problems arise and handle the special cases.

    Cases handled here:

    * Double slash (``//``) in a DN is encoded as ``,/=/,`` (exists at least
    in UDM module saml/serviceprovidern, see Bug #50175).
    The decoding in replies is done in the callers of ``openapi_client_udm``.
    * The case of users/self redirecting to users/user is handled in callers
    of ``openapi_client_udm``.

    :param str uri: a URI
    :return: 2-tuple with the module name and the DN
    :rtype: tuple[str, str]
    """
    path = urlsplit(uri).path
    path_split = path.strip("/").split("/")
    module_name = "/".join(path_split[2:4])
    dn_enc = "/".join(path_split[4:])
    dn = unquote(dn_enc)
    dn = dn.replace(",/=/,", "//")
    return module_name, dn


def _camel_case_name(udm_module_name: str) -> str:
    cc_name = "".join(f"{s[0].upper()}{s[1:]}" for s in udm_module_name.strip("/_").split("/"))
    while "_" in cc_name:
        index = cc_name.find("_")
        cc_name = "{}{}{}".format(
            cc_name[:index],
            cc_name[index + 1].upper(),
            cc_name[index + 2 :],  # noqa: E203
        )
    return cc_name


class Session:
    def __init__(
        self,
        username: str,
        password: str,
        url: str,
        max_client_tasks: int = 10,
        **kwargs,
    ):
        """
        Use the provided data to connect to the UDM REST API. Pass an instance
        of this to the UDM constructor.

        Additional settings for the HTTP client can be passes through `kwargs`:

        * debug (bool, False): debug switch
        * verify_ssl (bool, True): enable/disable verifying SSL certificate
        * ssl_ca_cert (str, None): CA certificate file to verify the peer
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
        if max_client_tasks < 4:
            txt = "Raising value of 'max_client_tasks' to its minimum of 4."
            warnings.warn(txt, BadSettingsWarning)
            logger.warning(txt)
            max_client_tasks = 4
        self.max_client_tasks = max_client_tasks
        connection_pool_maxsize = kwargs.get("connection_pool_maxsize", 100)
        if connection_pool_maxsize < max_client_tasks:
            txt = (
                f"Raising 'connection_pool_maxsize' to value of "
                f"'max_client_tasks' ({max_client_tasks})."
            )
            warnings.warn(txt, BadSettingsWarning)
            logger.warning(txt)
            connection_pool_maxsize = max_client_tasks
            kwargs["connection_pool_maxsize"] = connection_pool_maxsize
        _url: SplitResult = urlsplit(url)
        if _url.scheme == "http":
            txt = (
                f"Using unencrypted connection. The password of the user "
                f"{username!r} will be visible on the network!"
            )
            warnings.warn(txt, InsecureRequestWarning)
            logger.warning(txt)

        # purge openapi client configuration cache
        openapi_client_udm.Configuration._default = None
        self.openapi_client_config = openapi_client_udm.Configuration(
            host=url, username=username, password=password
        )
        # purge openapi client configuration cache
        openapi_client_udm.Configuration._default = None

        for k, v in kwargs.items():
            if not hasattr(self.openapi_client_config, k):
                raise ConfigurationError(
                    f"Unknown attribute {k!r} for an " f"'openapi_client_udm.Configuration' object."
                )
            setattr(self.openapi_client_config, k, v)
        self._client: openapi_client_udm.ApiClient = None
        self._session: aiohttp.ClientSession = None
        self._client_task_limiter = asyncio.Semaphore(max_client_tasks)

    def open(self) -> None:
        if self._session:
            return
        self._client = openapi_client_udm.ApiClient(self.openapi_client_config)
        self._session = self._client.rest_client.pool_manager

    async def close(self) -> None:
        if self._session:
            await self._session.close()
            await asyncio.sleep(0.1)  # allow aiohttp SSL connections to close gracefully
        self._session = None
        self._client = None

    @property
    def session(self) -> aiohttp.ClientSession:
        if not self._session:
            raise RuntimeError("Session is closed.")
        return self._session

    async def get_json(self, url: str, **kwargs) -> Dict[str, Any]:
        request_kwargs = copy.deepcopy(kwargs)
        request_kwargs.setdefault("headers", {}).update({"Accept": "application/json"})
        request_kwargs["auth"] = aiohttp.BasicAuth(
            self.openapi_client_config.username, self.openapi_client_config.password
        )
        async with self._client_task_limiter:
            async with self.session.get(url, **request_kwargs) as response:
                request_kwargs["auth"] = (
                    self.openapi_client_config.username,
                    "********",
                )
                logger.debug(
                    "GET %r (**%r) -> %r (%r)",
                    url,
                    request_kwargs,
                    response.status,
                    response.reason,
                )
                if 200 <= response.status <= 299:
                    return await response.json()
                elif 400 <= response.status <= 499:
                    raise NoObject(
                        f"UDM REST API returned status {response.status}, "
                        f"reason {response.reason!r} for URL {url!r}.",
                        dn=url,
                        module_name="<unknown>",
                    )
                else:
                    raise APICommunicationError(
                        reason=response.reason, status=response.status
                    )  # pragma: no cover

    async def get_object_type(self, dn: str) -> str:
        dn = dn.replace("//", ",/=/,")
        url = urljoin(self.openapi_client_config.host + "/", f"object/{dn}")
        body = await self.get_json(url, allow_redirects=True)
        try:
            return body["objectType"]
        except KeyError as exc:  # pragma: no cover
            raise UnknownModuleType(
                f"Received object from UDM REST API without or with unknown "
                f"'objectType' attribute at URL {url!r}. Complete body: {body!r}",
                dn=dn,
                module_name="n/a",
            ) from exc

    @async_cached_property
    async def dn_regex(self) -> Pattern:
        base_dn = await self.base_dn
        return re.compile(r"^(\w+=.+)+,{}$".format(re.escape(base_dn)))

    @async_property
    async def base_dn(self) -> str:
        if self.openapi_client_config.host not in _ldap_base_cache:
            url = urljoin(self.openapi_client_config.host + "/", "ldap/base/")
            body = await self.get_json(url)
            _ldap_base_cache[self.openapi_client_config.host] = body["dn"]
        return _ldap_base_cache[self.openapi_client_config.host]

    def openapi_class(self, udm_module_name: str) -> type:
        camel_case_name = _camel_case_name(udm_module_name)
        try:
            return getattr(openapi_client_udm, f"{camel_case_name}Api")
        except AttributeError:
            raise UnknownModuleType(f"Unknown module: {udm_module_name!r}.", module_name=udm_module_name)

    def openapi_model(self, udm_module_name: str) -> ApiModel:
        camel_case_name = _camel_case_name(udm_module_name)
        try:
            return getattr(openapi_client_udm, camel_case_name)
        except AttributeError:
            raise UnknownModuleType(f"Unknown module: {udm_module_name!r}.", module_name=udm_module_name)

    @lru_cache(maxsize=256)
    def openapi_method(self, udm_module_name: str, operation: str):
        name_snake_case = "_".join(s.lower() for s in udm_module_name.split("/"))
        meth_name = METHOD_NAMES[operation].format(name_snake_case)
        api_cls = self.openapi_class(udm_module_name)
        api: ApiModule = api_cls(self._client)
        try:
            return getattr(api, meth_name)
        except AttributeError:
            raise MethodNotSupportedError(
                f"Unsupported method {meth_name!r} for module {udm_module_name!r}.",
                module_name=udm_module_name,
            )

    async def call_openapi(  # noqa: C901
        self,
        udm_module_name: str,
        operation: str,
        dn: str = None,
        api_model_obj: Union[ApiModel, Dict[str, Any]] = None,
        **kwargs,
    ) -> Tuple[Union[ApiModel, List[ApiModel]], int, Dict[str, str]]:
        meth = self.openapi_method(udm_module_name, operation)
        if api_model_obj:
            name_snake_case = "_".join(s.lower() for s in udm_module_name.split("/"))
            kwargs[name_snake_case] = api_model_obj
        if dn:
            kwargs["dn"] = dn.replace("//", ",/=/,")
        # TODO: make 'retries' and 'retry_wait' configurable
        retries = 3
        retry_wait = 10
        while True:
            # loop to allow retry in case of HTTP 503
            try:
                async with self._client_task_limiter:
                    api_model_obj, status, header = await meth(**kwargs)
                    api_model_obj = cast(Union[ApiModel, Any], api_model_obj)
                    status = cast(int, status)
                    header = cast(Dict[str, str], header)
                    res_type = api_model_obj.__class__.__name__
                    if res_type.endswith("List") and not hasattr(api_model_obj, "dn"):
                        # resource collection
                        if api_model_obj.embedded.udmobject is None:
                            return [], status, header
                        collection_size = len(api_model_obj.embedded.udmobject)
                        resource_name = api_model_obj.__class__.__name__[:-4]
                        logger.debug(
                            "%r %r -> %s(**%r) -> %s(%d * %s) [%r]",
                            operation,
                            udm_module_name,
                            meth.__name__,
                            kwargs,
                            api_model_obj.__class__.__name__,
                            collection_size,
                            resource_name,
                            status,
                        )
                        return api_model_obj.embedded.udmobject, status, header
                    else:
                        # resource
                        _dn = None if status == 204 else api_model_obj.dn
                        logger.debug(
                            "%r %r -> %s(**%r) -> %s(%r) [%r]",
                            operation,
                            udm_module_name,
                            meth.__name__,
                            kwargs,
                            api_model_obj.__class__.__name__,
                            _dn,
                            status,
                        )
                        return api_model_obj, status, header
            except ApiException as exc:
                if exc.status == 401:
                    raise APICommunicationError(
                        f"[HTTP 401] Credentials invalid or no permissions for "
                        f"operation {operation!r} on {udm_module_name!r} with "
                        f"arguments {kwargs!r}.",
                        status=exc.status,
                        reason=exc.reason,
                    ) from exc
                if exc.status == 404:
                    raise NoObject(
                        f"[HTTP 404] No {udm_module_name!r} object found for " f"arguments {kwargs!r}.",
                        dn=kwargs.get("dn"),
                        module_name=udm_module_name,
                    ) from exc
                if exc.status == 503:  # pragma: no cover
                    if retries > 0:
                        logger.warning(
                            "UDM REST API returned HTTP 503 (%s), retrying in %d " "seconds.",
                            exc.reason,
                            retry_wait,
                        )
                        retries -= 1
                        await asyncio.sleep(retry_wait)
                        continue
                    else:
                        logger.error("Last retry unsuccessful.")
                        # fall through
                reason = exc.reason
                if exc.body:
                    try:
                        resp_obj = json.loads(exc.body)
                        reason = f"{reason}: {resp_obj['error']['error']}"
                    except (KeyError, ValueError):  # pragma: no cover
                        pass
                if exc.status == 422 and operation == "create":
                    raise CreateError(reason) from exc
                if exc.status == 422 and operation == "update":
                    raise ModifyError(reason) from exc
                raise APICommunicationError(
                    f"[HTTP {exc.status}]: for operation {operation!r} on "
                    f"{udm_module_name!r} with arguments {kwargs!r}: {reason}",
                    reason=reason,
                    status=exc.status,
                ) from exc  # pragma: no cover


class UdmObjectProperties(BaseObjectProperties):
    """Container for UDM properties."""

    def _to_dict(self) -> Dict[str, Any]:
        return dict((k, _serialize_obj(v)) for k, v in self.items())


class UdmObject(BaseObject):
    """
    Base class for UDM_HTTP object classes.

    Usage:

    Creation of instances :py:class:`udm_rest_client.UdmObject` is always done through a
    :py:class:`BaseHttpModul` instances py:meth:`new()`, py:meth:`get()` or
    py:meth:`search()` methods.

    * Modify an object::

        user.props.firstname = 'Peter'
        user.props.lastname = 'Pan'
        user.save()

    * Move an object::

        user.position = 'cn=users,ou=Company,dc=example,dc=com'
        user.save()

    * Delete an object::

        obj.delete()

    After saving a :py:class:`udm_rest_client.UdmObject`, it is :py:meth:`reload()` 'ed
    automatically because UDM hooks and listener modules often add, modify or
    remove properties when saving to LDAP. As this involves LDAP, it can be
    disabled if the object is not used afterwards and performance is an issue::

        user_mod.meta.auto_reload = False
    """

    udm_prop_class = UdmObjectProperties

    def __init__(self):
        """
        Don't instantiate a :py:class:`udm_rest_client.UdmObject` directly. Use
        :py:meth:`udm_rest_client.UdmModule.get()`, :py:meth:`udm_rest_client.UdmModule.new()` or
        :py:meth:`udm_rest_client.UdmModule.search()`.
        """
        super(UdmObject, self).__init__()
        self.uri = ""
        self.uuid = ""
        self._api_obj: ApiModel = None
        self._fresh = True
        self._deleted = False
        self._udm_module = cast(UdmModule, self._udm_module)

    def __deepcopy__(self, memo: Dict[int, "UdmObject"]) -> "UdmObject":
        id_self = id(self)
        if not memo.get(id_self):
            memo[id_self] = self.__class__()
            for k in (
                "dn",
                "options",
                "policies",
                "position",
                "props",
                "superordinate",
            ):
                setattr(memo[id_self], k, copy.deepcopy(getattr(self, k)))
            obj_dump = self._api_obj.to_dict()
            memo[id_self]._api_obj = self._api_obj.__class__(**obj_dump)
            # _udm_module must be set in the current session
        return memo[id_self]

    def __eq__(self, other: "UdmObject") -> bool:
        if not super().__eq__(other):
            return False
        for attr in ("uri", "uuid"):
            if getattr(self, attr) != getattr(other, attr):
                return False
        return True

    async def reload(self) -> "UdmObject":
        """
        Refresh object from LDAP.

        :return: self
        :rtype: udm_rest_client.UdmObject
        """
        if self._deleted:
            raise DeletedError(
                f"{self} has been deleted.",
                dn=self.dn,
                module_name=self._udm_module.name,
            )
        if not self.dn or not self._api_obj:
            raise NotYetSavedError(module_name=self._udm_module.name)
        api_obj = await self._udm_module._get_api_object(self.dn)
        self._api_obj = api_obj
        if api_obj.object_type != self._udm_module.name:
            # probably only happens with users/self
            self._udm_module = UdmModule(api_obj.object_type, self._udm_module.session)
        await self._copy_from_api_instance_obj(api_obj)
        return self

    async def save(self) -> "UdmObject":  # noqa: C901
        """
        Save object to LDAP (via UDM REST API).

        :return: self
        :rtype: udm_rest_client.UdmObject
        :raises ApiException: when the operation fails
        """
        if self._deleted:
            raise DeletedError(
                f"{self} has been deleted.",
                dn=self.dn,
                module_name=self._udm_module.name,
            )
        if not self._fresh:
            txt = "Saving stale UDM object instance."
            logger.warning(txt)
            warnings.warn(txt, StaleObjectWarning)

        diff_dict = {}
        old_obj = _serialize_obj(self._api_obj)
        new_obj = self.to_dict()
        for k, v in new_obj.items():
            if k in ("dn", "uri", "uuid"):
                continue
            elif k == "props":
                for prop, value in v.items():
                    if isinstance(value, list):
                        # convert to tuple to avoid TypeError: unhashable type 'dict'
                        new_value = {
                            tuple(sorted(_val.items())) if isinstance(_val, dict) else _val
                            for _val in value
                        }
                        old_value = {
                            tuple(sorted(_old_val.items())) if isinstance(_old_val, dict) else _old_val
                            for _old_val in old_obj["properties"].get(prop, [])
                        }
                    else:
                        new_value = value
                        old_value = old_obj["properties"].get(prop)
                    if new_value != old_value:
                        diff_dict.setdefault("properties", {})[prop] = value
            elif k == "superordinate" and not hasattr(old_obj, "superordinate"):
                continue
            elif k == "policies" and v:
                if hasattr(self._api_obj.policies, "attribute_map"):
                    attribute_map: Dict[str, str] = self._api_obj.policies.attribute_map
                    old_policies = dict(
                        (attribute_map[k], v) for k, v in self._api_obj.policies.to_dict().items()
                    )
                else:
                    old_policies = self._api_obj.policies
                # v is Dict[str, List[str]], compare as Dict[str, Set[str]]
                if dict((diff_k, set(diff_v)) for diff_k, diff_v in v.items()) == dict(
                    (new_k, set(new_v)) for new_k, new_v in old_policies.items()
                ):
                    continue
                diff_dict[k] = v
            elif k == "position" and v:
                diff_dict[k] = v  # always set position
            else:
                if v != old_obj[k]:
                    diff_dict[k] = v
        for k in ("options", "policies", "props", "superordinate"):
            if not diff_dict.get(k):
                diff_dict.pop(k, None)
        if self.dn:
            # 'move' as a separate step before 'modify'
            if self.dn and self._api_obj.position and self._api_obj.position != self.position:
                # TODO: handle base64 encoded DNs
                logger.info("Moving {!r} to new position {!r}.".format(self, self.position))
                api_obj = await self._move(self.position)
                await self._copy_from_api_instance_obj(api_obj)
                logger.info("Finished moving object, new DN: %r", self.dn)

            # position is always set, ignore if unchanged
            if diff_dict == {"position": self._api_obj.position}:
                logger.debug("No modifications for %r found, nothing to do.", self)
                return self
            else:
                logger.debug("Modifications to %r found (ignore 'position'): %r", self, diff_dict)
            operation = "update"
            dn = self.dn
        else:
            operation = "create"
            dn = None

        kwargs = {
            "udm_module_name": self._udm_module.name,
            "operation": operation,
            "dn": dn,
            "api_model_obj": diff_dict,
        }
        _, status, header = await self._udm_module.session.call_openapi(**kwargs)
        if status in (201, 204):
            new_module_name, new_dn = _uri2module_dn(header["Location"])
            if new_module_name != self._udm_module.name:  # pragma: no cover
                if not (self._udm_module.name == "users/self" and new_module_name == "users/user"):
                    logger.warning(
                        "UDM REST API redirected to an object of a different "
                        "module. %r of %r returned the 'Location' %r which was"
                        " decoded to module %r and DN %r. Arguments were: %r ",
                        operation,
                        self._udm_module.name,
                        header["Location"],
                        new_module_name,
                        new_dn,
                        kwargs,
                    )
                self._udm_module = UdmModule(new_module_name, self._udm_module.session)
            self.dn = new_dn
        else:  # pragma: no cover
            # TODO: wrap in {Create/Modify/Move/Delete}Exception
            raise ApiException(
                f"UDM REST API returned status {status}, header: {header!r} "
                f"for {operation!r} of {self._udm_module.name!r} {dn!r}."
            )
        self._fresh = False
        await self.reload()
        return self

    async def delete(self) -> None:
        """
        Remove the object from the LDAP database.

        :return: None
        """
        if self._deleted:
            logger.warning("%s has already been deleted.", self)
            return
        if not self.dn or not self._api_obj:
            raise NotYetSavedError()
        try:
            await self._udm_module.session.call_openapi(self._udm_module.name, "remove", dn=self.dn)
        except NoObject as exc:
            logger.warning("When deleting %r: %s", self, exc)
        self._api_obj = None
        self._deleted = True

    @classmethod
    async def _new_from_api_object(cls, api_obj: ApiModel, udm_module: "UdmModule") -> "UdmObject":
        obj = cls()
        obj._api_obj = api_obj
        obj._udm_module = udm_module
        await obj._copy_from_api_instance_obj(api_obj)
        return obj

    async def _copy_from_api_instance_obj(self, api_model_obj: ApiModel) -> None:
        """
        Copy UDM property values from openapi-generator model object to
        `props` container as well as its `policies` and `options`.

        :return: None
        """
        self.dn = api_model_obj.dn
        self.uri = api_model_obj.uri
        self.uuid = api_model_obj.uuid
        if hasattr(api_model_obj.options, "attribute_map"):
            #  openapi_client_udm.models.usersuser_options.UsersuserOptions etc
            attribute_map: Dict[str, str] = api_model_obj.options.attribute_map
            self.options = dict(
                (attribute_map[k], v) for k, v in api_model_obj.options.to_dict().items()
            )
        else:
            # empty dict
            self.options = api_model_obj.options
        if hasattr(api_model_obj.policies, "attribute_map"):
            # openapi_client_udm.models.settingsmswmifilter_policies.SettingsmswmifilterPolicies
            attribute_map: Dict[str, str] = api_model_obj.policies.attribute_map
            policies = dict((attribute_map[k], v) for k, v in api_model_obj.policies.to_dict().items())
        else:
            # empty dict
            policies = api_model_obj.policies
        self.policies = dict(
            (
                p_type,
                [DnPropertyEncoder("__policies", dn, self._udm_module.session).decode() for dn in dns],
            )
            for p_type, dns in policies.items()
        )

        self.props = self.udm_prop_class(self)
        dn_regex = await self._udm_module.session.dn_regex
        for k, v in api_model_obj.properties.items():
            if isinstance(v, str) and v and dn_regex.match(v):
                v = DnPropertyEncoder(k, v, self._udm_module.session).decode()
            elif (
                isinstance(v, list)  # flake8 doesn't like the way black splits this:
                and v  # noqa: 503
                and all(isinstance(x, str) for x in v)  # noqa: 503
                and all(dn_regex.match(x) for x in v)  # noqa: 503
            ):
                v = [DnPropertyEncoder(k, dn, self._udm_module.session).decode() for dn in v]
            elif isinstance(v, MutableSequence) or isinstance(v, MutableMapping):
                # changing obj.property.x should not change obj._api_obj.property.x
                v = copy.deepcopy(v)
            setattr(self.props, k, v)
        superordinate: str = getattr(api_model_obj, "superordinate", None)
        if (
            superordinate
            and isinstance(superordinate, str)  # noqa: 503
            and dn_regex.match(superordinate)  # noqa: 503
        ):
            superordinate_encoder = DnPropertyEncoder(
                "__superordinate", superordinate, self._udm_module.session
            )
            superordinate = superordinate_encoder.decode()
        self.superordinate = superordinate

        self.position = api_model_obj.position
        self._fresh = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dn": self.dn,
            "uri": self.uri,
            "uuid": self.uuid,
            "options": _serialize_obj(self.options),
            "policies": _serialize_obj(self.policies),
            "position": self.position,
            "props": self.props._to_dict(),
            "superordinate": self.superordinate,
        }

    async def _move(self, position: str) -> ApiModel:
        """
        Change the `position` ob an object.

        :param str position: DN of the objects new position
        :return: the new ApiModel object from the UDM REST API
        :rtype: ApiModel
        """
        # workaround for Bug #50262: use PUT instead of PATCH
        self._api_obj.position = position
        try:
            new_api_obj, status, header = await self._udm_module.session.call_openapi(
                self._udm_module.name, "modify", dn=self.dn, api_model_obj=self._api_obj
            )
        except APICommunicationError as exc:
            raise MoveError(f"Error moving {self} to {position!r}: [{exc.status}] {exc.reason}")
        if status != 201:  # pragma: no cover
            raise MoveError(
                f"Error moving {self} to {position!r}:\nHTTP [{status}]\n"
                f"response: {new_api_obj!r}\nheader: {header!r}'",
                dn=self.dn,
                module_name=self._udm_module.name,
            )

        udm_api_response = await self._follow_move_redirects(header["Location"], position)

        api_obj_attrs = [
            attr for attr in self._api_obj.attribute_map.values() if not attr.startswith("_")
        ]  # ["dn", ..., "properties", "objectType"]
        if all(attr in udm_api_response for attr in api_obj_attrs):
            openapi_model_cls = self._udm_module.session.openapi_model(udm_api_response["objectType"])
            api_model_kwargs = dict(
                (k, udm_api_response[v])
                for k, v in openapi_model_cls.attribute_map.items()
                if v in udm_api_response
            )
            return openapi_model_cls(**api_model_kwargs)

    async def _follow_move_redirects(self, move_progress_url: str, position: str) -> Dict[str, Any]:
        operation_timeout = 300  # TODO: make configurable?
        start_time = time.time()
        while time.time() - start_time < operation_timeout:
            resp = await self._udm_module.session.session.get(
                move_progress_url,
                allow_redirects=False,
                auth=aiohttp.BasicAuth(
                    self._udm_module.session.openapi_client_config.username,
                    self._udm_module.session.openapi_client_config.password,
                ),
            )
            try:
                sleep_time = float(resp.headers["Retry-After"])
            except (KeyError, ValueError):
                sleep_time = MIN_FOLLOW_REDIRECT_SLEEP_TIME
            sleep_time = min(sleep_time, MIN_FOLLOW_REDIRECT_SLEEP_TIME)
            if resp.status == 301:
                await asyncio.sleep(sleep_time)
                # report that we're alive, when moving takes more than 2s
                operation_time = time.time() - start_time
                if operation_time > 2 and int(operation_time) % 2 == 0:  # pragma: no cover
                    logger.debug(
                        "Waiting on move operation since %.2f seconds...",
                        operation_time,
                    )
                continue  # pragma: no cover
            if resp.status == 303:
                operation_time = time.time() - start_time
                if operation_time > 2:
                    # we have slept
                    logger.debug(  # pragma: no cover
                        "Move operation finished after %.2f seconds.", operation_time
                    )
                move_progress_url = resp.headers["Location"]
                resp = await self._udm_module.session.get_json(move_progress_url, allow_redirects=True)
                break
            raise ApiException(
                f"UDM REST API returned status {resp.status}, headers: {resp.headers!r} "
                f"for move of {self} to position {position!r}."
            )  # pragma: no cover
        else:
            raise MoveError(
                f"Moving {self} to {position!r} did not complete in " f"{operation_timeout} seconds.",
                dn=self.dn,
                module_name=self._udm_module.name,
            )  # pragma: no cover
        return resp


class UdmModuleMetadata(BaseModuleMetadata):
    """Base class for module meta data. Nothing here in the REST client"""

    @property
    def identifying_property(self) -> str:
        """
        UDM Property of which the mapped LDAP attribute is used as first
        component in a DN, e.g. `username` (LDAP attribute `uid`) or `name`
        (LDAP attribute `cn`).
        """
        raise NotImplementedError()

    def lookup_filter(self, filter_s: str = None) -> str:
        """
        Filter the UDM module uses to find its corresponding LDAP objects.

        This can be used in two ways:

        * get the filter to find all objects:
            `myfilter_s = obj.meta.lookup_filter()`
        * get the filter to find a subset of the corresponding LDAP objects
            (`filter_s` will be combined with `&` to the filter for all
            objects):
            `myfilter = obj.meta.lookup_filter('(|(givenName=A*)(givenName=B*))')`

        :param str filter_s: optional LDAP filter expression
        :return: an LDAP filter string
        :rtype: str
        """
        raise NotImplementedError()

    @property
    def mapping(self) -> LdapMapping:
        """
        UDM properties to LDAP attributes mapping and vice versa.

        :return: a namedtuple containing two mappings: a) from UDM property to
            LDAP attribute and b) from LDAP attribute to UDM property
        :rtype: LdapMapping
        """
        raise NotImplementedError()


class UdmModuleMeta(BaseModuleMeta):
    udm_meta_class = UdmModuleMetadata


class UdmModule(BaseModule, metaclass=UdmModuleMeta):
    """
    Base class for UDM_HTTP module classes. UDM modules are basically UDM object
    factories.

    Usage:

    0. Get module using::

        user_mod = UDM().get('users/user')

    1 Create fresh, not yet saved UdmObject::

        new_user = user_mod.new()

    2 Load an existing object::

        group = group_mod.get('cn=test,cn=groups,dc=example,dc=com')
        group = group_mod.get_by_id('Domain Users')

    3 Search and load existing objects::

        dc_slaves = dc_slave_mod.search(filter_s='cn=s10*')
        campus_groups = group_mod.search(base='ou=campus,dc=example,dc=com')

    4. Load existing object(s) without `open()` 'ing them::

        user_mod.meta.auto_open = False
        user = user_mod.get(dn)
        user.props.groups == []
    """

    _udm_object_class = UdmObject
    _udm_module_meta_class = UdmModuleMetadata
    _new_object_templates: Dict[str, UdmObject] = {}

    class Meta:
        """
        This is not about versions of the UDM REST API. This is here only to
        provide better drop-in functionality when using this lib instead of the
        UDM Python API on a UCS system.
        """

        supported_api_versions = [0, 1, 2]
        suitable_for = ["*/*"]

    def __init__(self, name: str, session: Session):
        """

        :param name:
        :param session:
        :raises AttributeError: if UDM module with name `name`
            is unknown
        """
        super(UdmModule, self).__init__(name, session, 1)
        camel_case_name = _camel_case_name(name)
        if not hasattr(openapi_client_udm, f"{camel_case_name}Api"):
            raise UnknownModuleType(f"Unknown module: {name!r}.", module_name=name)
        self.session: Session = cast(Session, self.connection)
        # side effect: check that UDM module `name` exists:
        self.session.openapi_class(name)

    async def new(self, superordinate: str = None) -> UdmObject:
        """
        Create a new, unsaved BaseHttpObject object.

        :param superordinate: DN or UDM object this one references as its
            superordinate (required by some modules)
        :type superordinate: str or GenericObject
        :return: a new, unsaved :py:class:`udm_rest_client.UdmObject` object
        :rtype: udm_rest_client.UdmObject
        """
        if self.name not in self._new_object_templates:
            # TODO: turn superordinate into an ApiModel object for _load_udm_object()
            # await self._get_api_object(superordinate / superordinate.dn) ?
            self._new_object_templates[self.name] = await self._load_udm_object("", superordinate)
        new_obj = copy.deepcopy(self._new_object_templates[self.name])
        new_obj._udm_module = self
        return new_obj

    async def get(self, dn: str) -> UdmObject:
        """
        Load UDM object from LDAP.

        :param str dn: DN of the object to load
        :return: an existing :py:class:`udm_rest_client.BaseHttpObject` object
        :rtype: udm_rest_client.UdmObject
        :raises udm_rest_client.NoObject: if no object is found at `dn`
        :raises udm_rest_client.WrongObjectType: if the object found at `dn` is not of type :py:attr:`self.name`
        """
        return await self._load_udm_object(dn)

    async def search(
        self, filter_s: str = "", base: str = "", scope: str = "sub"
    ) -> AsyncIterator[UdmObject]:
        """
        Get all UDM objects from LDAP that match the given filter.

        :param str filter_s: LDAP filter (only object selector like uid=foo
            required, objectClasses will be set by the UDM module)
        :param str base: base dn for search
        :param str scope: one of `base`, `one`, `sub` or `children`
        :return: iterator of :py:class:`UdmObject` objects
        :rtype: Iterator(udm_rest_client.UdmObject)
        """
        params = {"hidden": "true"}
        if filter_s:
            params["filter"] = filter_s
        if base:
            params["position"] = base
        if scope:
            if scope not in ("sub", "base", "one"):
                raise ValueError("Argument 'scope' must be one of 'sub', base' or 'one'.")
            params["scope"] = scope

        api_model_objs, _, _ = await self.session.call_openapi(self.name, "search", **params)
        for obj in api_model_objs:
            yield await self._load_udm_object(api_obj=obj)

    async def _get_api_object(self, dn: str) -> ApiModel:
        """
        Retrieve UDM object from HTTP server.

        May raise from :py:exception:`NoObject` if no object is found for `dn`.

        :param str dn: the DN of the object to load, '' to load a template object
        :return: a ApiModel object
        :rtype: ApiModel
        :raises udm_rest_client.NoObject: if no object is found for `dn`
        """
        if dn == "":
            operation = "new"
            dn = None
        else:
            operation = "get"
        api_model_obj, status, header = await self.session.call_openapi(self.name, operation, dn=dn)
        return api_model_obj

    async def _load_udm_object(self, dn: str = None, api_obj: ApiModel = None) -> UdmObject:
        """
        UdmObject factory.

        Either `dn` or `api_obj` must be not be None.

        :param str dn: the DN of the UDM object to load, '' to load a new one
        :param api_obj: api object instance, if unset one will be loaded over
            HTTP using `dn`
        :return: a :py:class:`UdmObject`
        :rtype: udm_rest_client.UdmObject
        :raises udm_rest_client.NoObject: if no object is found for `dn`
        """
        if not api_obj:
            if dn is None:
                raise ValueError("Either 'dn' or 'api_obj' must be not be None.")
            api_obj = await self._get_api_object(dn)

        if api_obj.object_type == self.name:
            udm_module = self
        else:
            # probably only happens with users/self
            udm_module = UdmModule(api_obj.object_type, self.session)

        return await self._udm_object_class._new_from_api_object(api_obj=api_obj, udm_module=udm_module)


class DnPropertyEncoder:
    """
    Given a DN, return a string object with the DN and an additional member
    ``obj``. ``obj`` is a property that, when accessed, will return the UDM
    object the DN refers to. The property has to be `await` 'ed.
    """

    class DnStr(str):
        """
        A string with an additional member variable.
        """

        _property_name: str
        _dn: str
        _session: Session
        _udm_module_name: str

        def __deepcopy__(self, memodict=None) -> str:
            return str(self)

        @async_property
        async def obj(self) -> UdmObject:
            udm_module_name = self._udm_module_name or await self._session.get_object_type(self._dn)
            return await UdmModule(udm_module_name, self._session).get(self._dn)

    def __init__(self, property_name: str, dn: str, session: Session, udm_module_name: str = None):
        self.property_name = property_name
        self.dn = dn
        self.session = session
        self.udm_module_name = udm_module_name

    def decode(self) -> Union["DnPropertyEncoder.DnStr", None]:
        if self.dn in (None, ""):
            return None
        new_str = self.DnStr(self.dn)
        new_str._property_name = self.property_name
        new_str._dn = self.dn
        new_str._session = self.session
        new_str._udm_module_name = self.udm_module_name
        return new_str

    # @staticmethod
    # def encode(value: DnStr = None) -> Union[str, None]:
    #     if value is None:
    #         return None
    #     return str(value)
