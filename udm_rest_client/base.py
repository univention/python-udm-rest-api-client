# -*- coding: utf-8 -*-
#
# Copyright 2018-2019 Univention GmbH
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
Base classes for (simplified) UDM modules and objects.
"""

import collections
import copy
import pprint
from typing import Any, Dict, Iterable, Iterator, Tuple, Union

LdapMapping = collections.namedtuple("LdapMapping", ("ldap2udm", "udm2ldap"))


class BaseObjectProperties(collections.abc.Mapping, collections.abc.Iterable):
    """Container for UDM properties."""

    def __init__(self, udm_obj: "BaseObject") -> None:
        self._udm_obj = udm_obj

    def __contains__(self, item) -> bool:
        return hasattr(self, item)

    def __deepcopy__(self, memo: Dict[int, "BaseObjectProperties"]) -> "BaseObjectProperties":
        id_self = id(self)
        if not memo.get(id_self):
            memo[id_self] = self.__class__(self._udm_obj)
            for k, v in self.__dict__.items():
                if k == "_udm_obj":
                    setattr(memo[id_self], k, v)
                else:
                    setattr(memo[id_self], k, copy.deepcopy(v))
        return memo[id_self]

    def __eq__(self, other: "BaseObjectProperties") -> bool:
        # compare keys first (fast and low memory)
        if set(self.keys()) != set(other.keys()):
            return False
        # compare values one at a time to reduce memory usage
        for k, v in self.items():
            if v != getattr(other, k):
                return False
        return True

    def __getitem__(self, key):
        try:
            return getattr(self, key)
        except AttributeError as exc:
            raise KeyError(f"{self.__class__.__name__} does not have key {key!r}.") from exc

    def __iter__(self) -> Iterator[str]:
        return (k for k in self.__dict__.keys() if not str(k).startswith("_"))

    def __len__(self):
        return len(list(self.keys()))

    def __repr__(self) -> str:
        return "{}({})".format(
            self.__class__.__name__,
            pprint.pformat(dict((k, v) for k, v in self.items()), indent=2),
        )

    def __setitem__(self, key, value):
        if key not in self:
            raise TypeError(f"Assignment to non existent attribute {key!r} forbidden.")
        setattr(self, key, value)

    def items(self) -> Iterable[Tuple[str, Any]]:
        return ((k, v) for k, v in self.__dict__.items() if not str(k).startswith("_"))

    def keys(self) -> Iterable[str]:
        return (k for k in iter(self))

    def update(self, other: "BaseObjectProperties" = None, **kwargs) -> None:
        for k in other or []:
            self[k] = other[k]
        for k in kwargs:
            self[k] = kwargs[k]

    def values(self) -> Iterable[Any]:
        return (v for k, v in self.__dict__.items() if not str(k).startswith("_"))


class BaseObject:
    """
    Base class for UDM object classes.

    Usage:

    *   Creation of instances is always done through
        :py:meth:`BaseModule.new`, :py:meth:`BaseModule.get` or :py:meth:`BaseModule.search`.

    *   Modify an object::

          user.props.firstname = 'Peter'
          user.props.lastname = 'Pan'
          user.save()

    *   Move an object::

          user.position = 'cn=users,ou=Company,dc=example,dc=com'
          user.save()

    *   Delete an object::

          obj.delete()

    After saving a :py:class:`BaseObject`, it is :py:meth:`.reload` 'ed
    automatically because UDM hooks and listener modules often add, modify or
    remove properties when saving to LDAP. As this involves LDAP, it can be
    disabled if the object is not used afterwards and performance is an issue::

        user_mod.meta.auto_reload = False
    """

    udm_prop_class = BaseObjectProperties

    def __init__(self):
        """
        Don't instantiate a :py:class:`BaseObject` directly. Use
        :py:meth:`BaseModule.get()`, :py:meth:`BaseModule.new()` or
        :py:meth:`BaseModule.search()`.
        """
        self.dn: str = ""
        self.props: BaseObjectProperties = None
        self.options: Dict[str:bool] = {}
        self.policies: Dict[str, str] = {}
        self.position: str = ""
        self.superordinate: str = None
        self._udm_module: BaseModule = None

    def __eq__(self, other: "BaseObject") -> bool:
        if self._udm_module.name != other._udm_module.name:
            return False
        for attr in ("dn", "options", "props", "policies", "position", "superordinate"):
            if getattr(self, attr) != getattr(other, attr):
                return False
        return True

    def __repr__(self) -> str:
        return "{}({!r}, {!r})".format(
            self.__class__.__name__,
            self._udm_module.name if self._udm_module else "<not initialized>",
            self.dn,
        )

    def reload(self) -> "BaseObject":
        """
        Refresh object from LDAP.

        :return: self
        :rtype: BaseObject
        """
        raise NotImplementedError()

    def save(self) -> "BaseObject":
        """
        Save object to LDAP.

        :return: self
        :rtype: BaseObject
        :raises univention.udm.exceptions.MoveError: when a move operation fails
        """
        raise NotImplementedError()

    def delete(self) -> None:
        """
        Remove the object from the LDAP database.

        :return: None
        """
        raise NotImplementedError()


class BaseModuleMetadata:
    """Base class for UDM module meta data."""

    auto_open = True
    """Whether UDM objects should be ``open()`` 'ed."""
    auto_reload = True
    """Whether UDM objects should be ``reload()`` 'ed after saving."""

    def __init__(self, meta: "BaseModule.Meta") -> None:
        self.supported_api_versions: Iterable[int] = []
        self.suitable_for: Iterable[str] = []
        self.used_api_version: int = None
        self._udm_module: BaseModule = None
        if hasattr(meta, "supported_api_versions"):
            self.supported_api_versions = meta.supported_api_versions
        if hasattr(meta, "suitable_for"):
            self.suitable_for = meta.suitable_for

    def __repr__(self) -> str:
        return "{}({})".format(
            self.__class__.__name__,
            ", ".join(
                "{}={!r}".format(k, v) for k, v in self.__dict__.items() if not str(k).startswith("_")
            ),
        )

    def instance(self, udm_module: "BaseModule", api_version: int) -> "BaseModuleMetadata":
        cpy = copy.deepcopy(self)
        cpy._udm_module = udm_module
        cpy.used_api_version = api_version
        return cpy

    @property
    def identifying_property(self) -> str:
        """
        UDM property of which the mapped LDAP attribute is used as first
        component in a DN, e.g. `username` (LDAP attribute `uid`) or `name`
        (LDAP attribute `cn`).
        """
        raise NotImplementedError()

    def lookup_filter(self, filter_s: str = None) -> str:
        """
        Filter the UDM module uses to find its corresponding LDAP objects.

        This can be used in two ways:

        * get the filter to find all objects::

              myfilter_s = obj.meta.lookup_filter()

        * get the filter to find a subset of the corresponding LDAP objects
          (`filter_s` will be combined with `&` to the filter for all objects)::

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


class BaseModuleMeta(type):
    """
    This is not a subclass of :py:class:`univention.udm.plugins.Plugin`, like
    in the original :py:class:`univention.udm.base.ModuleMeta`, because we
    don't need to load module specific code in the client.
    """

    udm_meta_class = BaseModuleMetadata

    def __new__(mcs, name, bases, attrs):
        meta = attrs.pop("Meta", None)
        new_cls_meta = mcs.udm_meta_class(meta)
        new_cls = super(BaseModuleMeta, mcs).__new__(mcs, name, bases, attrs)
        new_cls.meta = new_cls_meta
        return new_cls


class BaseModule(metaclass=BaseModuleMeta):
    """
    Base class for UDM module classes. UDM modules are basically UDM object
    factories.

    Usage:

    0.  Get module using::

            user_mod = UDM().get('users/user')

    1.  Create fresh, not yet saved BaseObject::

            new_user = user_mod.new()

    2.  Load an existing object::

            group = group_mod.get('cn=test,cn=groups,dc=example,dc=com')
            group = group_mod.get_by_id('Domain Users')

    3.  Search and load existing objects::

            dc_slaves = dc_slave_mod.search(filter_s='cn=s10*')
            campus_groups = group_mod.search(base='ou=campus,dc=example,dc=com')

    4.  Load existing object(s) without ``open()`` 'ing them::

            user_mod.meta.auto_open = False
            user = user_mod.get(dn)
            user.props.groups == []
    """

    _udm_object_class = BaseObject
    _udm_module_meta_class = BaseModuleMetadata

    class Meta:
        supported_api_versions: Iterable[int] = ()
        suitable_for: Iterable[str] = []

    def __init__(self, name: str, connection: Any, api_version: int) -> None:
        self.connection = connection
        self.name: str = name
        self.meta: BaseModuleMetadata = self.meta.instance(self, api_version)

    def __repr__(self) -> str:
        return "{}({!r})".format(self.__class__.__name__, self.name)

    def new(self, superordinate: Union[str, BaseObject] = None) -> BaseObject:
        """
        Create a new, unsaved :py:class:`BaseObject` object.

        :param superordinate: DN or UDM object this one references as its
            superordinate (required by some modules)
        :type superordinate: str or GenericObject
        :return: a new, unsaved BaseObject object
        :rtype: BaseObject
        """
        raise NotImplementedError()

    def get(self, dn: str) -> BaseObject:
        """
        Load UDM object from LDAP.

        :param str dn: DN of the object to load.
        :return: an existing :py:class:`BaseObject` instance.
        :rtype: BaseObject
        :raises univention.udm.exceptions.NoObject: if no object is found at `dn`
        :raises univention.udm.exceptions.WrongObjectType: if the object found at `dn` is not of type :py:attr:`self.name`
        """
        raise NotImplementedError()

    def search(self, filter_s: str = "", base: str = "", scope: str = "sub") -> Iterator[BaseObject]:
        """
        Get all UDM objects from LDAP that match the given filter.

        :param str filter_s: LDAP filter (only object selector like `uid=foo`
            required, `objectClasses` will be set by the UDM module)
        :param str base: LDAP search base.
        :param str scope: LDAP search scope, e.g. `base` or `sub` or `one`.
        :return: iterator of :py:class:`BaseObject` objects
        :rtype: Iterator(BaseObject)
        """
        raise NotImplementedError()
