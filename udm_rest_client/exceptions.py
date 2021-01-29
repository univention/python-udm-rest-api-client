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

from __future__ import unicode_literals


class UdmError(Exception):
    """Base class of Exceptions raised by (simplified) UDM modules."""

    msg: str = ""

    def __init__(self, msg: str = None, dn: str = None, module_name: str = None):
        msg = msg or self.msg
        super().__init__(msg)
        self.dn = dn
        self.module_name = module_name


class APICommunicationError(UdmError):
    """Raised when something goes wrong communicating."""

    def __init__(self, msg: str = None, status: int = None, reason: str = None):
        self.reason = reason
        self.status = status
        msg = msg or reason
        super().__init__(msg)


class ConfigurationError(UdmError):
    pass


class CreateError(UdmError):
    """Raised when an error occurred when creating an object."""

    pass


class DeletedError(UdmError):
    def __init__(self, msg: str = None, dn: str = None, module_name: str = None):
        msg = msg or "Object{} has already been deleted.".format(" {!r}".format(dn) if dn else "")
        super().__init__(msg, dn, module_name)


class NotYetSavedError(UdmError):
    """
    Raised when a client tries to delete or reload a UDM object that is not
    yet saved.
    """

    msg = "Object has not been created/loaded yet."


class MethodNotSupportedError(UdmError):
    """Raised if the API client does not support a method."""

    pass


class ModifyError(UdmError):
    """Raised if an error occurred when modifying an object."""

    pass


class MoveError(UdmError):
    """Raised if an error occurred when moving an object."""

    pass


class NoObject(UdmError):
    """Raised when a UDM object could not be found at a DN."""

    def __init__(self, msg: str = None, dn: str = None, module_name: str = None):
        msg = msg or f"No object found at DN {dn!r}."
        super().__init__(msg, dn, module_name)


class MultipleObjects(UdmError):
    """
    Raised when more than one UDM object was found when there should be at
    most one.
    """

    pass


class UnknownModuleType(UdmError):
    """
    Raised when an LDAP object has no or empty attribute univentionObjectType.
    """

    def __init__(self, msg: str = None, dn: str = None, module_name: str = None):
        msg = msg or f'No or empty attribute "univentionObjectType" found at DN {dn!r}.'
        super().__init__(msg, dn, module_name)
