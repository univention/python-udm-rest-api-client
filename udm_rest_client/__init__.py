# -*- coding: utf-8 -*-

"""Top-level package for Python UDM REST Client."""
__author__ = """Daniel Troeder"""
__email__ = "troeder@univention.de"
__version__ = "1.2.3"

from .base_http import UdmModule, UdmObject
from .exceptions import (
    APICommunicationError,
    ConfigurationError,
    CreateError,
    DeletedError,
    ModifyError,
    MoveError,
    MultipleObjects,
    NoObject,
    NotYetSavedError,
    UdmError,
    UnknownModuleType,
)
from .udm import UDM

__all__ = [
    "UDM",
    "UdmModule",
    "UdmObject",
    "ConfigurationError",
    "CreateError",
    "DeletedError",
    "NotYetSavedError",
    "ModifyError",
    "MoveError",
    "MultipleObjects",
    "NoObject",
    "UdmError",
    "UnknownModuleType",
    "APICommunicationError",
]
