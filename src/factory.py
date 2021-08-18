"""This module provides a factory as a common interface for other DIT module to create new
InstanceTypes objects."""
from enum import Enum, auto
from .dtls import DtlsClientHandler, DtlsServerHandler
from .proxy import Proxy
from .configuration import ArgParser, ConfigFileParser, ConfigChecker


class InstanceTypes(Enum):
    """Configures instance types that can be created with the factory"""
    CLIENT_HANDLER = auto()
    SERVER_HANDLER = auto()
    PROXY = auto()
    CONFIG_FILE_PARSER = auto()
    ARG_PARSER = auto()
    CONFIG_CHECKER = auto()

def dit_factory(instance_type, config, name):
    """Returns an object of the given instance type"""
    if instance_type == InstanceTypes.CLIENT_HANDLER:
        return DtlsClientHandler(config, name)
    elif instance_type == InstanceTypes.SERVER_HANDLER:
        return DtlsServerHandler(config, name)
    elif instance_type == InstanceTypes.PROXY:
        return Proxy(config, name)
    elif instance_type == InstanceTypes.CONFIG_FILE_PARSER:
        return ConfigFileParser(name)
    elif instance_type == InstanceTypes.ARG_PARSER:
        return ArgParser(config, name)
    elif instance_type == InstanceTypes.CONFIG_CHECKER:
        return ConfigChecker(config, name)
    else:
        raise ValueError("Unknown instance type.")
