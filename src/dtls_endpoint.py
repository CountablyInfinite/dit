"""Module providing a parent class for DtlsClientHandler and DtlsServerHandler."""
import logging
from multiprocessing import Lock
from abc import ABC, abstractmethod
from contextlib import suppress
from mbedtls import tls


class DtlsEndpoint(ABC):
    """Parent class providing all common methods for DtlsClientHandler and DtlsServerHandler."""

    logfile_lock = Lock()

    def __init__(self, config, name, instance_type):
        self.name = name
        self._config = config
        self._logger = logging.getLogger(self.name)
        if config.get('verbose'):
            self._logger.setLevel(logging.DEBUG)
        self._logger.debug(f"Creating a new {instance_type} instance")
        self._context = self._set_context()

    def _block(self, callback, *args, **kwargs):
        """A blocking call supressing specific mbedTLS exceptions as specified in official
        documentation."""
        while True:
            with suppress(tls.WantReadError, tls.WantWriteError):
                return callback(*args, **kwargs)

    def _write_to_logfile(self, message):
        """Method to write a message to a logfile configured with a misc. cli arg."""
        # set lock before accessing file (multiple process are writing to this file)
        with self.logfile_lock:
            with open(self._config.get('output_file').name, "a") as logfile:
                logfile.write(message)

    @abstractmethod
    def _set_context(self):
        """Method to set a dtls context for an upcoming connection."""

    @abstractmethod
    def _wrap_socket(self, context):
        """Method to wrap a socket with a given dtls context."""

    @abstractmethod
    def _establish_connection(self, context, ip, port):
        """Method to establish a connection with a certain ip:port using a preset context."""

    @abstractmethod
    def _manipulate_payload(self, payload):
        """Method to manipulate a given payload to another preset payload."""
