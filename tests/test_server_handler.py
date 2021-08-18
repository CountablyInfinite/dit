""" Module providing very basic unit tests for the server handler class."""
import unittest
from mbedtls import tls
import src.factory as factory


class TestServerHandler(unittest.TestCase):
    """Class providing very basic unit tests for the server handler class."""

    def __init__(self, *args, **kwargs):
        super(TestServerHandler, self).__init__(*args, **kwargs)
        config_file_parser = factory.dit_factory(
                                instance_type=factory.InstanceTypes.CONFIG_FILE_PARSER,
                                config=None,
                                name="Config File Parser")
        self.config_file_config = config_file_parser.parse_config_file("tests/test_dit_config.yaml")
        arg_parser = factory.dit_factory(instance_type=factory.InstanceTypes.ARG_PARSER,
                                config=self.config_file_config,
                                name="Config Arg Parser")
        self.config = arg_parser.parse_arguments(testargs=["start"])

    def test_parameters(self):
        """Method providing a very basic parameter test."""
        server_handler = factory.dit_factory(instance_type=factory.InstanceTypes.SERVER_HANDLER,
                                config=self.config,
                                name="Test Server Handler")
        self.assertEqual(server_handler._target_ip, "127.0.0.1")
        self.assertEqual(server_handler._target_port, 1339)

    def test_versions(self):
        """Method providing a very basic DTLS version test."""
        server_handler = factory.dit_factory(instance_type=factory.InstanceTypes.SERVER_HANDLER,
                                config=self.config,
                                name="Test Server Handler")
        self.assertEqual(server_handler._context.configuration.lowest_supported_version,
                         tls.DTLSVersion.DTLSv1_0)
        self.assertEqual(server_handler._context.configuration.highest_supported_version,
                         tls.DTLSVersion.DTLSv1_2)

    def test_psk_ciphers(self):
        """Method providing a very basic psk cipher test."""
        server_handler = factory.dit_factory(instance_type=factory.InstanceTypes.SERVER_HANDLER,
                                             config=self.config,
                                             name="Test Server Handler")
        self.assertEqual(server_handler._context.configuration.pre_shared_key,
                         ('Client_identity', b'DIT_secret'))
        self.assertEqual(server_handler._context.configuration.ciphers,
                         ('TLS-PSK-WITH-AES-128-CCM-8', 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384'))

if __name__ == '__main__':
    unittest.main()
