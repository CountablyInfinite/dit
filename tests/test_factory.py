""" Module providing very basic unit tests for factory class"""
import unittest
from src.configuration import ConfigFileParser, ArgParser
import src.factory as factory
from src.proxy import Proxy

class TestFactory(unittest.TestCase):
    """Class providing very basic unit tests for the factory class."""

    def __init__(self, *args, **kwargs):
        super(TestFactory, self).__init__(*args, **kwargs)
        config_file_parser = factory.dit_factory(
                                        instance_type=factory.InstanceTypes.CONFIG_FILE_PARSER,
                                        config=None,
                                        name="Config File Parser")
        self.config_file_config = config_file_parser.parse_config_file("tests/test_dit_config.yaml")
        arg_parser = factory.dit_factory(instance_type=factory.InstanceTypes.ARG_PARSER,
                                         config=self.config_file_config,
                                         name="Config Arg Parser")
        self.config = arg_parser.parse_arguments(testargs=["start"])

    def test_config_file_parser_instance(self):
        """Method providing a very basic test for a config file parser instance."""
        instance = factory.dit_factory(instance_type=factory.InstanceTypes.CONFIG_FILE_PARSER,
                                       config=None,
                                       name="Test Config File Parser")
        self.assertTrue(isinstance(instance, ConfigFileParser))
        self.assertEqual(instance.name, "Test Config File Parser")

    def test_arg_parser_instance(self):
        """Method providing a very basic test for an arg parser instance."""
        instance = factory.dit_factory(instance_type=factory.InstanceTypes.ARG_PARSER,
                                       config=self.config_file_config,
                                       name="Test Arg Parser")
        self.assertTrue(isinstance(instance, ArgParser))
        self.assertEqual(instance.name, "Test Arg Parser")

    def test_proxy_instance(self):
        """Method providing a very basic test for a proxy instance."""
        instance = factory.dit_factory(instance_type=factory.InstanceTypes.PROXY,
                                       config=self.config,
                                       name="Test Proxy")
        self.assertTrue(isinstance(instance, Proxy))
        self.assertEqual(instance.name, "Test Proxy")

    def test_client_instance(self):
        """Method providing a very basic test for a client instance."""
        instance = factory.dit_factory(instance_type=factory.InstanceTypes.CLIENT_HANDLER,
                                       config=self.config,
                                       name="Test Client Handler")
        self.assertTrue(isinstance(instance, factory.DtlsClientHandler))
        self.assertEqual(instance.name, "Test Client Handler")

    def test_server_instance(self):
        """Method providing a very basic test for a server instance."""
        instance = factory.dit_factory(instance_type=factory.InstanceTypes.SERVER_HANDLER,
                                       config=self.config,
                                       name="Test Server Handler")
        self.assertTrue(isinstance(instance, factory.DtlsServerHandler))
        self.assertEqual(instance.name, "Test Server Handler")

if __name__ == '__main__':
    unittest.main()
