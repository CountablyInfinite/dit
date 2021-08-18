"""Module providing classes to parse cli arguments and config files and to check configurations
for errors"""
from argparse import ArgumentParser, RawDescriptionHelpFormatter, FileType
from ipaddress import ip_address
from subprocess import CalledProcessError
import logging
import sys
import yaml
from .utilities import get_mac_address, check_for_root, get_mtu


class ConfigFileParser():
    """Class providing methods to parse a YAML configuration file returning a dict."""

    def __init__(self, name):
        self.name = name
        self._logger = logging.getLogger(self.name)
        self._logger.debug(f"Creating a new {self.__class__.__name__} instance")

    def parse_config_file(self, path):
        """Loads yaml file in path and returns content as python dict"""
        self._logger.debug(f"Parsing configuration file: {path}")
        try:
            with open(path, "r", encoding="utf-8") as config_file:
                config = yaml.load(config_file, Loader=yaml.FullLoader)
        except FileNotFoundError:
            self._logger.error(f"Configuration file {path} not found")
            raise FileNotFoundError
        return config

class ArgParser(ArgumentParser):
    """Class providing methods and checks to parse command line arguments."""

    def __init__(self, config, name):
        super().__init__(description=("\ncheck configuration stored in ./config./dit_config.yaml before"
                                      " running DIT. \nedit file or use optional command line"
                                      " arguments to override the default configuration. \nDIT needs"
                                      " root privileges and custom iptable rules to work"
                                      " properly."),
                         usage="./dit.py [optional arguments] start",
                         epilog=("examples:\n"
                                 "./dit.py -isi 192.168.0.1 -isp 1337 -ici 192.168.0.2 "
                                 "--ciphers TLS-PSK-WITH-AES-128-CCM-8 TLS-PSK-WITH-CHACHA20-"
                                 "POLY1305-SHA256 -psk DIT_secret start\n./dit.py --iot_srv_ip"
                                 " 192.168.0.1 --iot_cli_ip 192.168.0.2 --use_cert "
                                 "--key_size 3072 --ciphers TLS-RSA-WITH-AES-128-GCM-SHA256 "
                                 "--verbose start\n./dit.py -isi 192.168.0.1 -ici 192.168.0"
                                 ".2 --use_cert -ecc --output_file logfile.log --verbose start"
                                 "\n\nthis tool has been created for the purposes of academic "
                                 "research. \nuse responsibly and only when explicitly "
                                 "authorized."),
                         formatter_class=RawDescriptionHelpFormatter,
                         # disable help flag so we can use our own implementation
                         add_help=False)
        self.name = name
        self._config = config
        self._logger = logging.getLogger(self.name)
        self._logger.debug(f"Creating a new {self.__class__.__name__} instance")
        self._add_args()

    def error(self, message):
        """Overrides the default ARGS error method, so a custom behaivior can be provided."""
        sys.stderr.write(f"error: {message}\n")
        self.print_help()
        sys.exit(2)

    def _add_args(self):
        """Wrapper method calling all specific functions to create argument groups and agruments."""
        self._add_run_args()
        self._add_target_args()
        self._add_interface_args()
        self._add_psk_args()
        self._add_certificate_args()
        self._add_local_services_args()
        self._add_misc_args()

    def _add_run_args(self):
        """Method creating a 'run DIT' arg. group and all neccessary arguments."""
        run_args = self.add_argument_group("run DIT")
        run_args.add_argument("start",
                              help=("run DIT with the current settings (args override config file "
                                   "settings)"))

    def _add_target_args(self):
        """Method creating a 'target configuration' arg. group and all neccessary arguments."""
        t_args = self.add_argument_group("target configuration")
        t_args.add_argument("-isi",
                            "--iot_srv_ip",
                            metavar="",
                            type=str,
                            help=("iot server ip address (listening service) to be intercepted "
                                  f"(config file: {self._config['targets']['iot_srv_ip']})"),
                            default=self._config['targets']['iot_srv_ip'])
        t_args.add_argument("-isp",
                            "--iot_srv_po",
                            metavar="",
                            type=int,
                            help=("iot server port to be intercepted. (config file: "
                                  f"{self._config['targets']['iot_srv_po']})"),
                            default=self._config['targets']['iot_srv_po'])
        t_args.add_argument("-ici",
                            "--iot_cli_ip",
                            metavar="",
                            type=str,
                            help=("iot client ip address to be intercepted. (config file: "
                                  f"{self._config['targets']['iot_cli_ip']})"),
                            default=self._config['targets']['iot_cli_ip'])

    def _add_interface_args(self):
        """Method creating an 'interface configuration' arg. group and all neccessary arguments."""
        if_args = self.add_argument_group("interface configuration")
        if_args.add_argument("-eif",
                             "--ex_if_name",
                             metavar="",
                             type=str,
                             help=("external interface name (e.g. \"eth0\") to listen for incoming "
                                   "connections. (config file: "
                                   f"{self._config['interfaces']['ex_if_name']})"),
                             default=self._config['interfaces']['ex_if_name'])
        if_args.add_argument("-lif",
                             "--lh_if_name",
                             metavar="",
                             type=str,
                             help=("local interface name (e.g. \"lo\") to communicate with local "
                                   "services. (config file: "
                                   f"{self._config['interfaces']['lh_if_name']})"),
                                  default=self._config['interfaces']['lh_if_name'])

    def _add_psk_args(self):
        """Method creating a 'psk configuration' argument group and all neccessary arguments."""
        psk_args = self.add_argument_group("psk configuration")
        psk_args.add_argument("-cid",
                              "--cli_id",
                              metavar="",
                              type=str,
                              help=("client identity to configure server and client handler with. "
                                    f"(config file: {self._config['psk']['cli_id']})"),
                              default=self._config['psk']['cli_id'])
        psk_args.add_argument("-psk",
                              "--pre_sh_key",
                              metavar="",
                              type=str,
                              help=("pre-shared key to configure server and client handler with. "
                                    f"(config file: {self._config['psk']['pre_sh_key']})"),
                              default=self._config['psk']['pre_sh_key'])
        psk_args.add_argument("--ciphers",
                              metavar="",
                              nargs="+",
                              type=str,
                              help=("list of ciphers to use, separated by spaces. (config file: "
                                   f"{self._config.get('targets').get('ciphers')})"),
                              # Read ciphers from config file, (None-> Use all available ciphers)
                              default=self._config.get('targets', None).get('ciphers', None))

    def _add_certificate_args(self):
        """Method creating a 'certificate configuration' arg group and all neccessary arguments."""
        crt_args = self.add_argument_group("certificate configuration")
        crt_args.add_argument("-cer",
                              "--use_cert",
                              help=("[FLAG] use certificates as a method of authentication "
                                   "(instead of a psk). (config file: "
                                   f"{self._config.get('certificate').get('use_cert') or False})"),
                              default=self._config.get('certificate').get('use_cert') or False,
                              action='store_true')
        crt_args.add_argument("-ks",
                              "--key_size",
                              metavar="",
                              type=int,
                              help=("length of the RSA/ECC key in bits. (config file: "
                                    f"{self._config.get('certificate').get('key_size')})"),
                              default=self._config.get('certificate').get('key_size') or 2048)
        crt_args.add_argument("-ecc",
                              "--use_ecc",
                              help=("[FLAG] use 521 bit ECC instead of RSA to generate a key pair."
                                    " disables --key_size. (config file: "
                                    f"{self._config.get('certificate').get('use_ecc') or False})"),
                              default=self._config.get('certificate').get('use_ecc') or False,
                              action='store_true')

    def _add_local_services_args(self):
        """Method creating a 'local services configuration' argument group and all neccessary
        arguments."""
        local_services_args = self.add_argument_group("local services configuration")
        local_services_args.add_argument("-lci",
                                         "--lh_cli_ip",
                                         metavar="",
                                         type=str,
                                         help=("local ip address to start a client handler "
                                               "(DTLS server) on. (config file: "
                                               f"{self._config['local_services']['lh_cli_ip']})"),
                                         default=self._config['local_services']['lh_cli_ip'])
        local_services_args.add_argument("-lcp",
                                         "--lh_cli_po",
                                         metavar="",
                                         type=int,
                                         help=("local port to start a client handler (DTLS server "
                                               "listener) on. (config file: "
                                               f"{self._config['local_services']['lh_cli_po']})"),
                                         default=self._config['local_services']['lh_cli_po'])
        local_services_args.add_argument("-lsi",
                                         "--lh_srv_ip",
                                         metavar="",
                                         type=str,
                                         help=("local ip address to connect a server handler "
                                               "(DTLS client) to. (config file: "
                                               f"{self._config['local_services']['lh_srv_ip']})"),
                                         default=self._config['local_services']['lh_srv_ip'])
        local_services_args.add_argument("-lsp",
                                         "--lh_srv_po",
                                         metavar="",
                                         type=int,
                                         help=("local port to connect a server handler "
                                               "(DTLS client) to. (config file: "
                                               f"{self._config['local_services']['lh_srv_po']})"),
                                         default=self._config['local_services']['lh_srv_po'])

    def _add_misc_args(self):
        """Method creating a 'miscellaneous' argument group and all neccessary arguments."""
        misc_args = self.add_argument_group("miscellaneous")
        misc_args.add_argument("-ibl",
                               "--icmp_block",
                               help=("[FLAG] automatically create an iptables rule to suppress icmp"
                                     " 'destination unreachable' messages"),
                               action='store_true')
        misc_args.add_argument("-o",
                               "--output_file",
                               metavar="",
                               type=FileType('w'),
                               help=("append intercepted unencrypted messages to an output file"))
        misc_args.add_argument("-v",
                               "--verbose",
                               help="[FLAG] increase verbosity to DEBUG level",
                               action='store_true')
        # override default help arg so we can order arguments
        misc_args.add_argument("-h",
                               "--help",
                               action="help",
                               help="[FLAG] show this help text and exit")

    def parse_arguments(self, testargs=None):
        """Method to parse all cli args. (Cli args overwrite dit_config.yaml.)"""
        args = self.parse_args(testargs)
        self._logger.debug("Checking for root privileges")
        if check_for_root():
            self._logger.debug("User id = 0. User is root")
            return self._create_config(args)
        else:
            self.error("User has insufficient privileges")

    def _get_mac_address(self, config):
        """Method to get a MAC adress for a given interface"""
        try:
            self._logger.debug("Trying to parse mac address for interface name "
                               f"{config.get('ex_if_name')}")
            config.update(ex_if_mac = get_mac_address(config.get('ex_if_name')))
            self._logger.debug(f"Mac address for interface name {config.get('ex_if_name')} is "
                               f"{config.get('ex_if_mac')}")
        except FileNotFoundError:
            self._logger.error(f"Unable to parse mac address for {config.get('ex_if_name')}. "
                               "Unknown interface")
            raise ValueError
        return config

    def _get_mtu(self, config):
        """Method to get MTUs for internal and external interface"""
        try:
            self._logger.debug("Trying to parse interface mtu for interface name "
                               f"{config.get('ex_if_name')}")
            config.update(ex_if_mtu = get_mtu(config.get('ex_if_name')))
            self._logger.debug(f"MTU for interface name {config.get('ex_if_name')} is "
                               "{config.get('ex_if_mtu')}")
        except CalledProcessError:
            self._logger.error("Unable to parse mtu for interface name "
                               f"{config.get('ex_if_name')}.")
            raise ValueError
        try:
            self._logger.debug("Trying to parse interface mtu for interface name "
                               f"{config.get('lh_if_name')}")
            config.update(lh_if_mtu = get_mtu(config.get('lh_if_name')))
            self._logger.debug(f"MTU for interface name {config.get('lh_if_name')} is "
                               f"{config.get('lh_if_mtu')}")
        except CalledProcessError:
            self._logger.error("Unable to parse mtu for interface name "
                               f"{config.get('lh_if_name')}.")
            raise ValueError
        return config

    def _create_config(self, args):
        """Method to parse all args into a dict and update the config with some additional
        information"""
        config = {}
        for arg in vars(args):
            if arg=="start":
                # check if additional positional parameters are given and throw error if so
                if getattr(args, arg) != "start":
                    self.error(f"unrecognized arguments: {getattr(args, arg)}")
            elif arg=="ciphers":
                # set ciphersuites, if none are specified, set parameter to None
                try:
                    # mbedtls expects ciphers as tuple -> typecast value to tulpe
                    config.update({arg:tuple(getattr(args, arg))})
                except TypeError:
                    self._logger.debug("No ciphers specified, offering all suites available "
                                       "with mbedTLS")
                    config.update({"ciphers":None})
            else:
                config.update({arg:getattr(args, arg)})
        config = self._get_mac_address(config)
        config = self._get_mtu(config)
        return config

class ConfigChecker():
    """Class providing methods to execute sanity checks on a given dit configuration dict"""

    def __init__(self, config, name):
        self.name = name
        self._logger = logging.getLogger(self.name)
        if config.get('verbose'):
            self._logger.setLevel(logging.DEBUG)
        self._logger.debug(f"Creating a new {self.__class__.__name__} instance")

    def check_config(self, config):
        """Method to call all implemented checks for a given dit configuration"""
        self._logger.debug("Checking configuration for errors")
        for key, value in config.items():
            if "_ip" in key:
                self._check_ipv4_format(key, value)
            if "_po" in key:
                self._check_port_format(key,value)
            if key == "key_size":
                self._check_key_size(key,value)
            if key == "lh_if_mtu":
                self._check_lh_mtu(value)
        self._print_config(config)

    def _check_ipv4_format(self, param, ipv4_value):
        """Method to check if a value is a valid ipv4 address."""
        try:
            # assume it is a valid ipv4 value and catch exceptions
            ip_address(ipv4_value)
        except ValueError:
            self._logger.error(f"{param}: {ipv4_value} is not a valid IPv4 address")
            raise ValueError

    def _check_port_format(self, param, port):
        """Method to check if a port number is within a valid range."""
        try:
            if not (isinstance(port, int) and (0 < port < 65536)):
                raise ValueError
        except ValueError:
            self._logger.error(f"{param}: {port} is not a valid port number")
            raise ValueError

    def _check_key_size(self, param, key_size):
        """Method to check if key size is within a reasonable range."""
        try:
            # default value is 2048
            if not (isinstance(key_size, int) and (0 < key_size < 16384)):
                raise ValueError
        except ValueError:
            self._logger.error(f"{param}: {key_size} is not a valid key size for RSA")
            raise ValueError

    def _check_lh_mtu(self, mtu_size):
        """Method to check if the mtu is 65536 on localhost. Issues a warning if this not the
        case"""
        if mtu_size < 65536:
            self._logger.warning(f"MTU of interface localhost: {mtu_size} is < 65536. "
                                 "This can cause errors with fragmented packets.")

    def _print_config(self, config):
        """"Mehtod to print a summarization of the current config to stdout"""
        self._logger.info("Configuration summary:")
        self._logger.info(" " + f"- IoT server: {config.get('iot_srv_ip')}")
        self._logger.info(" " + f"- IoT server port: {config.get('iot_srv_po')}")
        self._logger.info(" " + f"- IoT client: {config.get('iot_cli_ip')}")
        if config.get('use_cert'):
            if config.get('use_ecc'):
                self._logger.info(" " + "- Using ECC 521b and following ciphers: "
                                  f"{config.get('ciphers') or 'ALL AVAILABLE'}")
            else:
                self._logger.info(" " + f"- Using RSA {config.get('key_size')} and following "
                                  f"ciphers: {config.get('ciphers') or 'ALL AVAILABLE'}")
        else:
            self._logger.info(" " + f"- Using PSK: {config.get('pre_sh_key')}, client identity: "
                              f"{config.get('cli_id')} and following ciphers: "
                              f"{config.get('ciphers') or 'ALL AVAILABLE'}")
        if config.get('output_file'):
            self._logger.info(" " + "- Writing decrypted datagram payload to "
                              f"{config.get('output_file').name}")
