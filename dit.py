#!/usr/bin/env python3
"""Entry point. Configures and starts logger, config parser, proxy and client/server handler 
instances."""
import logging
import sys
from src.factory import InstanceTypes, dit_factory
from src.utilities import activate_icmp_blocking, deactivate_icmp_blocking, print_signature

def setup_logger():
    """Setup logger configuration, log level and format."""
    logging.basicConfig(format='%(asctime)s || %(levelname)s || %(name)s || %(message)s', 
                        level=logging.INFO)
    logger = logging.getLogger("DIT")
    logger.debug("Logger initialized")
    return logger

def read_config_file(path):
    """Parse a configuration file and return config."""
    config_parser = dit_factory(instance_type=InstanceTypes.CONFIG_FILE_PARSER, config=None, 
                                name="Config Parser")
    config = config_parser.parse_config_file(path)
    return config

def read_args(current_config):
    """Parse command line args and return config."""
    arg_parser = dit_factory(instance_type=InstanceTypes.ARG_PARSER, config=current_config, 
                             name="Argument Parser")
    config = arg_parser.parse_arguments()
    return config

def enable_icmp_rule(config, logger):
    """Trys to enable ip rules to block icmp messages for the configured targets."""
    logger.debug(f"Enabling the following iptables rule: iptables -I OUTPUT "
                 f"{config.get('lh_cli_ip')} -p icmp --icmp-type destination-unreachable -j DROP")
    activate_icmp_blocking(config)

def increase_verbosity(logger):
    """Increase the verbosity level of a given logger object."""
    logger.setLevel(logging.DEBUG)
    logger.info(f"Raised log level to {logging.getLevelName(logger.level)}")

def check_configuration(config):
    """Check the current configuration for errors."""
    config_checker = dit_factory(instance_type=InstanceTypes.CONFIG_CHECKER, config=config, 
                                 name="Config Checker")
    config_checker.check_config(config)

def shutdown_dit(logger):
    """Shuts dit down gracefully."""
    logger.info("Shutting down DIT")
    sys.exit(0)

def main():
    """Main routine to parse config file and command line arguments, start proxy layer and run DTLS 
    handlers with a given config file."""
    print_signature()
    logger = setup_logger()
    logger.debug("Starting DIT services")

    try:
        config_file = read_config_file("config/dit_config.yaml")
    except FileNotFoundError:
        shutdown_dit(logger)
    except Exception as unexpected_error:
        logger.error(f"Unexpected error while reading config file: {unexpected_error}")
        shutdown_dit(logger)

    try:
        config = read_args(config_file)
    except ValueError:
        shutdown_dit(logger)
    except Exception as unexpected_error:
        logger.error(f"Unexpected error while reading cli arguments: {unexpected_error}")
        shutdown_dit(logger)

    # increase verbosity if verbose cli arg has been set
    if config.get('verbose'):
        increase_verbosity(logger)

    # check configuration for errors
    try:
        check_configuration(config)
    except ValueError:
        shutdown_dit(logger)
    except Exception as unexpected_error:
        logger.error(f"Unexpected error while checking configuration: {unexpected_error}")
        shutdown_dit(logger)

    # set iptables rule if icmp_block cli arg has been set
    if config.get('icmp_block'):
        try:
            enable_icmp_rule(config, logger)
        except Exception as unexpected_error:
            logger.error(f"Unexpected error while setting iptables rule: {unexpected_error}")
            shutdown_dit(logger)

    # start DIT services
    try:
        # initialize and run proxy layer
        proxy = dit_factory(instance_type=InstanceTypes.PROXY, config=config, name="Proxy")
        proxy.run()
        # create a new client_handler and run it
        client_handler = dit_factory(instance_type=InstanceTypes.CLIENT_HANDLER, config=config, 
                                     name="Client Handler")
        # retrieve process so parent can join (blocking)
        child = client_handler.run()
        child.join()
    except (KeyboardInterrupt, SystemExit):
        logger.debug("Received SIGINT")
        shutdown_dit(logger)
    except Exception as unexpected_error:
        logger.error(f"Unexpected error: {unexpected_error}")
        shutdown_dit(logger)
    finally:
        if config.get('icmp_block'):
            logger.debug("Removing firewall rules.")
            deactivate_icmp_blocking(config)

if __name__ == "__main__":
    main()
