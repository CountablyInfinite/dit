"""Module providing utility functions to like printing the signature or activating firewall
rules."""
from subprocess import call, check_output, DEVNULL
from re import search
import os


def print_signature():
    """Prints the DIT signature to std out."""
    print("*"*26)
    print("*   ___    ___   _____   *\n"
          "*  |   \  |_ _| |_   _|  *\n"
          "*  | |) |  | |    | |    *\n"
          "*  |___/  |___|   |_|    *")
    print("*                        *")
    print("* DTLS INTERCEPTION TOOL *")
    print("*                        *")
    print("*"*26 + "\n")

def activate_icmp_blocking(config):
    """Activates an iptables rule to suppress icmp destination unreachable messages to localhost."""
    call(["iptables",
          "-I", "OUTPUT",
          "-d", f"{config.get('lh_cli_ip')}",
          "-p", "icmp",
          "--icmp-type", "destination-unreachable",
          "-j", "DROP"],
         stdout=DEVNULL,
         stderr=DEVNULL)

def deactivate_icmp_blocking(config):
    """Deactivates an iptables rule to suppress icmp destination unreachable messages
    to localhost."""
    call(["iptables",
          "-D", "OUTPUT",
          "-d", f"{config.get('lh_cli_ip')}",
          "-p", "icmp",
          "--icmp-type", "destination-unreachable",
          "-j", "DROP"],
         stdout=DEVNULL,
         stderr=DEVNULL)

def check_for_root():
    """Checks if the current user is running with 0 as effective UID."""
    if os.geteuid() == 0:
        return True
    else:
        return False

def get_mac_address(interface_name):
    """Parses the mac address for a given interface name."""
    mac = open(f"/sys/class/net/{interface_name}/address").readline()
    return mac[0:17]

def get_mtu(interface_name):
    """Parses the MTU for a given interface name."""
    output_ip_link = str(check_output(['ip', 'link', 'show', interface_name]))
    mtu = int(search('.*mtu ([0-9]+) .*', output_ip_link).groups()[0])
    return mtu
