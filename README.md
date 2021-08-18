# DIT - DTLS Interception Tool

DIT is a MitM proxy tool to intercept DTLS traffic. 

It can intercept, manipulate and/or suppress DTLS datagrams between two DTLS endpoints. To achieve this, the machine DIT is running on has to be put in a MitM position with tools like arpspoof. DIT has been built with Python 3.8, utilizes scapy and python-mbedtls to process datagrams and supports a wide variety of cipher suites. It can handle PSK-based and certificate-based (RSA + ECC) authentication schemes and has been built and tested on Debian-based Linux operating systems like Ubuntu or Kali Linux.

DIT has been built to analyze traffic between IoT devices but can intercept any DTLS traffic in a local network. It has been tested and evaluated with OpenSSL and devices from the IKEA TRÅDFRI and Philips Hue series. DIT can print the decrypted datagram payload to stdout or write it into a logfile. The tool can be configured via CLI arguments or via a configuration file (./config/dit_config.yaml).

## 1. Installation

DIT works with raw sockets and needs to run with root privileges. You can install DIT by simply cloning the repository and installing the dependencies listed in ```requirements.txt``` with elevated privileges.

```
git clone https://github.com/CountablyInfinite/dit
pip3 install -r requirements.txt
```

## 2. Getting started

### 2.1 Verifying the installation

After cloning and installing the dependencies you can run the following command with elevated privileges to see if DIT has been installed successfully:

```
./dit.py -h
**************************
*   ___    ___   _____   *
*  |   \  |_ _| |_   _|  *
*  | |) |  | |    | |    *
*  |___/  |___|   |_|    *
*                        *
* DTLS INTERCEPTION TOOL *
*                        *
**************************

usage: ./dit.py [optional arguments] start

check configuration stored in ./config/dit_config.yaml before running DIT. 
edit the file or use optional command line arguments to override the default configuration. 
DIT needs root privileges and custom iptable rules to work properly.

run DIT:
  start                 run DIT with the current settings (args override config file settings)

target configuration:
  -isi , --iot_srv_ip   iot server ip address (listening service) to be intercepted (config file: 192.168.183.129)
  -isp , --iot_srv_po   iot server port to be intercepted. (config file: 1337)
  -ici , --iot_cli_ip   iot client ip address to be intercepted. (config file: 192.168.183.128)

interface configuration:
  -eif , --ex_if_name   external interface name (e.g. "eth0") to listen for incoming connections. (config file: ens33)
  -lif , --lh_if_name   local interface name (e.g. "lo") to communicate with local services. (config file: lo)

psk configuration:
  -cid , --cli_id       client identity to configure server and client handler with. (config file: Client_identity)
  -psk , --pre_sh_key   pre-shared key to configure server and client handler with. (config file: DIT_secret)
  --ciphers  [ ...]     list of ciphers to use, separated by spaces. (config file: None)

certificate configuration:
  -cer, --use_cert      [FLAG] use certificates as a method of authentication (instead of a psk). (config file: False)
  -ks , --key_size      length of the RSA/ECC key in bits. (config file: 2048)
  -ecc, --use_ecc       [FLAG] use 521 bit ECC instead of RSA to generate a key pair. disables --key_size. (config file: False)

local services configuration:
  -lci , --lh_cli_ip    local ip address to start a client handler (DTLS server) on. (config file: 127.0.0.1)
  -lcp , --lh_cli_po    local port to start a client handler (DTLS server listener) on. (config file: 1338)
  -lsi , --lh_srv_ip    local ip address to connect a server handler (DTLS client) to. (config file: 127.0.0.1)
  -lsp , --lh_srv_po    local port to connect a server handler (DTLS client) to. (config file: 1339)

miscellaneous:
  -ibl, --icmp_block    [FLAG] automatically create an iptables rule to suppress icmp 'destination unreachable' messages
  -o , --output_file    append intercepted unencrypted messages to an output file
  -v, --verbose         [FLAG] increase verbosity to DEBUG level
  -h, --help            [FLAG] show this help text and exit

examples:
./dit.py -isi 192.168.0.1 -isp 1337 -ici 192.168.0.2 --ciphers TLS-PSK-WITH-AES-128-CCM-8 TLS-PSK-WITH-CHACHA20-POLY1305-SHA256 -psk DIT_secret start
./dit.py --iot_srv_ip 192.168.0.1 --iot_cli_ip 192.168.0.2 --use_cert --key_size 3072 --ciphers TLS-RSA-WITH-AES-128-GCM-SHA256 --verbose start
./dit.py -isi 192.168.0.1 -ici 192.168.0.2 --use_cert -ecc --output_file logfile.log --verbose start

this tool has been created for the purposes of academic research. 
use responsibly and only when explicitly authorized.
```

### 2.2 Prerequisite

#### 2.2.1 Elevated privileges

DIT uses raw sockets and therefore needs to run with elevated (root) privileges.

#### 2.2.2 iptables rule

DIT builds four proxy layers with scapy that are communicating between the external interface and the DTLS services running on localhost. To suppress upcoming "Destination unreachable" errors - that cause DIT to halt with an error - a custom iptables rule is necessary. You can generate it with the following command:

```iptables -I OUTPUT -d localhost-ip -p icmp --icmp-type destination-unreachable -j DROP```

The iptable rules can be set/unset automatically by using the --icmp_block argument when starting DIT.

```./dit.py --icmp_block start```

#### 2.2.3 MitM position

For DIT to work it has to be run from a MitM position. A MitM position can be achieved in many ways, one of them is by using the tool arpspoof (part of the dsniff tool suite). To gain a MitM position in a local network between the clients 192.168.0.1 and 192.168.0.2 you can use the following command:

```arpspoof -i ens33 -t 192.168.0.1 -r 192.168.0.2```

### 2.3 Configuring DIT

DIT can be configured via CLI arguments or via a configuration file (./config/dit_config.yaml). CLI arguments override settings stored in the configuration file. When calling ```./dit.py -h``` - as depicted in section 2.1 - DIT prints out the current configuration that has been read from the configuration file.

#### 2.3.1 ./config/dit_config.yaml

DIT comes with a default configuration you'll need to adapt before running an attack.

```
cat ./config/dit_config.yaml 
# configure spoofing/sniffing targets
targets:  
  iot_srv_ip: 192.168.183.129
  iot_srv_po: 1337
  iot_cli_ip: 192.168.183.128
  ciphers:
    # if no ciphers are configured, DIT will offer all ciphersuites available with mbedTLS
    #- TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384
    #- TLS-PSK-WITH-AES-128-CCM-8
    #- TLS-RSA-WITH-AES-128-GCM-SHA256

# configure interface names
interfaces:
  ex_if_name: ens33
  lh_if_name: lo

# configure psk options
psk:
  cli_id: Client_identity
  pre_sh_key: DIT_secret

# configure certificate options
certificate:
  # default is RSA. "use_ecc" arg enables ECC and disables key_size
  use_cert: False
  key_size: 2048
  use_ecc: False

# configure local dtls services
local_services:
  lh_cli_ip: 127.0.0.1
  lh_cli_po: 1338
  lh_srv_ip: 127.0.0.1
  lh_srv_po: 1339
```

**targets**:
- **iot_srv_ip**: IP address of the dtls server
- **iot_srv_po**: Port the dtls server is listening on
- **iot_cli_ip**: IP address of the dtls client
- **ciphers**: List of cipher suites (using the OpenSSL format) DIT will offer/support when establishing the connections. When no suites are configured DIT offers/supports all cipher suites available with mbedTLS.
 
**interfaces**:
- **ex_if_name**: Name of the external interface DIT will operate on. 
- **lh_if_name**: Name of the internal interface DIT will operate on. Local DTLS server and client services will operate on this interface.

**psk**:
- **cli_id**: Client identy to be used when accepting / establishing DTLS connections. (Default key is 'Client_identity')
- **pr_sh_key**: PSK to be used when accepting / establishing DTLS connections. (ASCII encoded)

**certificate**:
- **use_cert**: Boolean value. Activates the usage of RSA certificates. DIT automatically creates and uses a corresponding certificate with "key_size" Bits in length.
- **key_size**: Length of the RSA key in bits.
- **use_ecc**: Boolean value. Activates the usege of ECC certificates. Only works when "use_cert" is set. Deactivates "key_size".

**local services**:
- **lh_cli_ip**: IP address of the localhost interface the dtls client is running on. (typically 127.0.0.1)
- **lh_cli_po**: Port the local client instance is accepting traffic on. (needn't be changed in a typical setup)
- **lh_srv_ip**: IP address of the localhost interface the dtls server is running on. (typically 127.0.0.1)
- **lh_srv_po**: Port the local server instance is accepting traffic on. (needn't be changed in a typical setup)

#### 2.3.2 Command Line Arguments

DIT can be configured via Command Line Arguments. The arguments are listed and described when calling ```./dit.py -h``` - as shown in section 2.1. Command Line Arguments override settings stored in the configuration file and are a fast way to adapt/test settings without changing the config file.

## 3. Use cases / Evaluation

Refer to https://github.com/CountablyInfinite/dit/tree/master/doc
