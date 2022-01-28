"""Module providing a proxy layer to forward IP pakets for non local addresses to a locally running
DTLS service and vice versa."""
import logging
import socket
import os
from multiprocessing import Process
from scapy.all import Ether, sniff, IP, UDP, Raw, send, IPSession


class Proxy():
    """Class to intercept UDP traffic from/to a given IP address / port and to forward it to a local
     DTLS handler and vice versa."""

    def __init__(self, config, name):
        self.name = name
        self._config = config
        self._suppress_localhost_duplication = False
        self._logger = logging.getLogger(self.name)
        if config.get('verbose'):
            self._logger.setLevel(logging.DEBUG)
        self._logger.debug(f"Creating a new {self.__class__.__name__} instance")

    def _sniff_in_from_client(self, src_ip, dst_ip, dst_port, interf, interf_mac, new_src_port,
                              new_dst_ip, new_dst_port, func):
        """Method to start a scapy sniffer for incoming pakets from the iot client."""
        self._logger.debug("Created a new sniffer to sniff incoming client packets. Process id: "
                           f"{os.getpid()}, Parent id: {os.getppid()}")
        while True:
            sniff(filter=f"ip proto 17 and not ether src {interf_mac} and ip dst host {dst_ip} and"
                         f" ip src host {src_ip} and ((dst port {dst_port}) or (((ip[6:2] > 0) or "
                         "(ip[7] > 0)) and (not ip[6] = 64)))",
                  iface=interf,
                  session=IPSession,
                  prn=func(new_dst_ip, new_dst_port, new_src_port))

    def _sniff_out_to_client(self, src_ip, src_port, interf, new_src_ip, new_src_port, new_dst_ip,
                             new_dst_port, func):
        """Method to start a scapy sniffer for outgoing pakets to the iot client."""
        self._logger.debug("Created a new sniffer to sniff outgoing client packets. Process id: "
                           f"{os.getpid()}, Parent id: {os.getppid()}")
        while True:
            sniff(filter=f"ip proto 17 and ip src host {src_ip} and src port {src_port}",
                  iface=interf,
                  prn=func(new_src_ip, new_src_port, new_dst_ip, new_dst_port))

    def _sniff_in_from_server(self, src_ip, src_port, dst_ip, interf, interf_mac, new_src_port,
                              new_dst_ip, new_dst_port, func):
        """Method to start a scapy sniffer for incoming pakets from the iot server."""
        self._logger.debug("Created a new sniffer to sniff incoming server packets. Process id: "
                           f"{os.getpid()}, Parent id: {os.getppid()}")
        while True:
            sniff(filter=f"ip proto 17 and not ether src {interf_mac} and ip dst host {dst_ip} and"
                         f" ip src host {src_ip} and ((src port {src_port}) or (((ip[6:2] > 0) or "
                         "(ip[7] > 0)) and (not ip[6] = 64)))",
                  iface=interf,
                  session=IPSession,
                  prn=func(new_dst_ip, new_dst_port, new_src_port))

    def _sniff_out_to_server(self, src_ip, dst_port, interf, new_src_ip, new_src_port, new_dst_ip,
                             new_dst_port, func):
        """Method to start a scapy sniffer for outgoing pakets to the iot server."""
        self._logger.debug("Created a new sniffer to sniff outgoing server packets. Process id: "
                           f"{os.getpid()}, Parent id: {os.getppid()}")
        while True:
            sniff(filter=f"ip proto 17 and ip src host {src_ip} and dst port {dst_port}",
                  iface=interf,
                  prn=func(new_src_ip, new_src_port, new_dst_ip, new_dst_port))

    def _wrapper_change_incoming_packet(self, new_dst_ip, new_dst_port, new_src_port):
        """Method to change incoming pakets and forward them to local dtls services
        Nested function to give it access to additional parameters (scapy only provides packet)"""
        def change_incoming_packet(ori_packet):
            # set varibles that need assigment to local function scope
            local_new_src_port = new_src_port
            local_new_dst_port = new_dst_port
            # incoming packets from iot client
            if local_new_dst_port and (local_new_src_port is None):
                local_new_src_port = ori_packet[UDP].sport
            # incoming packets from iot server
            elif local_new_src_port and (local_new_dst_port is None):
                local_new_dst_port = ori_packet[UDP].dport
            # transfer all necessary header fiedls from die original packet to the new packet
            new_packet = (IP(tos=ori_packet[IP].tos,
                             len=ori_packet[IP].len,
                             id=ori_packet[IP].id,
                             flags=ori_packet[IP].flags,
                             frag=ori_packet[IP].frag,
                             proto=17)/
                          UDP(sport=local_new_src_port,
                              dport=local_new_dst_port,
                              len=ori_packet[UDP].len)/
                          ori_packet[UDP].payload)
            # localhost MTU is 65536, so there is no Fragmentation needed
            # set socket options so we can send to the localhost interface
            rawudp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            rawudp.bind((new_dst_ip, local_new_dst_port))
            rawudp.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
            rawudp.sendto(new_packet.build(), (new_dst_ip, local_new_dst_port))
        return change_incoming_packet

    def _wrapper_change_outgoing_packet(self, new_src_ip, new_src_port, new_dst_ip, new_dst_port):
        """Method to change outgoing pakets and forward them the iot devices.
        Nested function to give it access to additional parameters (scapy only provides 'packet')"""
        def change_outgoing_packet(ori_packet):
            # BE AWARE! this a very hacky workaround for scapy's loopback/duplication issues.
            if self._suppress_localhost_duplication:
                # transfer all necessary header fields from the original packet to the new packet
                new_packet = (IP(dst=new_dst_ip,
                                 src=new_src_ip,
                                 tos=ori_packet[IP].tos,
                                 id=ori_packet[IP].id,
                                 frag=ori_packet[IP].frag,
                                 proto=17)/
                              UDP(len=ori_packet[UDP].len)/
                              ori_packet[UDP].payload)
                # outgoing packets to iot client
                if new_src_port:
                    new_packet[UDP].sport = new_src_port
                    new_packet[UDP].dport = ori_packet[UDP].dport
                # outgoing packets to iot server
                if new_dst_port:
                    new_packet[UDP].dport = new_dst_port
                    new_packet[UDP].sport = ori_packet[UDP].sport
                # build packet
                new_packet = new_packet.__class__(bytes(new_packet))
                if new_packet[IP].len > (self._config.get("ex_if_mtu") - 20):
                    fragments = IP.fragment(new_packet)
                    for fragment in fragments:
                        send(fragment, verbose=False)
                else:
                    send(new_packet, verbose=False)
                self._suppress_localhost_duplication = False
            else:
                self._suppress_localhost_duplication = True
        return change_outgoing_packet

    def run(self):
        """Method to start all neccessary sniffers as deamonized processes."""
        # the following section may seem uneccessary repetative but vastly improves readability
        # child processes are daemonized so they die with the parent process
        # create sniffer process for incoming packets from the iot client
        sniff_in_client = Process(target=self._sniff_in_from_client,
                                  args=(self._config.get("iot_cli_ip"),
                                        self._config.get("iot_srv_ip"),
                                        self._config.get("iot_srv_po"),
                                        self._config.get("ex_if_name"),
                                        self._config.get("ex_if_mac"),
                                        None,
                                        self._config.get("lh_cli_ip"),
                                        self._config.get("lh_cli_po"),
                                        self._wrapper_change_incoming_packet))
        sniff_in_client.daemon = True
        sniff_in_client.start()

        # create sniffer process for outgoing packets to the iot client
        sniff_out_client = Process(target=self._sniff_out_to_client,
                                   args=(self._config.get("lh_cli_ip"),
                                         self._config.get("lh_cli_po"),
                                         self._config.get("lh_if_name"),
                                         self._config.get("iot_srv_ip"),
                                         self._config.get("iot_srv_po"),
                                         self._config.get("iot_cli_ip"),
                                         None,
                                         self._wrapper_change_outgoing_packet))
        sniff_out_client.daemon = True
        sniff_out_client.start()

        # create sniffer process for incoming packets from the iot server
        sniff_in_server = Process(target=self._sniff_in_from_server,
                                  args=(self._config.get("iot_srv_ip"),
                                        self._config.get("iot_srv_po"),
                                        self._config.get("iot_cli_ip"),
                                        self._config.get("ex_if_name"),
                                        self._config.get("ex_if_mac"),
                                        self._config.get("lh_srv_po"),
                                        self._config.get("lh_srv_ip"),
                                        None,
                                        self._wrapper_change_incoming_packet))
        sniff_in_server.daemon = True
        sniff_in_server.start()

        # create sniffer process for outgoing packets to the iot server
        sniff_out_server = Process(target=self._sniff_out_to_server,
                                   args=(self._config.get("lh_cli_ip"),
                                   self._config.get("lh_srv_po"),
                                   self._config.get("lh_if_name"),
                                   self._config.get("iot_cli_ip"),
                                   None,
                                   self._config.get("iot_srv_ip"),
                                   self._config.get("iot_srv_po"),
                                   self._wrapper_change_outgoing_packet))
        sniff_out_server.daemon = True
        sniff_out_server.start()
