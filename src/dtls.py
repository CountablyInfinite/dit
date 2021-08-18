"""Module providing classes to initiate dtls client and dtls server instances."""
import socket
import os
import sys
from datetime import datetime, timedelta
from multiprocessing import Process, Queue
from contextlib import suppress
from mbedtls import tls, hashlib, pk, x509, exceptions
import src.factory
from src.dtls_endpoint import DtlsEndpoint


class DtlsClientHandler(DtlsEndpoint):
    """Class providing all necessary functionality for a dtls client handler (dtls server)"""

    def __init__(self, config, name):
        super().__init__(config, name, self.__class__.__name__)

    def _set_context(self):
        """Set the context for the DTLS connection."""
        if self._config.get('use_cert'):
            dtls_com_crt, dtls_com_key = self._create_chain_of_trust(self._config)
            return self._set_context_crt(self._config, dtls_com_crt, dtls_com_key,
                   self._config.get('trust_store'))
        else:
            return self._set_context_psk(self._config)

    def _create_chain_of_trust(self, config):
        """Create a certificate and a truststore for cert. dtls communication"""
        # current setup does not include a full chain of trust (single self signed certificate)
        dtls_com_crt, dtls_com_key = self._create_crt(config)
        self._config['trust_store'] = self._create_trust_store(dtls_com_crt)
        return dtls_com_crt, dtls_com_key

    def _create_crt(self, config):
        """Creates a RSA/ECC key and a corresponding x509 certificate."""
        self._logger.debug("Creating a new communication certificate")
        now = datetime.utcnow()
        # check for ECC flag, otherwise use RSA with predefined keysize
        if config.get('use_ecc', False):
            self._logger.debug("ECC args flag detected. Using 521 Bit ECC instead of RSA to"
                               " generate key pair")
            dtls_com_key = pk.ECC()
            dtls_com_key.generate()
        else:
            self._logger.debug("Using RSA to generate a key pair "
                               f"({config.get('key_size', 2048)}bit)")
            dtls_com_key = pk.RSA()
            dtls_com_key.generate(key_size=config.get('key_size', 2048))
        dtls_com_csr = x509.CSR.new(dtls_com_key, "CN=DIT DTLS-Cert", hashlib.sha256())
        # offset/extend certificate validity time to a allow validation when clocks are not in sync
        dtls_com_crt = x509.CRT.selfsign(csr=dtls_com_csr,
                                         issuer_key=dtls_com_key,
                                         not_before=now-timedelta(days=360),
                                         not_after=now+timedelta(days=360),
                                         serial_number=0x1,)
        return dtls_com_crt, dtls_com_key

    def _create_trust_store(self, crt):
        """Creates a trust store to use with a crt context."""
        self._logger.debug("Creating a new trust store")
        trust_store = tls.TrustStore()
        trust_store.add(crt)
        return trust_store

    def _set_context_crt(self, config, crt, private_key, trust_store):
        """Set a certificate context for the DTLS connection."""
        self._logger.debug("Setting up certificate dtls context supporting the following ciphers: "
                           f"{config.get('ciphers') or 'ALL AVAILABLE'}")
        return tls.ServerContext(tls.DTLSConfiguration(ciphers=config.get('ciphers'),
                                                       trust_store=trust_store,
                                                       certificate_chain=([crt], private_key),
                                                       validate_certificates=False,))

    def _set_context_psk(self, config):
        """Set a psk context for the DTLS connection."""
        self._logger.debug(f"Setting up dtls context: client identity: {config.get('cli_id')}, "
                           f"client psk: {config.get('pre_sh_key')}, "
                           "supporting the following ciphers: "
                           f"{config.get('ciphers') or 'ALL AVAILABLE'}")
        return tls.ServerContext(tls.DTLSConfiguration(ciphers=config.get('ciphers'),
                                                       pre_shared_key_store={config.get('cli_id'):
                                                                    bytes(config.get('pre_sh_key'),
                                                                    encoding='ascii'), },))
    def run(self):
        """Starts the client handler (DTLS server) by spawning a new process."""
        srv_hand = src.factory.dit_factory(instance_type=src.factory.InstanceTypes.SERVER_HANDLER,
                                           config=self._config,
                                           name="Server Handler")
        cli_hand_q, srv_hand_q = self._setup_proc_queues()
        cli_hand = Process(target=self._run_client_handler,
                                 args=(self._context,
                                       self._config.get('lh_cli_ip'),
                                       self._config.get('lh_cli_po'),
                                       cli_hand_q,
                                       srv_hand,
                                       srv_hand_q))
        cli_hand.start()
        return cli_hand

    @staticmethod
    def _setup_proc_queues():
        """Sets up two process queues to be used in server/client communication."""
        return Queue(), Queue()

    def _run_client_handler(self, context, ip, port, cli_hand_q, srv_hand, srv_hand_q):
        """Opens a (listening) client handler (dtls server) that starts a server handler (dtls
        client) with the given parameters as soon as an incoming connection has been established."""
        self._logger.debug(f"Created new {self.__class__.__name__} socket: process id: "
                           f"{os.getpid()}, parent id: {os.getppid()}")
        self._logger.info("DTLS client handler is listening for incoming connections from "
                          f"{self._config.get('iot_cli_ip')} to {self._config.get('iot_srv_ip')} on"
                          f" port {self._config.get('iot_srv_po')}")
        try:
            _, conn, _ = self._establish_connection(context, ip, port)
            self._logger.debug("Starting a new Server Handler instance")
            self._start_server_handler(cli_hand_q, srv_hand, srv_hand_q)
            while True:
                # check for messages from server handler
                while cli_hand_q.empty():
                    try:
                        conn.setblocking(0)
                        received_datagram = conn.recv(65536)
                    except BlockingIOError:
                        pass
                    try:
                        if received_datagram:
                            self._logger.info(f"Received new datagram: {received_datagram}")
                            if self._config.get("output_file"):
                                self._write_to_logfile(f"{datetime.now()} || From Client to Server "
                                                       f"|| {received_datagram}\n")
                            received_datagram = self._manipulate_payload(received_datagram)
                            srv_hand_q.put(received_datagram)
                            received_datagram = None
                    except UnboundLocalError:
                        pass
                outgoing_datagram = cli_hand_q.get()
                self._logger.debug(f"Sending datagram: {outgoing_datagram}")
                conn.send(outgoing_datagram)
        except (KeyboardInterrupt, SystemExit):
            self._logger.debug("Gracefully ending Client Handler and child daemons.")
            sys.exit(0)
        except exceptions.TLSError as tls_exception:
            if "[0x7180]" in str(tls_exception):
                self._logger.error("DTLS handshake error: Unable to verify MAC. "
                                   "(PSK not matching?)")
            else:
                self._logger.error(f"Unknow DTLS error: {str(tls_exception)}")
            self._logger.info("Shutting down DIT")
            sys.exit(1)

    def _establish_connection(self, context, ip, port):
        """Creates a listening socket and performs a DTLS Handshake once a connection has been
        established."""
        sock = self._wrap_socket(context)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((ip, port))
        conn, addr = sock.accept()
        conn.setcookieparam(addr[0].encode())
        with suppress(tls.HelloVerifyRequest):
            self._block(conn.do_handshake)
        conn, addr = conn.accept()
        conn.setcookieparam(addr[0].encode())
        self._block(conn.do_handshake)
        self._logger.info("Handshake completed")
        return sock, conn, addr

    def _wrap_socket(self, context):
        """Wraps a default UDP socket with a given DTLS context."""
        return context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))

    def _start_server_handler(self, cli_hand_q, srv_hand, srv_hand_q):
        """Starts a new server_handler (dtls client) process with the given parameters."""
        srv_hand.run(client_handler_queue=cli_hand_q, server_handler_queue=srv_hand_q)

    def _manipulate_payload(self, payload):
        """Hook to manipulate a given payload/message"""
        if payload == b'Default Message\n':
            manipulated_payload = b'Manipulated Message\n'
            self._logger.info(f"Changed payload: {payload} to: {manipulated_payload}")
            return manipulated_payload
        else:
            return payload


class DtlsServerHandler(DtlsEndpoint):
    """Class providing all necessary functionality for a dtls server handler (dtls client)"""

    def __init__(self, config, name):
        super().__init__(config, name, self.__class__.__name__)
        self._target_ip = config.get('lh_srv_ip')
        self._target_port = config.get('lh_srv_po')

    def _set_context(self):
        """Set context for the DTLS connection."""
        if self._config.get('use_cert'):
            return self._set_context_crt(self._config, self._config.get('trust_store'))
        else:
            return self._set_context_psk(self._config)

    def _set_context_crt(self, config, trust_store):
        """Set a certificate context for the DTLS connection."""
        self._logger.debug("Setting up certificate dtls context supporting the following ciphers: "
                           f"{config.get('ciphers') or 'ALL AVAILABLE'}")
        return tls.ClientContext(tls.DTLSConfiguration(ciphers=config.get('ciphers'),
                                                       trust_store=trust_store,
                                                       validate_certificates=False))

    def _set_context_psk(self, config):
        """Set a psk context for the DTLS connection."""
        self._logger.debug(f"Setting up dtls context: client identity: {config.get('cli_id')}, "
                           f"client psk: {config.get('pre_sh_key')}, "
                           "supporting the following ciphers: "
                           f"{config.get('ciphers') or 'ALL AVAILABLE'}")
        return tls.ClientContext(tls.DTLSConfiguration(ciphers=config.get('ciphers'),
                                                       pre_shared_key=(
                                                            config.get('cli_id'),
                                                            bytes(config.get('pre_sh_key'),
                                                            encoding='ascii'))))

    def run(self, client_handler_queue, server_handler_queue):
        """Starts the server handler (dtls client) by spawning a new process."""
        server_handler = Process(target=self._run_server_handler,
                                 args=(self._context,
                                       self._target_ip,
                                       self._target_port,
                                       client_handler_queue,
                                       server_handler_queue))
        server_handler.daemon = True
        server_handler.start()

    def _run_server_handler(self, context, ip, port, client_handler_queue, server_handler_queue):
        """Connects a server handler (dtls client) to the given address:port"""
        self._logger.debug(f"Created new {self.__class__.__name__} socket: process id: "
                           f"{os.getpid()}, parent id: {os.getppid()}")
        self._logger.info(f"DTLS server handler is connecting to {self._config.get('iot_srv_ip')} "
                          f"on port {self._config.get('iot_srv_po')}")
        try:
            sock = self._establish_connection(context, ip, port)
            while True:
                # check for messages from client_handler
                while server_handler_queue.empty():
                    try:
                        received_datagram = self._block(sock.recv, 65536)
                    except socket.timeout:
                        pass
                    try:
                        if received_datagram:
                            self._logger.info(f"Received new datagram: {received_datagram}")
                            if self._config.get("output_file"):
                                self._write_to_logfile(f"{datetime.now()} || From Server to Client "
                                                       f"|| {received_datagram}\n")
                            received_datagram = self._manipulate_payload(received_datagram)
                            client_handler_queue.put(received_datagram)
                            received_datagram = None
                    except UnboundLocalError:
                        pass
                outgoing_datagram = server_handler_queue.get()
                self._logger.debug(f"Sending datagram: {outgoing_datagram}")
                self._block(sock.send, outgoing_datagram)
        except exceptions.TLSError as tls_exception:
            if "[0x7180]" in str(tls_exception):
                self._logger.error("DTLS handshake error: Unable to verify MAC. "
                                   "(PSK not matching?)")
            else:
                self._logger.error(f"Unknow DTLS error: {str(tls_exception)})")
            self._logger.info("Shutting down DIT")
            sys.exit(1)

    def _establish_connection(self, context, ip, port):
        """Creates a socket connecting to the given ip adress, performing a DTLS handshake"""
        sock = self._wrap_socket(context)
        sock.settimeout(0.01)
        sock.connect((ip, port))
        self._block(sock.do_handshake)
        self._logger.info("Handshake completed")
        return sock

    def _wrap_socket(self, context):
        """Wraps a default UDP socket with a given DTLS context."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #sock.setsockopt(socket.AF_INET, 1, 1)
        sock = context.wrap_socket(sock, server_hostname=None,)
        return sock

    def _manipulate_payload(self, payload):
        """Hook to manipulate a given payload/message"""
        if payload == b'Default Message\n':
            manipulated_payload = b'Manipulated Message\n'
            self._logger.info(f"Changed payload: {payload} to: {manipulated_payload}")
            return manipulated_payload
        else:
            return payload
