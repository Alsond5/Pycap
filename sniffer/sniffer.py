from struct import *
import socket
from utils import utils

from typing import Callable
from sniffer_types import Ethernet, Ip, Tcp

class Sniffer:
    def __init__(self, port: int, callback: Callable[[Ethernet, Ip, Tcp, bytes], None]) -> None:
        self.port = port
        self.callback = callback
        self.socket: socket.socket | None = None

    def extract_ethernet_header(self, raw_data: bytes) -> Ethernet:
        destination, source, prototype = unpack("! 6s 6s H", raw_data)

        ethernet = Ethernet(
            utils.bytes_to_mac(destination),
            utils.bytes_to_mac(source),
            prototype
        )
        
        return ethernet
    
    def extract_ip_header(self, raw_data: bytes) -> tuple[Ip, bytes]:
        version_header_length = raw_data[0]
        version = version_header_length >> 4

        header_length = (version_header_length & 15) * 4

        ttl, proto, src, target = unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        data = raw_data[header_length:]

        ip = Ip(
            version,
            header_length,
            ttl,
            proto,
            [utils.extract_ip_address(src), utils.extract_ip_address(target)]
        )

        return ip, data
    
    def extract_tcp_header(self, raw_data: bytes) -> tuple[Tcp, bytes]:
        (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = unpack('! H H L L H', raw_data[:14])

        offset = (offset_reserved_flags >> 12) * 4

        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        
        data = raw_data[offset:]

        tcp = Tcp(
            src_port,
            dest_port,
            sequence,
            acknowledgment,
            [flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin]
        )

        return tcp, data

    def process_message(self, packet):
        eth_data = packet[:14]
        eth = self.extract_ethernet_header(eth_data)

        data = packet[14:]
        ip, ip_data = self.extract_ip_header(data)

        if ip.proto == 6:
            tcp, tcp_data = self.extract_tcp_header(ip_data)
            
            if tcp.src_port == self.port or tcp.dest_port == self.port:
                self.callback(eth, ip, tcp, tcp_data)

    def start(self):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        running = True
        
        try:
            while running:
                packet, adr = self.socket.recvfrom(65535)

                self.process_message(packet)
        except KeyboardInterrupt:
            self.socket.close()

            print("Sniffer intercepted!")
        finally:
            self.socket.close()

    def __del__(self):
        try:
            self.socket.close()
        except:
            self.socket = None