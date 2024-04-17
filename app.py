from sniffer.sniffer import Sniffer
from sniffer.sniffer_types import Ethernet, Ip, Tcp

def callback(eth: Ethernet, ip: Ip, tcp: Tcp, tcp_data: bytes):
    print(eth.source)
    print(eth.destination)
    print(ip.ips[0])
    print(ip.ips[1])
    print(tcp.src_port)
    print(tcp.dest_port)
    print(tcp_data)

sniffer = Sniffer(80, callback)
sniffer.start()