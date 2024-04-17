from dataclasses import dataclass

@dataclass
class Ethernet:
    destination: str
    source: str
    prototype: int

@dataclass
class Ip:
    version: int
    header_length: int
    ttl: int
    proto: int
    ips: list[str]

@dataclass
class Tcp:
    src_port: int
    dest_port: int
    sequence: int
    acknowledgment: int
    flags: list[int]