def bytes_to_mac(raw_data: bytes) -> str:
    mac_address = ':'.join(['{:02x}'.format(byte) for byte in raw_data])

    return mac_address

def extract_ip_address(raw_data: bytes) -> str:
    return '.'.join(map(str, raw_data))