# Ahmet Olkun - Assignment 7


def dissect_packet(src_ip, dst_ip, protocol, payload_bytes, flags=None):
    return {
        "src": src_ip,
        "dst": dst_ip,
        "proto": protocol.upper(),
        "length": max(payload_bytes, 0),
        "syn_flag": flags is not None and "SYN" in flags,
    }
