# Ahmet Olkun - Assignment 7 Unit Tests
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "code"))
from solution import dissect_packet


# Test 1: Standard TCP SYN handshake packet.
pkt1 = dissect_packet("192.168.1.15", "10.0.0.1", "tcp", 64, flags=["SYN"])
assert pkt1.get("src") == "192.168.1.15", "Failed Test 1: Source address check"
assert pkt1.get("proto") == "TCP", "Failed Test 1: Protocol must be uppercase"
assert pkt1.get("syn_flag") is True, "Failed Test 1: SYN flag check"
assert pkt1.get("length") == 64, "Failed Test 1: Length check"

# Test 2: UDP packet with no flags and a negative payload length.
pkt2 = dissect_packet("10.0.0.1", "8.8.8.8", "UDP", -10)
assert pkt2.get("dst") == "8.8.8.8", "Failed Test 2: Check destination address"
assert pkt2.get("length") == 0, "Failed Test 2: Negative payload should normalize to 0"
assert pkt2.get("syn_flag") is False, "Failed Test 2: SYN flag should be False when flags is None"

# Test 3: TCP ACK packet without SYN.
pkt3 = dissect_packet("10.0.0.5", "10.0.0.1", "tcp", 120, flags=["ACK"])
assert pkt3.get("syn_flag") is False, "Failed Test 3: SYN flag should be False for ACK"

print("ALL UNIT TESTS PASSED - ASSIGNMENT 7")
