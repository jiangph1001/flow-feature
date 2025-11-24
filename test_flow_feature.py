import unittest
import sys
import os
from unittest.mock import Mock, MagicMock, patch
import hashlib

# Add the current directory to the path so we can import the modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flow import *

class TestNormalization(unittest.TestCase):
    """Test the NormalizationSrcDst function - ensures deterministic ordering"""

    def test_sport_less_than_dport(self):
        # When sport < dport, swap to put larger port first
        # 1234 < 80 is False, so no swap
        result = NormalizationSrcDst("192.168.1.1", 1234, "10.0.0.1", 80)
        self.assertEqual(result, ("192.168.1.1", 1234, "10.0.0.1", 80))

    def test_sport_greater_than_dport(self):
        # When sport > dport, swap to put larger port first
        # 80 > 1234 is False, but 80 < 1234 is True, so swap
        result = NormalizationSrcDst("192.168.1.1", 80, "10.0.0.1", 1234)
        self.assertEqual(result, ("10.0.0.1", 1234, "192.168.1.1", 80))

    def test_sport_equal_dport_src_ip_less(self):
        # When sport == dport, compare IPs (remove dots and compare as numbers)
        # src_ip = "19216811", dst_ip = "10001"
        # 19216811 < 10001 is False, so no swap
        result = NormalizationSrcDst("192.168.1.1", 8080, "10.0.0.1", 8080)
        self.assertEqual(result, ("192.168.1.1", 8080, "10.0.0.1", 8080))

    def test_sport_equal_dport_dst_ip_less(self):
        # When sport == dport, compare IPs (remove dots and compare as numbers)
        # src_ip = "10001", dst_ip = "19216811"
        # 10001 < 19216811 is True, so swap
        result = NormalizationSrcDst("10.0.0.1", 8080, "192.168.1.1", 8080)
        self.assertEqual(result, ("192.168.1.1", 8080, "10.0.0.1", 8080))


class TestTuple2Hash(unittest.TestCase):
    """Test the tuple2hash function"""

    def test_hash_generation(self):
        # Test that hash is generated correctly
        src = "192.168.1.1"
        sport = 1234
        dst = "10.0.0.1"
        dport = 80
        protocol = "TCP"

        hash_result = tuple2hash(src, sport, dst, dport, protocol)

        # Should be a non-empty string
        self.assertIsInstance(hash_result, str)
        self.assertGreater(len(hash_result), 0)

        # Should be SHA256 (64 hex characters)
        self.assertEqual(len(hash_result), 64)

        # Same input should produce same hash
        hash_result2 = tuple2hash(src, sport, dst, dport, protocol)
        self.assertEqual(hash_result, hash_result2)

        # Different input should produce different hash
        hash_result3 = tuple2hash("192.168.1.2", sport, dst, dport, protocol)
        self.assertNotEqual(hash_result, hash_result3)

    def test_default_protocol(self):
        # Test default protocol parameter
        src = "192.168.1.1"
        sport = 1234
        dst = "10.0.0.1"
        dport = 80

        hash_with_protocol = tuple2hash(src, sport, dst, dport, "TCP")
        hash_default = tuple2hash(src, sport, dst, dport)

        self.assertEqual(hash_with_protocol, hash_default)


class TestStatisticsCalculation(unittest.TestCase):
    """Test the calculation function"""

    def test_empty_list(self):
        result = calculation([])
        self.assertEqual(result, [0, 0, 0, 0])

    def test_single_value(self):
        result = calculation([5.0])
        self.assertEqual(result[0], 5.0)  # mean
        self.assertEqual(result[1], 5.0)  # min
        self.assertEqual(result[2], 5.0)  # max
        self.assertEqual(result[3], 0.0)  # std

    def test_normal_list(self):
        data = [1.0, 2.0, 3.0, 4.0, 5.0]
        result = calculation(data)
        self.assertEqual(result[0], 3.0)  # mean
        self.assertEqual(result[1], 1.0)  # min
        self.assertEqual(result[2], 5.0)  # max
        # std is population std (divide by n) = sqrt((4+1+0+1+4)/5) = sqrt(2) = 1.414214
        self.assertAlmostEqual(result[3], 1.414214, places=5)

    def test_negative_values(self):
        data = [-1.0, -2.0, -3.0, -4.0, -5.0]
        result = calculation(data)
        self.assertEqual(result[0], -3.0)  # mean
        self.assertEqual(result[1], -5.0)  # min
        self.assertEqual(result[2], -1.0)  # max


class TestFlowDivide(unittest.TestCase):
    """Test the flow_divide function"""

    def test_flow_divide(self):
        # Create mock packets
        pkt1 = Mock()
        pkt1.__getitem__ = Mock(return_value=Mock(src="192.168.1.1"))

        pkt2 = Mock()
        pkt2.__getitem__ = Mock(return_value=Mock(src="10.0.0.1"))

        pkt3 = Mock()
        pkt3.__getitem__ = Mock(return_value=Mock(src="192.168.1.1"))

        flow = [pkt1, pkt2, pkt3]
        src = "192.168.1.1"

        fwd_flow, bwd_flow = flow_divide(flow, src)

        # Should have 2 forward packets and 1 backward packet
        self.assertEqual(len(fwd_flow), 2)
        self.assertEqual(len(bwd_flow), 1)

    def test_empty_flow(self):
        fwd_flow, bwd_flow = flow_divide([], "192.168.1.1")
        self.assertEqual(len(fwd_flow), 0)
        self.assertEqual(len(bwd_flow), 0)


class TestPacketIAT(unittest.TestCase):
    """Test the packet_iat function"""

    def test_normal_iat(self):
        # Create mock packets with timestamps
        pkt1 = Mock()
        pkt1.time = 1.0

        pkt2 = Mock()
        pkt2.time = 2.0

        pkt3 = Mock()
        pkt3.time = 4.0

        flow = [pkt1, pkt2, pkt3]
        mean, min_, max_, std = packet_iat(flow)

        self.assertAlmostEqual(mean, 1.5, places=5)  # (1.0 + 2.0) / 2
        self.assertEqual(min_, 1.0)
        self.assertEqual(max_, 2.0)

    def test_single_packet(self):
        pkt1 = Mock()
        pkt1.time = 1.0

        flow = [pkt1]
        mean, min_, max_, std = packet_iat(flow)

        # Should return all zeros for single packet
        self.assertEqual(mean, 0)
        self.assertEqual(min_, 0)
        self.assertEqual(max_, 0)
        self.assertEqual(std, 0)

    def test_empty_flow(self):
        mean, min_, max_, std = packet_iat([])
        self.assertEqual(mean, 0)
        self.assertEqual(min_, 0)
        self.assertEqual(max_, 0)
        self.assertEqual(std, 0)


class TestPacketLen(unittest.TestCase):
    """Test the packet_len function"""

    def test_normal_lengths(self):
        # Create mock packets
        pkt1 = Mock()
        pkt1.__len__ = Mock(return_value=100)

        pkt2 = Mock()
        pkt2.__len__ = Mock(return_value=150)

        pkt3 = Mock()
        pkt3.__len__ = Mock(return_value=200)

        flow = [pkt1, pkt2, pkt3]
        total, mean, min_, max_, std = packet_len(flow)

        self.assertEqual(total, 450.0)
        self.assertEqual(mean, 150.0)
        self.assertEqual(min_, 100.0)
        self.assertEqual(max_, 200.0)

    def test_empty_flow(self):
        total, mean, min_, max_, std = packet_len([])
        self.assertEqual(total, 0)
        self.assertEqual(mean, 0)
        self.assertEqual(min_, 0)
        self.assertEqual(max_, 0)
        self.assertEqual(std, 0)


class TestFlowClass(unittest.TestCase):
    """Test the Flow class"""

    def test_flow_initialization(self):
        flow = Flow("192.168.1.1", 1234, "10.0.0.1", 80, "TCP")

        self.assertEqual(flow.src, "192.168.1.1")
        self.assertEqual(flow.sport, 1234)
        self.assertEqual(flow.dst, "10.0.0.1")
        self.assertEqual(flow.dport, 80)
        self.assertEqual(flow.protol, "TCP")
        self.assertEqual(flow.start_time, 1e11)
        self.assertEqual(flow.end_time, 0)
        self.assertEqual(flow.byte_num, 0)
        self.assertEqual(len(flow.packets), 0)

    def test_add_packet(self):
        flow = Flow("192.168.1.1", 1234, "10.0.0.1", 80, "TCP")

        # Create mock packet
        pkt = Mock()
        pkt.time = 100.0
        pkt.__len__ = Mock(return_value=64)

        flow.add_packet(pkt)

        self.assertEqual(len(flow.packets), 1)

    def test_flow_feature_invalid(self):
        """Test that flows with < 2 packets return None"""
        flow = Flow("192.168.1.1", 1234, "10.0.0.1", 80, "TCP")

        # Add only one packet
        pkt = Mock()
        pkt.time = 100.0
        pkt.__len__ = Mock(return_value=64)

        flow.add_packet(pkt)
        feature = flow.get_flow_feature()

        self.assertIsNone(feature)


class TestSortKey(unittest.TestCase):
    """Test the sortKey function"""

    def test_sort_key(self):
        pkt = Mock()
        pkt.time = 123.456

        result = sortKey(pkt)
        self.assertEqual(result, 123.456)


class TestIsTCPPacket(unittest.TestCase):
    """Test the is_TCP_packet function"""

    def test_valid_tcp_packet(self):
        pkt = Mock()
        pkt.__getitem__ = Mock(side_effect=lambda x: Mock(src="192.168.1.1") if x == "IP" else None)
        pkt.__contains__ = Mock(return_value=True)  # "TCP" in pkt returns True

        result = is_TCP_packet(pkt)
        self.assertTrue(result)

    def test_not_ip_packet(self):
        pkt = Mock()
        pkt.__getitem__ = Mock(side_effect=KeyError)  # No IP layer

        result = is_TCP_packet(pkt)
        self.assertFalse(result)

    def test_not_tcp_packet(self):
        pkt = Mock()
        pkt.__getitem__ = Mock(return_value=Mock(src="192.168.1.1"))
        pkt.__contains__ = Mock(return_value=False)  # No TCP layer

        result = is_TCP_packet(pkt)
        self.assertFalse(result)


class TestTuple2HashConsistency(unittest.TestCase):
    """Test that tuple2hash produces consistent results"""

    def test_consistency_across_calls(self):
        # Test that calling tuple2hash multiple times with same input gives same result
        test_cases = [
            ("192.168.1.1", 80, "10.0.0.1", 12345, "TCP"),
            ("172.16.0.1", 443, "192.168.50.100", 50000, "TCP"),
            ("1.2.3.4", 8080, "5.6.7.8", 9090, "TCP"),
        ]

        for src, sport, dst, dport, proto in test_cases:
            hash1 = tuple2hash(src, sport, dst, dport, proto)
            hash2 = tuple2hash(src, sport, dst, dport, proto)
            # Should be identical
            self.assertEqual(hash1, hash2, f"Hashes should be identical for same input: {src}:{sport} -> {dst}:{dport}")

            # Different order (after normalization) should give different hash
            # Note: this tests that the function is case-sensitive to argument order
            hash3 = tuple2hash(dst, dport, src, sport, proto)
            self.assertNotEqual(hash1, hash3, "Different argument order should produce different hash")


if __name__ == "__main__":
    unittest.main(verbosity=2)
