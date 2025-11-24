import math
import hashlib
import csv
import time
import os
from typing import List, Tuple, Any, Optional

import scapy
from scapy.all import *
from scapy.utils import PcapReader
# from scapy_ssl_tls.scapy_ssl_tls import *
# from datetime import datetime, timedelta, timezone
# import threading

from multiprocessing import Process

# Constants for network packet header lengths
ETHERNET_HEADER_LEN = 14  # Ethernet header length in bytes
TCP_HEADER_BASE_LEN = 20  # TCP header base length in bytes

# Feature names for TCP flow analysis (84 features total)
# IAT = Inter-Arrival Time (packet arrival intervals)
# win = TCP window size
# pl = Packet Length
# pnum = Packet Number
# cnt = TCP flag counts
# hdr_len = Header Length
# ht_len = Header length to total length ratio
feature_name = [
    # Inter-arrival time features (12)
    'fiat_mean', 'fiat_min', 'fiat_max', 'fiat_std',  # Forward IAT statistics
    'biat_mean', 'biat_min', 'biat_max', 'biat_std',  # Backward IAT statistics
    'diat_mean', 'diat_min', 'diat_max', 'diat_std',  # Combined IAT statistics

    # Flow duration (1)
    'duration',

    # TCP window size features (15)
    'fwin_total', 'fwin_mean', 'fwin_min', 'fwin_max', 'fwin_std',  # Forward
    'bwin_total', 'bwin_mean', 'bwin_min', 'bwin_max', 'bwin_std',  # Backward
    'dwin_total', 'dwin_mean', 'dwin_min', 'dwin_max', 'dwin_std',  # Combined

    # Packet count features (7)
    'fpnum', 'bpnum', 'dpnum',  # Forward/backward/total packet count
    'bfpnum_rate',  # Backward/forward packet ratio
    'fpnum_s', 'bpnum_s', 'dpnum_s',  # Packets per second

    # Packet length features (21)
    'fpl_total', 'fpl_mean', 'fpl_min', 'fpl_max', 'fpl_std',  # Forward
    'bpl_total', 'bpl_mean', 'bpl_min', 'bpl_max', 'bpl_std',  # Backward
    'dpl_total', 'dpl_mean', 'dpl_min', 'dpl_max', 'dpl_std',  # Combined
    'bfpl_rate',  # Backward/forward length ratio
    'fpl_s', 'bpl_s', 'dpl_s',  # Bytes per second (throughput)

    # TCP flag count features (12)
    'fin_cnt', 'syn_cnt', 'rst_cnt', 'pst_cnt', 'ack_cnt', 'urg_cnt', 'cwe_cnt', 'ece_cnt',
    'fwd_pst_cnt', 'fwd_urg_cnt',  # PSH and URG in forward direction
    'bwd_pst_cnt', 'bwd_urg_cnt',  # PSH and URG in backward direction

    # Header length features (6)
    'fp_hdr_len', 'bp_hdr_len', 'dp_hdr_len',  # Total header length
    'f_ht_len', 'b_ht_len', 'd_ht_len'  # Header length to payload ratio
]


class flowProcess(Process):
    """Multi-process handler for processing PCAP files in parallel."""

    def __init__(self, writer: Any, read_pcap: Any, process_name: Optional[str] = None):
        """Initialize a flow processing worker.

        Args:
            writer: CSV writer object for output
            read_pcap: Function to read and process PCAP files
            process_name: Optional name for the process
        """
        Process.__init__(self)
        self.pcaps: List[str] = []
        self.process_name = process_name if process_name else ""
        self.writer = writer
        self.read_pcap = read_pcap

    def add_target(self, pcap_name: str) -> None:
        """Add a PCAP file to the processing queue.

        Args:
            pcap_name: Path to PCAP file
        """
        self.pcaps.append(pcap_name)

    def run(self) -> None:
        """Process all PCAP files in the queue."""
        print("process {} run".format(self.name))
        for pcap_name in self.pcaps:
            self.read_pcap(pcap_name, self.writer)
        print("process {} finish".format(self.name))

class Flow:
    """Represents a network flow defined by 5-tuple (src, sport, dst, dport, protocol)."""

    def __init__(self, src: str, sport: int, dst: str, dport: int, protol: str = "TCP"):
        """Initialize a Flow object.

        Args:
            src: Source IP address
            sport: Source port number
            dst: Destination IP address
            dport: Destination port number
            protol: Protocol (TCP/UDP)
        """
        self.src: str = src
        self.sport: int = sport
        self.dst: str = dst
        self.dport: int = dport
        self.protol: str = protol
        self.start_time: float = 1e11
        self.end_time: float = 0
        self.byte_num: int = 0
        self.packets: List[Any] = []

    def add_packet(self, packet: Any) -> None:
        """Add a packet to this flow.

        Args:
            packet: Scapy packet object
        """
        self.packets.append(packet)

    def get_flow_feature(self) -> Optional[List[float]]:
        """Extract and return flow features.

        Returns:
            List of 84 flow features, or None if flow has less than 2 packets
        """
        pkts = self.packets
        if len(pkts) <= 1:
            return None

        pkts.sort(key=sortKey)
        fwd_flow,bwd_flow=flow_divide(pkts,self.src)
        # print(len(fwd_flow),len(bwd_flow))
        # feature about packet arrival interval 13
        fiat_mean,fiat_min,fiat_max,fiat_std = packet_iat(fwd_flow)
        biat_mean,biat_min,biat_max,biat_std = packet_iat(bwd_flow)
        diat_mean,diat_min,diat_max,diat_std = packet_iat(pkts)

        # 为了防止除0错误，不让其为0
        duration = round(pkts[-1].time - pkts[0].time + 0.0001, 6) 
        
        # 拥塞窗口大小特征 15
        fwin_total,fwin_mean,fwin_min,fwin_max,fwin_std = packet_win(fwd_flow)
        bwin_total,bwin_mean,bwin_min,bwin_max,bwin_std = packet_win(bwd_flow)
        dwin_total,dwin_mean,dwin_min,dwin_max,dwin_std = packet_win(pkts)
        
        # feature about packet num  7
        fpnum=len(fwd_flow)
        bpnum=len(bwd_flow)
        dpnum=fpnum+bpnum
        bfpnum_rate = round(bpnum / max(fpnum, 1), 6)
        fpnum_s = round(fpnum / duration, 6)
        bpnum_s = round(bpnum / duration, 6)
        dpnum_s = fpnum_s + bpnum_s
        
        # 包的总长度 19
        fpl_total,fpl_mean,fpl_min,fpl_max,fpl_std = packet_len(fwd_flow)
        bpl_total,bpl_mean,bpl_min,bpl_max,bpl_std = packet_len(bwd_flow)
        dpl_total,dpl_mean,dpl_min,dpl_max,dpl_std = packet_len(pkts)
        bfpl_rate = round(bpl_total / max(fpl_total, 1), 6)
        fpl_s = round(fpl_total / duration, 6)
        bpl_s = round(bpl_total / duration, 6)
        dpl_s = fpl_s + bpl_s
        
        # 包的标志特征 12
        fin_cnt,syn_cnt,rst_cnt,pst_cnt,ack_cnt,urg_cnt,cwe_cnt,ece_cnt=packet_flags(pkts,0)
        fwd_pst_cnt,fwd_urg_cnt=packet_flags(fwd_flow,1)
        bwd_pst_cnt,bwd_urg_cnt=packet_flags(bwd_flow,1)
        
        # 包头部长度 6
        fp_hdr_len=packet_hdr_len(fwd_flow)
        bp_hdr_len=packet_hdr_len(bwd_flow)
        dp_hdr_len=fp_hdr_len + bp_hdr_len
        f_ht_len=round(fp_hdr_len / max(fpl_total, 1), 6)
        b_ht_len=round(bp_hdr_len / max(bpl_total, 1), 6)
        d_ht_len=round(dp_hdr_len / max(dpl_total, 1), 6)

        '''
        # 数据流起始的时间 
        tz = timezone(timedelta(hours = +8 )) # 根据utc时间确定其中的值,北京时间为+8
        dt = datetime.fromtimestamp(flow.start_time,tz)
        date = dt.strftime("%Y-%m-%d")
        time = dt.strftime("%H:%M:%S")
        '''
        feature = [fiat_mean,fiat_min,fiat_max,fiat_std,biat_mean,biat_min,biat_max,biat_std,
                diat_mean,diat_min,diat_max,diat_std,duration,fwin_total,fwin_mean,fwin_min,
                fwin_max,fwin_std,bwin_total,bwin_mean,bwin_min,bwin_max,bwin_std,dwin_total,
                dwin_mean,dwin_min,dwin_max,dwin_std,fpnum,bpnum,dpnum,bfpnum_rate,fpnum_s,
                bpnum_s,dpnum_s,fpl_total,fpl_mean,fpl_min,fpl_max,fpl_std,bpl_total,bpl_mean,
                bpl_min,bpl_max,bpl_std,dpl_total,dpl_mean,dpl_min,dpl_max,dpl_std,bfpl_rate,
                fpl_s,bpl_s,dpl_s,fin_cnt,syn_cnt,rst_cnt,pst_cnt,ack_cnt,urg_cnt,cwe_cnt,ece_cnt,
                fwd_pst_cnt,fwd_urg_cnt,bwd_pst_cnt,bwd_urg_cnt,fp_hdr_len,bp_hdr_len,dp_hdr_len,
            f_ht_len,b_ht_len,d_ht_len]

        return feature

    def __repr__(self):
        return "{}:{} -> {}:{} {}".format(self.src,
                                             self.sport,self.dst,
                                             self.dport,len(self.packets))

def NormalizationSrcDst(src: str, sport: int, dst: str, dport: int) -> Tuple[str, int, str, int]:
    """Normalize source and destination based on port numbers and IP addresses.

    This ensures consistent flow direction identification by always putting
    the 'server' side first (higher port number, or numerically larger IP if ports equal).

    Args:
        src: Source IP address
        sport: Source port
        dst: Destination IP address
        dport: Destination port

    Returns:
        Tuple of (normalized_src, normalized_sport, normalized_dst, normalized_dport)
    """
    if sport < dport:
        return (dst, dport, src, sport)
    elif sport == dport:
        src_ip = "".join(src.split('.'))
        dst_ip = "".join(dst.split('.'))
        if int(src_ip) < int(dst_ip):
            return (dst, dport, src, sport)
        else:
            return (src, sport, dst, dport)
    else:
        return (src, sport, dst, dport)

def tuple2hash(src: str, sport: int, dst: str, dport: int, protocol: str = "TCP") -> str:
    """Convert 5-tuple to SHA256 hash for dictionary storage.

    Args:
        src: Source IP address
        sport: Source port
        dst: Destination IP address
        dport: Destination port
        protocol: Protocol (TCP/UDP)

    Returns:
        SHA256 hash string
    """
    hash_str = src + str(sport) + dst + str(dport) + protocol
    return hashlib.sha256(hash_str.encode(encoding="UTF-8")).hexdigest()


def calculation(flow: List[float]) -> List[float]:
    """Calculate mean, min, max, and standard deviation of a list.

    Args:
        flow: List of numeric values

    Returns:
        List of [mean, min, max, std] rounded to 6 decimal places
    """
    if not flow:
        return [0.0, 0.0, 0.0, 0.0]

    min_val = min(flow)
    max_val = max(flow)
    mean_val = sum(flow) / len(flow)
    std_val = math.sqrt(sum((x - mean_val) ** 2 for x in flow) / len(flow))

    return [round(mean_val, 6), round(min_val, 6), round(max_val, 6), round(std_val, 6)]

def flow_divide(flow: List[Any], src: str) -> Tuple[List[Any], List[Any]]:
    """Divide flow into forward and backward packets based on source IP.

    Args:
        flow: List of packets
        src: Source IP address to use as reference

    Returns:
        Tuple of (forward_packets, backward_packets)
    """
    fwd_flow: List[Any] = []
    bwd_flow: List[Any] = []
    for pkt in flow:
        if pkt["IP"].src == src:
            fwd_flow.append(pkt)
        else:
            bwd_flow.append(pkt)
    return fwd_flow, bwd_flow


def packet_iat(flow: List[Any]) -> Tuple[float, float, float, float]:
    """Calculate inter-arrival time statistics for a packet flow.

    Args:
        flow: List of packets with timestamp information

    Returns:
        Tuple of (mean, min, max, std) IAT values
    """
    piat: List[float] = []
    if len(flow) > 0:
        pre_time = flow[0].time
        for pkt in flow[1:]:
            next_time = pkt.time
            piat.append(next_time - pre_time)
            pre_time = next_time
        piat_mean, piat_min, piat_max, piat_std = calculation(piat)
    else:
        piat_mean, piat_min, piat_max, piat_std = 0.0, 0.0, 0.0, 0.0
    return piat_mean, piat_min, piat_max, piat_std


def packet_len(flow: List[Any]) -> Tuple[float, float, float, float, float]:
    """Calculate packet length statistics.

    Args:
        flow: List of packets

    Returns:
        Tuple of (total, mean, min, max, std) packet lengths
    """
    pl: List[int] = []
    for pkt in flow:
        pl.append(len(pkt))
    pl_total = round(sum(pl), 6)
    pl_mean, pl_min, pl_max, pl_std = calculation(pl)
    return pl_total, pl_mean, pl_min, pl_max, pl_std


def packet_win(flow: List[Any]) -> Tuple[float, float, float, float, float]:
    """Calculate TCP window size statistics.

    Args:
        flow: List of TCP packets

    Returns:
        Tuple of (total, mean, min, max, std) window sizes
    """
    if len(flow) == 0:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    if flow[0]["IP"].proto != 6:  # 6 = TCP protocol number
        return 0.0, 0.0, 0.0, 0.0, 0.0
    pwin: List[int] = []
    for pkt in flow:
        pwin.append(pkt['TCP'].window)
    pwin_total = round(sum(pwin), 6)
    pwin_mean, pwin_min, pwin_max, pwin_std = calculation(pwin)
    return pwin_total, pwin_mean, pwin_min, pwin_max, pwin_std

def packet_flags(flow: List[Any], key: int) -> Any:
    """Count TCP flag occurrences in a packet flow.

    Args:
        flow: List of TCP packets
        key: 0 for all flags, 1 for PSH and URG only

    Returns:
        If key=0: List of 8 flag counts [FIN, SYN, RST, PSH, ACK, URG, CWE, ECE]
        If key=1: Tuple of (PSH_count, URG_count)
    """
    flag: List[int] = [0, 0, 0, 0, 0, 0, 0, 0]
    if len(flow) == 0:
        if key == 0:
            return [-1, -1, -1, -1, -1, -1, -1, -1]
        else:
            return -1, -1
    if flow[0]["IP"].proto != 6:
        if key == 0:
            return [-1, -1, -1, -1, -1, -1, -1, -1]
        else:
            return -1, -1
    for pkt in flow:
        flags = int(pkt['TCP'].flags)
        for i in range(8):
            flag[i] += flags % 2
            flags = flags // 2
    if key == 0:
        return flag
    else:
        return flag[3], flag[5]


def packet_hdr_len(flow: List[Any]) -> int:
    """Calculate total header length for all packets in flow.

    Args:
        flow: List of packets

    Returns:
        Total header length in bytes
    """
    p_hdr_len = 0
    for pkt in flow:
        # Ethernet header + IP header (4*ihl) + TCP header
        p_hdr_len += ETHERNET_HEADER_LEN + (4 * pkt['IP'].ihl) + TCP_HEADER_BASE_LEN
    return p_hdr_len


def sortKey(pkt: Any) -> float:
    """Sort key function for packets based on timestamp.

    Args:
        pkt: Packet object

    Returns:
        Packet timestamp
    """
    return pkt.time


def is_TCP_packet(pkt: Any) -> bool:
    """Check if a packet is a TCP/IP packet.

    Args:
        pkt: Packet object

    Returns:
        True if packet is TCP/IP, False otherwise
    """
    try:
        pkt['IP']
    except:
        return False  # drop the packet which is not IP packet
    if "TCP" not in pkt:
        return False
    return True

def is_handshake_packet(pkt: Any) -> bool:
    """Check if packet is a TCP handshake packet (SYN, SYN-ACK, FIN, FIN-ACK, or small ACK).

    Args:
        pkt: TCP packet object

    Returns:
        False if handshake packet, True otherwise
    """
    handshake_flags = ["S", "SA", "F", "FA"]
    if pkt['TCP'].flags in handshake_flags:
        return False
    if pkt['TCP'].flags == "A" and len(pkt) < 61:
        return False
    return True


def get_flow_feature_from_pcap(pcapname: str, writer: Any) -> None:
    """Extract features from all flows in a PCAP file and write to CSV.

    Args:
        pcapname: Path to PCAP file
        writer: CSV writer object
    """
    try:
        packets = rdpcap(pcapname)
    except (IOError, OSError) as e:
        print("Failed to read pcap file {}: {}".format(pcapname, e))
        return
    except Exception as e:
        print("Error processing pcap {}: {}".format(pcapname, e))
        return
    flows: dict = {}
    for pkt in packets:
        if not is_TCP_packet(pkt):
            continue
        proto = "TCP"
        src, sport, dst, dport = NormalizationSrcDst(pkt['IP'].src, pkt[proto].sport,
                                                     pkt['IP'].dst, pkt[proto].dport)
        hash_str = tuple2hash(src, sport, dst, dport, proto)
        if hash_str not in flows:
            flows[hash_str] = Flow(src, sport, dst, dport, proto)
        flows[hash_str].add_packet(pkt)
    pid = os.getpid()
    print("{} has {} flows pid={}".format(pcapname, len(flows), pid))
    for flow in flows.values():
        feature = flow.get_flow_feature()
        if feature is None:
            print("invalid flow {}:{}->{}:{}".format(flow.src, flow.sport, flow.dst, flow.dport))
            continue
        feature = [flow.src, flow.sport, flow.dst, flow.dport] + feature
        writer.writerow(feature)


def get_pcap_feature_from_pcap(pcapname: str, writer: Any) -> None:
    """Extract features from entire PCAP as a single flow and write to CSV.

    Args:
        pcapname: Path to PCAP file
        writer: CSV writer object
    """
    try:
        packets = rdpcap(pcapname)
    except (IOError, OSError) as e:
        print("Failed to read pcap file {}: {}".format(pcapname, e))
        return
    except Exception as e:
        print("Error processing pcap {}: {}".format(pcapname, e))
        return
    this_flow = None
    for pkt in packets:
        if not is_TCP_packet(pkt):
            continue
        proto = "TCP"
        src, sport, dst, dport = NormalizationSrcDst(pkt['IP'].src, pkt[proto].sport,
                                                     pkt['IP'].dst, pkt[proto].dport)
        if this_flow is None:
            this_flow = Flow(src, sport, dst, dport, proto)
            this_flow.dst_sets = set()
        this_flow.add_packet(pkt)
        this_flow.dst_sets.add(dst)

    if this_flow is None:
        return

    feature = this_flow.get_flow_feature()
    pid = os.getpid()
    print("{} has {} different IP pid={}".format(pcapname, len(this_flow.dst_sets), pid))
    if feature is None:
        print("invalid pcap {}".format(this_flow.src, this_flow.sport, this_flow.dst, this_flow.dport))
        return
    feature = [pcapname, len(this_flow.dst_sets)] + feature
    writer.writerow(feature)
