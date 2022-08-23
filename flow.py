import math,decimal,hashlib,csv,uuid,time,os

import scapy
from scapy.all import *
from scapy.utils import PcapReader
#from scapy_ssl_tls.scapy_ssl_tls import *
#from datetime import datetime, timedelta, timezone
#import threading

from multiprocessing import Process
feature_name=['fiat_mean','fiat_min','fiat_max','fiat_std','biat_mean','biat_min','biat_max','biat_std',
             'diat_mean','diat_min','diat_max','diat_std','duration','fwin_total','fwin_mean','fwin_min',
             'fwin_max','fwin_std','bwin_total','bwin_mean','bwin_min','bwin_max','bwin_std','dwin_total',
             'dwin_mean','dwin_min','dwin_max','dwin_std','fpnum','bpnum','dpnum','bfpnum_rate','fpnum_s',
             'bpnum_s','dpnum_s','fpl_total','fpl_mean','fpl_min','fpl_max','fpl_std','bpl_total','bpl_mean',
             'bpl_min','bpl_max','bpl_std','dpl_total','dpl_mean','dpl_min','dpl_max','dpl_std','bfpl_rate',
             'fpl_s','bpl_s','dpl_s','fin_cnt','syn_cnt','rst_cnt','pst_cnt','ack_cnt','urg_cnt','cwe_cnt','ece_cnt',
             'fwd_pst_cnt','fwd_urg_cnt','bwd_pst_cnt','bwd_urg_cnt','fp_hdr_len','bp_hdr_len','dp_hdr_len',''
            'f_ht_len','b_ht_len','d_ht_len']

class flowProcess(Process):
    def __init__(self, writer,read_pcap,process_name = None):
        Process.__init__(self)
        self.pcaps = []
        if process_name is None:
            self.process_name = uuid.uuid1()
        else:
            self.process_name = process_name
        self.writer = writer
        self.read_pcap = read_pcap
    def add_target(self,pcap_name):
        self.pcaps.append(pcap_name)
    def run(self):
        print("process {} run".format(self.name))
        for pcap_name in self.pcaps:
            self.read_pcap(pcap_name,self.writer)
        print("process {} finish".format(self.name))

class Flow:
    def __init__(self,src,sport,dst,dport,protol = "TCP"):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.protol = protol
        self.start_time = 1e11
        self.end_time = 0
        self.byte_num = 0
        self.packets = []
    def add_packet(self,packet):
        # add new packet in this flow
        '''
        self.byte_num += len(packet)
        timestamp = packet.time   # float
        self.start_time = min(timestamp,self.start_time)
        self.end_time = max(timestamp,self.end_time)
        packet_head = ""
        if packet["IP"].src == self.src:
            # means this is a packet which comes from client
            packet_head += "---> "   
            if self.protol == "TCP":
                packet_head += "[{:^4}] ".format(str(packet['TCP'].flags))
        else:
            packet_head += "<--- "
        # packet_information = packet_head + "timestamp={}".format(timestamp)
        '''
        self.packets.append(packet)

    # get this flow's feature
    def get_flow_feature(self):
        pkts = self.packets
        if len(pkts) <= 1:
            # if there is only one packet in this flow
            # return None
            return None

        pkts.sort(key=sortKey)
        fwd_flow,bwd_flow=flow_divide(pkts,self.src)
        # print(len(fwd_flow),len(bwd_flow))
        # feature about packet arrival interval 13
        fiat_mean,fiat_min,fiat_max,fiat_std = packet_iat(fwd_flow)
        biat_mean,biat_min,biat_max,biat_std = packet_iat(bwd_flow)
        diat_mean,diat_min,diat_max,diat_std = packet_iat(pkts)

        # 为了防止除0错误，不让其为0
        duration = round(pkts[-1].time - pkts[0].time+ decimal.Decimal(0.0001), 6) 
        
        # 拥塞窗口大小特征 15
        fwin_total,fwin_mean,fwin_min,fwin_max,fwin_std = packet_win(fwd_flow)
        bwin_total,bwin_mean,bwin_min,bwin_max,bwin_std = packet_win(bwd_flow)
        dwin_total,dwin_mean,dwin_min,dwin_max,dwin_std = packet_win(pkts)
        
        # feature about packet num  7
        fpnum=len(fwd_flow)
        bpnum=len(bwd_flow)
        dpnum=fpnum+bpnum
        bfpnum_rate = round(bpnum / (fpnum + 0.001), 6) 
        fpnum_s = round(fpnum / duration, 6)
        bpnum_s = round(bpnum / duration, 6)
        dpnum_s = fpnum_s + bpnum_s
        
        # 包的总长度 19
        fpl_total,fpl_mean,fpl_min,fpl_max,fpl_std = packet_len(fwd_flow)
        bpl_total,bpl_mean,bpl_min,bpl_max,bpl_std = packet_len(bwd_flow)
        dpl_total,dpl_mean,dpl_min,dpl_max,dpl_std = packet_len(pkts)
        bfpl_rate = round(bpl_total / (fpl_total + 0.001), 6) 
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
        f_ht_len=round(fp_hdr_len /(fpl_total+1), 6)
        b_ht_len=round(bp_hdr_len /(bpl_total+1), 6)
        d_ht_len=round(dp_hdr_len /dpl_total, 6)

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

# 根据规则区分服务器和客户端
def NormalizationSrcDst(src,sport,dst,dport):
    if sport < dport:
        return (dst,dport,src,sport)
    elif sport == dport:
        src_ip = "".join(src.split('.'))
        dst_ip = "".join(dst.split('.'))
        if int(src_ip) < int(dst_ip):
            return (dst,dport,src,sport)
        else:
            return (src,sport,dst,dport)
    else:
        return (src,sport,dst,dport)

# 将五元组信息转换为MD5值,用于字典存储    
def tuple2hash(src,sport,dst,dport,protocol = "TCP"):
    hash_str = src+str(sport)+dst+str(dport)+protocol
    return hashlib.md5(hash_str.encode(encoding="UTF-8")).hexdigest()
        
# 输入:list
# 输出:mean,min,max,std
def calculation(flow):
    mean_,min_,max_,std_=0,0,0,0
    if len(flow) < 1:
        return [mean_,min_,max_,std_]
    else:
        min_=round(min(flow),6)
        max_=round(max(flow),6)
        mean_ = round(sum(flow)/len(flow),6)
        sd = sum([(i - mean_) ** 2 for i in flow])
        std_ = round(math.sqrt(sd / (len(flow))),6)
        return [mean_,min_,max_,std_]

# 划分上行流和下行流
def flow_divide(flow,src):
    fwd_flow=[]
    bwd_flow=[]
    for pkt in flow:
        if pkt["IP"].src == src:
            fwd_flow.append(pkt)
        else:
            bwd_flow.append(pkt)
    return fwd_flow,bwd_flow



# Packet arrival interval
def packet_iat(flow):    
    piat=[]
    if len(flow)>0:
        pre_time = flow[0].time
        for pkt in flow[1:]:
            next_time = pkt.time
            piat.append(next_time-pre_time)
            pre_time=next_time
        piat_mean,piat_min,piat_max,piat_std=calculation(piat)
    else:
        piat_mean,piat_min,piat_max,piat_std=0,0,0,0
    return piat_mean,piat_min,piat_max,piat_std


# 包长度特征
def packet_len(flow):   
    pl=[]
    for pkt in flow:
        pl.append(len(pkt))
    pl_total=round(sum(pl), 6)
    pl_mean,pl_min,pl_max,pl_std=calculation(pl)
    return pl_total,pl_mean,pl_min,pl_max,pl_std


# 拥塞窗口大小特征        
def packet_win(flow):
    if len(flow)==0:
        return 0,0,0,0,0
    if flow[0]["IP"].proto != 6:
        return 0,0,0,0,0
    pwin = [] 
    for pkt in flow:
        pwin.append(pkt['TCP'].window)
    pwin_total = round(sum(pwin), 6)
    pwin_mean,pwin_min,pwin_max,pwin_std=calculation(pwin)
    return pwin_total,pwin_mean,pwin_min,pwin_max,pwin_std

# 包中的标志字段统计
def packet_flags(flow,key):
    flag=[0,0,0,0,0,0,0,0]
    if len(flow) == 0:
        if key == 0:
            return [-1,-1,-1,-1,-1,-1,-1,-1]
        else:
            return -1,-1 
    if flow[0]["IP"].proto != 6:
        if key == 0:
            return [-1,-1,-1,-1,-1,-1,-1,-1]
        else:
            return -1,-1 
    for pkt in flow:
        flags=int(pkt['TCP'].flags)
        for i in range(8):
            flag[i] += flags%2
            flags=flags//2
    if key==0:
        return flag
    else:
        return flag[3],flag[5]

# length of packet header
def packet_hdr_len(flow): 
    p_hdr_len=0
    for pkt in flow:
        p_hdr_len = p_hdr_len+14+4*pkt['IP'].ihl+20
    return p_hdr_len


def sortKey(pkt):
    return pkt.time

# judge if it is tcp packet
def is_TCP_packet(pkt):
    try:
        pkt['IP'] 
    except:
        return False # drop the packet which is not IP packet
    if "TCP" not in pkt:
        return False
    return True

# judge if it is handshake packet 
def is_handshake_packet(pkt):
    handshake_flags = ["S","SA","F","FA"]
    if pkt['TCP'].flags in handshake_flags:
        #print("drop ",pkt['TCP'].flags)
        return False
    if pkt['TCP'].flags == "A" and len(pkt) <61:
        #print("drop ACK")
        return False
    return True
    
# get feature from flow which has same 5 tuple
def get_flow_feature_from_pcap(pcapname,writer):
    try:
        # It is possible that scapy can not read the pcap
        packets=rdpcap(pcapname)
    except Exception as e:
        print("read {} ERROR:{}".format(pcapname,e))
        return 
    flows = {}
    for pkt in packets:
        if is_TCP_packet(pkt) == False:
            continue
        proto = "TCP"
        src,sport,dst,dport = NormalizationSrcDst(pkt['IP'].src,pkt[proto].sport,
                                                          pkt['IP'].dst,pkt[proto].dport)
        hash_str = tuple2hash(src,sport,dst,dport,proto)
        if hash_str not in flows:
            flows[hash_str] = Flow(src,sport,dst,dport,proto)
        flows[hash_str].add_packet(pkt)
    pid = os.getpid()
    print("{} has {} flows pid={}".format(pcapname,len(flows),pid))
    for flow in flows.values():
        feature = flow.get_flow_feature()
        if feature == None:
            # can't get valid feature
            print("invalid flow {}:{}->{}:{}".format(flow.src,flow.sport,flow.dst,flow.dport))
            continue
        feature = [flow.src,flow.sport,flow.dst,flow.dport] + feature
        writer.writerow(feature)

# get a pcap feature
def get_pcap_feature_from_pcap(pcapname,writer):
    try:
        # It is possible that scapy can not read the pcap
        packets=rdpcap(pcapname)
    except Exception as e:
        print(" read {} ERROR:{} ".format(pcapname,e))
        return
    this_flow = None
    for pkt in packets:
        if is_TCP_packet(pkt) == False:
            continue
        proto = "TCP"
        src,sport,dst,dport = NormalizationSrcDst(pkt['IP'].src,pkt[proto].sport,
                                                          pkt['IP'].dst,pkt[proto].dport)
        # hash_key = tuple2hash(src,sport,dst,dport,proto)
        if this_flow == None:
            this_flow = Flow(src,sport,dst,dport,proto)
            this_flow.dst_sets = set()
        this_flow.add_packet(pkt)
        this_flow.dst_sets.add(dst)

    feature = this_flow.get_flow_feature()
    pid = os.getpid()
    print("{} has {} different IP pid={}".format(pcapname,len(this_flow.dst_sets),pid))
    if feature == None:
        # can't get valid feature
        print("invalid pcap {}".format(this_flow.src,this_flow.sport,this_flow.dst,this_flow.dport))
        return  
    feature = [pcapname,len(this_flow.dst_sets)] + feature
    writer.writerow(feature)
