import hashlib
import math
import configparser
from joblib import *
from datetime import datetime, timedelta, timezone
import scapy
from scapy.all import *
from scapy.utils import PcapReader
#from scapy_ssl_tls.scapy_ssl_tls import *
import csv


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
        # 在当前流下新增一个数据包
        '''
        self.byte_num += len(packet)
        timestamp = packet.time   # 浮点型
        self.start_time = min(timestamp,self.start_time)
        self.end_time = max(timestamp,self.end_time)
        packet_head = ""
        if packet["IP"].src == self.src:
            # 代表这是一个客户端发往服务器的包
            packet_head += "---> "   
            if self.protol == "TCP":
                # 对TCP包额外处理
                packet_head += "[{:^4}] ".format(str(packet['TCP'].flags))
        else:
            packet_head += "<--- "
        #packet_information = packet_head + "timestamp={}".format(timestamp)
        '''
        self.packets.append(packet)

    def __repr__(self):
        return "{} {}:{} -> {}:{} {} {} {}".format(self.protol,self.src,
                                             self.sport,self.dst,
                                             self.dport,self.byte_num,
                                            self.start_time,self.end_time)

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
        
# 均值,标准差,最大值,最小值计算
def calculation(list_info):
    mean_,min_,max_,std_=0,0,0,0
    if len(list_info) < 1:
        return [mean_,min_,max_,std_]
    else:
        min_=round(min(list_info),6)
        max_=round(max(list_info),6)
        mean_ = round(sum(list_info)/len(list_info),6)
        sd = sum([(i - mean_) ** 2 for i in list_info])
        std_ = round(math.sqrt(sd / (len(list_info))),6)
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
    #print("end divide",pkt.src)
    return fwd_flow,bwd_flow



# 包到达时间间隔特征 
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

# 包头部长度
def packet_hdr_len(flow): 
    p_hdr_len=0
    for pkt in flow:
        p_hdr_len = p_hdr_len+14+4*pkt['IP'].ihl+20
    return p_hdr_len


def sortKey(pkt):
    return pkt.time

