import scapy
from scapy.all import *
from scapy.utils import PcapReader
import hashlib
import argparse
import csv,time
import os


noLog = False
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

# 将五元组信息转换为SHA256值,用于字典存储
def tuple2hash(src,sport,dst,dport,protocol):
    hash_str = src+str(sport)+dst+str(dport)+protocol
    return hashlib.sha256(hash_str.encode(encoding="UTF-8")).hexdigest()

## 测试用
def getStreamPacketsHistory(src,sport,dst,dport,protocol='TCP'):
    src,sport,dst,dport = NormalizationSrcDst(src,sport,dst,dport)
    hash_str = tuple2hash(src,sport,dst,dport,protocol)
    if hash_str not in streams:
        return []
    stream = streams[hash_str]
    print(stream)
    return stream.packets
        
    
class Stream:
    def __init__(self,src,sport,dst,dport,protol = "TCP"):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.protol = protol
        self.start_time = 0
        self.end_time = 0
        self.packet_num = 0
        self.byte_num = 0
        self.packets = []
    def add_packet(self,packet):
        # 在当前流下新增一个数据包
        self.packet_num += 1
        self.byte_num += len(packet)
        timestamp = packet.time   # 浮点型
        if self.start_time == 0:
            # 如果starttime还是默认值0，则立即等于当前时间戳
            self.start_time = timestamp
        self.start_time = min(timestamp,self.start_time)
        self.end_time = max(timestamp,self.end_time)
        packet_head = ""
        if packet["IP"].src == self.src:
            # 代表这是一个客户端发往服务器的包
            packet_head += "---> "   
            if self.protol == "TCP":
                # 对TCP包额外处理
                packet_head += "[{:^4}] ".format(str(packet['TCP'].flags))
                if self.packet_num == 1 or packet['TCP'].flags == "S":
                    # 对一个此流的包或者带有Syn标识的包的时间戳进行记录，作为starttime
                    self.start_time = timestamp
        else:
            packet_head += "<--- "
        packet_information = packet_head + "timestamp={}".format(timestamp)
        self.packets.append(packet_information)
        
    def get_timestamp(self,packet):
        if packet['IP'].proto == 'udp':
            #udp协议查不到时间戳
            return 0
        for t in packet['TCP'].options:
            if t[0] == 'Timestamp':
                return t[1][0]
        # 存在查不到时间戳的情况
        return -1
    def __repr__(self):
        return "{} {}:{} -> {}:{} {} {} {}".format(self.protol,self.src,
                                             self.sport,self.dst,
                                             self.dport,self.byte_num,
                                            self.start_time,self.end_time)

# 调试用的函数        
def print_stream():
    for inf in getStreamPacketsHistory('192.168.2.241',51829,'52.109.120.23',443,'TCP'):
        print(inf)
        
# pcapname：输入pcap的文件名
# csvname : 输出csv的文件名
def read_pcap(pcapname,csvname):
    try:
        # 可能存在格式错误读取失败的情况
        packets=rdpcap(pcapname)
    except (IOError, OSError):
        print("Failed to read pcap file: {}".format(pcapname))
        return
    except Exception:
        print("Error processing pcap: {}".format(pcapname))
        return
    global streams
    streams = {}
    for data in packets:
        try:
            # 抛掉不是IP协议的数据包
            data['IP']
        except:
            continue
        if data['IP'].proto == 6:
            protol = "TCP"
        elif data['IP'].proto == 17:
            protol = "UDP"
        else:
            #非这两种协议的包，忽视掉
            continue
        src,sport,dst,dport = NormalizationSrcDst(data['IP'].src,data[protol].sport,
                                                          data['IP'].dst,data[protol].dport)
        hash_str = tuple2hash(src,sport,dst,dport,protol)
        if hash_str not in streams:
            streams[hash_str] = Stream(src,sport,dst,dport,protol)
        streams[hash_str].add_packet(data)
    print("有{}条数据流".format(len(streams)))
    with open(csvname,"a+",newline="") as file:
        writer = csv.writer(file)
        for v in streams.values():
            writer.writerow((time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(v.start_time)),v.end_time-v.start_time,v.src,v.sport,v.dst,v.dport,
                             v.packet_num,v.byte_num,v.byte_num/v.packet_num,v.protol))
            if noLog == False:
                print(v)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-p","--pcap",help="pcap文件名",action='store',default='test.pcap')
    parser.add_argument("-o","--output",help="输出的csv文件名",action = 'store',default = "stream.csv")
    parser.add_argument("-a","--all",action = 'store_true',help ='读取当前文件夹下的所有pcap文件',default=False)
    parser.add_argument("-n","--nolog",action = 'store_true',help ='读取当前文件夹下的所有pcap文件',default=False)
    parser.add_argument("-t","--test",action = 'store_true',default = False)
    args = parser.parse_args()
    csvname = args.output
    noLog = args.nolog
    if args.all == False:
        pcapname = args.pcap
        read_pcap(pcapname,csvname)
    else:
        #读取当前目录下的所有文件
        path = os.getcwd()
        all_file = os.listdir(path)
        for pcapname in all_file:
            if ".pcap" in pcapname:
                # 只读取pcap文件
                read_pcap(pcapname,csvname)