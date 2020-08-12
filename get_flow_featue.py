
import os
from flow import *

# 判断是否是TCP的数据包
def is_TCP_packet(pkt):
    try:
        pkt['IP'] 
    except:
        return False # 抛掉不是IP协议的数据包
    if "TCP" not in pkt:
        return False
    return True

 
# 判断是否是握手阶段的数据包
def is_handshake_packet(pkt):
    handshake_flags = ["S","SA","F","FA"]
    if pkt['TCP'].flags in handshake_flags:
        #print("drop ",pkt['TCP'].flags)
        return False
    if pkt['TCP'].flags == "A" and len(pkt) <61:
        #print("drop ACK")
        return False
    return True
    
# pcapname：输入pcap的文件名
# writer 
# 获取数据流的特征并写入csv
def get_flow_feature_from_pcap(pcapname,writer):
    try:
        # 可能存在格式错误读取失败的情况
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

    print("{} 有{}条数据流".format(pcapname,len(flows)))
    for flow in flows.values():
        feature = flow.get_flow_feature()
        if feature == None:
            # 无效flow，提不出来有效特征
            print("invalid flow {}:{}->{}:{}".format(flow.src,flow.sport,flow.dst,flow.dport))
            continue
        feature = [flow.src,flow.dst] + feature
        writer.writerow(feature)

# pcapname：输入pcap的文件名
# writer
# 统计整个pcap的特征信息
def get_pcap_feature_from_pcap(pcapname,writer):
    try:
        # 可能存在格式错误读取失败的情况
        packets=rdpcap(pcapname)
    except Exception as e:
        print("read {} ERROR:{}".format(pcapname,e))
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
    print("{} 中有{}个目的IP".format(pcapname,len(this_flow.dst_sets)))
    if feature == None:
        # 无效flow，提不出来有效特征
        print("invalid pcap {}".format(this_flow.src,this_flow.sport,this_flow.dst,this_flow.dport))
        return  
    feature = [pcapname,len(this_flow.dst_sets)] + feature
    writer.writerow(feature)



def load_flows(flow_data,writer):
    import joblib
    flows = joblib.load(flow_data)
    for flow in flows.values():
        feature = flow.get_flow_feature()
        feature = [flow.src,flow.dst] + feature
        writer.writerow(feature)

if __name__ == "__main__":

    config = configparser.ConfigParser()
    config.read("run.conf")
    run_mode = config.get("mode","run_mode")

    # 决定后续read_pcap代表的函数
    if run_mode == "pcap":
        read_pcap = get_pcap_feature_from_pcap
    else:
        read_pcap = get_flow_feature_from_pcap
        
    csvname = config.get("mode","csv_name")
    file = open(csvname,"w+")
    writer = csv.writer(file)

    # 写入表头
    if config.getboolean("feature","print_colname"):
        if run_mode == "flow":
            feature_name = ['src','dst'] + feature_name
        else:
            feature_name = ['pcap_name','flow_num'] + feature_name
        writer.writerow(feature_name) 
    
    # load功能
    # load后，不再读取pcap文件
    if config.getboolean("joblib","load_switch"):
        load_file = config.get("joblib","load_name")
        print("Loading ",load_file)
        load_flows(load_file,writer)
    elif config.getboolean("mode","read_all"):
        # 读取指定目录下的所有pcap文件
        path = config.get("mode","pcap_loc")
        if path == "./" or path == "pwd":
            path = os.getcwd()
        
        all_file = os.listdir(path)
        for pcapname in all_file:
            if ".pcap" in pcapname:
                # 只读取pcap文件
                read_pcap(path+'/'+pcapname,writer)
    else:
        # 读取指定pcap文件
        pcapname = config.get("mode","pcap_name")
        flows = get_flow_feature_from_pcap(pcapname,writer)
        if config.getboolean("joblib","dump_switch"):
            from joblib import *
            dump(flows,"flows.data")
    file.close()

    
    
    