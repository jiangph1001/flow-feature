
import os,decimal
from flow import *

# 计算单条flow的特征
# 如果无法计算，则返回None
def flow_features(flow):
    pkts = flow.packets
    if len(pkts) <= 1:
        # 如果该流仅有一个数据包，则不再统计特征
        return None

    pkts.sort(key=sortKey)
    fwd_flow,bwd_flow=flow_divide(pkts,flow.src)
    #print(len(fwd_flow),len(bwd_flow))
    # 包到达的时间间隔 13
    fiat_mean,fiat_min,fiat_max,fiat_std = packet_iat(fwd_flow)
    biat_mean,biat_min,biat_max,biat_std = packet_iat(bwd_flow)
    diat_mean,diat_min,diat_max,diat_std = packet_iat(pkts)
    duration = round(pkts[-1].time - pkts[0].time+ decimal.Decimal(0.0001), 6) 
    
    # 拥塞窗口大小特征 15
    fwin_total,fwin_mean,fwin_min,fwin_max,fwin_std = packet_win(fwd_flow)
    bwin_total,bwin_mean,bwin_min,bwin_max,bwin_std = packet_win(bwd_flow)
    dwin_total,dwin_mean,dwin_min,dwin_max,dwin_std = packet_win(pkts)
    
    # 包的数目 7
    fpnum=len(fwd_flow)
    bpnum=len(bwd_flow)
    dpnum=fpnum+bpnum
    bfpnum_rate = round(bpnum / (fpnum + 0.001), 6) 
    fpnum_s = round(fpnum / duration, 6)
    bpnum_s = round(bpnum / duration, 6)
    dpnum_s = round(dpnum / duration, 6)
    
    # 包的总长度 19
    fpl_total,fpl_mean,fpl_min,fpl_max,fpl_std = packet_len(fwd_flow)
    bpl_total,bpl_mean,bpl_min,bpl_max,bpl_std = packet_len(bwd_flow)
    dpl_total,dpl_mean,dpl_min,dpl_max,dpl_std = packet_len(pkts)
    bfpl_rate = round(bpl_total / (fpl_total + 0.001), 6) 
    fpl_s = round(fpl_total / duration, 6)
    bpl_s = round(bpl_total / duration, 6)
    dpl_s = round(dpl_total / duration, 6)
    
    # 包的标志特征 12
    fin_cnt,syn_cnt,rst_cnt,pst_cnt,ack_cnt,urg_cnt,cwe_cnt,ece_cnt=packet_flags(pkts,0)
    fwd_pst_cnt,fwd_urg_cnt=packet_flags(fwd_flow,1)
    bwd_pst_cnt,bwd_urg_cnt=packet_flags(bwd_flow,1)
    
    # 包头部长度 6
    fp_hdr_len=packet_hdr_len(fwd_flow)
    bp_hdr_len=packet_hdr_len(bwd_flow)
    dp_hdr_len=packet_hdr_len(pkts)
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

# 丢弃非TCP的数据包
def is_TCP_packet(pkt):
    try:
        pkt['IP'] 
    except:
        return False # 抛掉不是IP协议的数据包
    if "TCP" not in pkt:
        return False
    return True
# 丢弃握手阶段的数据包

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
        feature = flow_features(flow)
        if feature == None:
            print("invalid flow {}->{}".format(flow.src,flow.dst))
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

    feature = flow_features(this_flow)
    feature = [pcapname,len(this_flow.dst_sets)] + feature
    writer.writerow(feature)



def load_flows(flow_data,writer):
    flows = load(flow_data)
    for flow in flows.values():
        feature = flow_features(flow)
        feature = [flow.src,flow.dst] + feature
        writer.writerow(feature)

if __name__ == "__main__":

    feature_name=['fiat_mean','fiat_min','fiat_max','fiat_std','biat_mean','biat_min','biat_max','biat_std',
             'diat_mean','diat_min','diat_max','diat_std','duration','fwin_total','fwin_mean','fwin_min',
             'fwin_max','fwin_std','bwin_total','bwin_mean','bwin_min','bwin_max','bwin_std','dwin_total',
             'dwin_mean','dwin_min','dwin_max','dwin_std','fpnum','bpnum','dpnum','bfpnum_rate','fpnum_s',
             'bpnum_s','dpnum_s','fpl_total','fpl_mean','fpl_min','fpl_max','fpl_std','bpl_total','bpl_mean',
             'bpl_min','bpl_max','bpl_std','dpl_total','dpl_mean','dpl_min','dpl_max','dpl_std','bfpl_rate',
             'fpl_s','bpl_s','dpl_s','fin_cnt','syn_cnt','rst_cnt','pst_cnt','ack_cnt','urg_cnt','cwe_cnt','ece_cnt',
             'fwd_pst_cnt','fwd_urg_cnt','bwd_pst_cnt','bwd_urg_cnt','fp_hdr_len','bp_hdr_len','dp_hdr_len',''
            'f_ht_len','b_ht_len','d_ht_len']

    config = configparser.ConfigParser()
    config.read("run.conf")
    run_mode = config.get("mode","run_mode")


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
        read_pcap(pcapname,writer)
        
    if config.getboolean("joblib","dump_switch"):
        dump(flows,"flows.data")
    file.close()

    
    
    