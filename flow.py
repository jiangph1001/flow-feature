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
        self.packets.append(packet)

    def __repr__(self):
        return "{} {}:{} -> {}:{} {} {} {}".format(self.protol,self.src,
                                             self.sport,self.dst,
                                             self.dport,self.byte_num,
                                            self.start_time,self.end_time)