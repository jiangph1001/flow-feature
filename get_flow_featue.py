
from flow import *

def load_flows(flow_data,writer):
    import joblib
    flows = joblib.load(flow_data)
    for flow in flows.values():
        feature = flow.get_flow_feature()
        feature = [flow.src,flow.dst] + feature
        writer.writerow(feature)

if __name__ == "__main__":
    start_time = time.time()
    config = configparser.ConfigParser()
    config.read("run.conf")
    run_mode = config.get("mode","run_mode")

    # 决定后续read_pcap代表的函数
    if run_mode == "pcap":
        read_pcap = get_pcap_feature_from_pcap
    else:
        read_pcap = get_flow_feature_from_pcap
        
    csvname = config.get("mode","csv_name")
    

    # decide whether write column name to csv
    if config.getboolean("feature","print_colname"):
        with open(csvname,"w+") as file:
            writer = csv.writer(file)
            print("write colname")
            if run_mode == "flow":
                feature_name = ['src','sport','dst','dport'] + feature_name
            else:
                feature_name = ['pcap_name','flow_num'] + feature_name
            writer.writerow(feature_name) 
        file = open(csvname,"a+")
        writer = csv.writer(file)
    else:
        file = open(csvname,"w+")
        writer = csv.writer(file)

    

    # multi process 
    multi_process = config.getboolean("mode","multi_process")
    if multi_process == True:
        process_num = config.getint("mode","process_num")
        process_pool = []
        cpu_num = multiprocessing.cpu_count()
        # limit cpu_num 
        if process_num > cpu_num or process_num < 1:
            print("Maximum number of cores exceeded！")
            process_num = cpu_num
        for i in range(process_num):
            process_pool.append(flowProcess(writer,read_pcap,i))

    # load function
    # no longer read pcap file after load
    if config.getboolean("joblib","load_switch"):
        load_file = config.get("joblib","load_name")
        print("Loading ",load_file)
        load_flows(load_file,writer)
    elif config.getboolean("mode","read_all"):
        # read all pcap files in specified directory
        path = config.get("mode","pcap_loc")
        if path == "./" or path == "pwd":
            path = os.getcwd()
        all_file = os.listdir(path)
        if multi_process == True:
            for i in range(len(all_file)):
                pcap_name = all_file[i]
                if ".pcap" in pcap_name:
                    process_pool[i%process_num].add_target(path+'/'+pcap_name)
            for p in process_pool:
                p.start()
            for p in process_pool:
                p.join()
        else:
            for pcap_name in all_file:
                if ".pcap" in pcap_name:
                    read_pcap(path+'/'+pcap_name,writer)
    else:
        # read specified pcap file
        pcapname = config.get("mode","pcap_name")
        flows = get_flow_feature_from_pcap(pcapname,writer)
        if config.getboolean("joblib","dump_switch"):
            from joblib import *
            dump(flows,"flows.data")
    file.close()

    end_time = time.time()
    print("using {} s".format(end_time-start_time))
    
    