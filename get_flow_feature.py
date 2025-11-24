from flow import *
from tempfile import TemporaryFile
import configparser
import multiprocessing
from multiprocessing import Pool

def load_flows(flow_data,writer):
    import joblib
    flows = joblib.load(flow_data)
    for flow in flows.values():
        feature = flow.get_flow_feature()
        if feature is not None:
            feature = [flow.src,flow.sport,flow.dst,flow.dport] + feature
            writer.writerow(feature)

# Worker function to process a single pcap file
def process_pcap_worker(args):
    """Process a single pcap file and return features
    Args:
        args: tuple of (pcap_path, run_mode)
    Returns:
        list of features for all flows in the pcap
    """
    import os
    pcap_path, run_mode = args
    try:
        packets = rdpcap(pcap_path)
    except (IOError, OSError) as e:
        print(f"Failed to read pcap file {pcap_path}: {e}")
        return []
    except Exception as e:
        print(f"Error processing pcap {pcap_path}: {e}")
        return []

    if run_mode == "pcap":
        # pcap mode: treat all packets as one flow
        flows = {}
        this_flow = None
        for pkt in packets:
            if is_TCP_packet(pkt) == False:
                continue
            proto = "TCP"
            src,sport,dst,dport = NormalizationSrcDst(pkt['IP'].src,pkt[proto].sport,
                                                              pkt['IP'].dst,pkt[proto].dport)
            if this_flow == None:
                this_flow = Flow(src,sport,dst,dport,proto)
                this_flow.dst_sets = set()
            this_flow.add_packet(pkt)
            this_flow.dst_sets.add(dst)

        if this_flow is None:
            return []

        feature = this_flow.get_flow_feature()
        if feature is None:
            return []
        return [[os.path.basename(pcap_path), len(this_flow.dst_sets)] + feature]

    else:
        # flow mode: group by 5-tuple
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

        results = []
        for flow in flows.values():
            feature = flow.get_flow_feature()
            if feature is not None:
                feature = [flow.src,flow.sport,flow.dst,flow.dport] + feature
                results.append(feature)
        return results

if __name__ == "__main__":
    start_time = time.time()
    config = configparser.ConfigParser()
    config.read("run.conf")
    run_mode = config.get("mode","run_mode")
    csvname = config.get("mode","csv_name")

    # Decide whether to write column names to csv
    if config.getboolean("feature","print_colname"):
        with open(csvname, "w+", newline="") as file:
            writer = csv.writer(file)
            if run_mode == "flow":
                col_names = ['src','sport','dst','dport'] + feature_name
            else:
                col_names = ['pcap_name','flow_num'] + feature_name
            writer.writerow(col_names)
        print("Written column names to CSV")
    else:
        # Create empty output file
        open(csvname, "w").close()

    # load function - no longer read pcap file after load
    if config.getboolean("joblib","load_switch"):
        load_file = config.get("joblib","load_name")
        print("Loading ", load_file)
        with open(csvname, "a+", newline="") as file:
            writer = csv.writer(file)
            load_flows(load_file, writer)

    # Read pcap files
    elif config.getboolean("mode","read_all"):
        # read all pcap files in specified directory
        path = config.get("mode","pcap_loc")
        if path == "./" or path == "pwd":
            path = os.getcwd()
        all_files = [f for f in os.listdir(path) if f.endswith(".pcap")]
        pcap_paths = [os.path.join(path, f) for f in all_files]

        if len(pcap_paths) == 0:
            print("No pcap files found in directory:", path)
            exit(1)

        multi_process = config.getboolean("mode","multi_process")
        if multi_process:
            process_num = config.getint("mode","process_num")
            cpu_num = multiprocessing.cpu_count()
            # limit cpu_num
            if process_num > cpu_num or process_num < 1:
                print(f"Warning: process_num {process_num} exceeds CPU count {cpu_num}! Using {cpu_num}")
                process_num = cpu_num

            print(f"Processing {len(pcap_paths)} pcap files with {process_num} processes...")
            with Pool(processes=process_num) as pool:
                results = pool.map(process_pcap_worker, [(p, run_mode) for p in pcap_paths])

            # Write all results to CSV
            with open(csvname, "a+", newline="") as file:
                writer = csv.writer(file)
                for result in results:
                    for feature in result:
                        writer.writerow(feature)
        else:
            # Single process mode
            with open(csvname, "a+", newline="") as file:
                writer = csv.writer(file)
                for pcap_path in pcap_paths:
                    results = process_pcap_worker((pcap_path, run_mode))
                    for feature in results:
                        writer.writerow(feature)

    else:
        # read specified pcap file
        pcapname = config.get("mode","pcap_name")
        results = process_pcap_worker((pcapname, run_mode))
        with open(csvname, "a+", newline="") as file:
            writer = csv.writer(file)
            for feature in results:
                writer.writerow(feature)

    end_time = time.time()
    print("Finished in {} seconds".format(end_time-start_time))
