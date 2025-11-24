<div align="center">

# PCAP Flow Feature Extractor

**Extract network flow features from PCAP files for machine learning and network analysis**

**[中文版本](README_zh.md)**

[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/downloads/)
[![Scapy](https://img.shields.io/badge/scapy-2.x-green.svg)](https://scapy.net/)
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](https://opensource.org/licenses/MIT)

</div>

---

## ⚡ Quick Start

```bash
# Clone and setup
git clone <repository-url>
cd flow-feature

# Create virtual environment
uv venv
uv pip install -r requirements.txt

# Run tests
uv run python test_flow_feature.py

# Extract features
python get_flow_feature.py
```

## 🎯 Important Updates (November 2025)

✅ **Critical Bug Fixes & Security Updates**
- ✅ Multi-processing now safe to use (no more data corruption)
- ✅ Upgraded from MD5 to SHA256 for better security
- ✅ Fixed broken dump/load functionality
- ✅ Fixed missing port information in flow mode
- ✅ Fixed CSV column name errors
- ✅ Added comprehensive unit tests (31 test cases, all passing)

📄 See [CHANGES.md](CHANGES.md) for detailed migration guide.

## 📦 Installation

### Prerequisites

- Python 3.x
- pip or uv package manager

### Install Dependencies

Using pip:
```bash
pip install scapy
pip install ConfigParser
pip install joblib  # Optional
```

Using uv (Recommended):
```bash
uv venv
uv pip install -r requirements.txt
```

### Requirements File

Create a `requirements.txt` file:
```
scapy>=2.4.0
ConfigParser
joblib
```

## 🚀 Features

Extract network flow features from PCAP files and export to CSV for analysis and machine learning. Two versions available:
- **Basic Edition**: Simple statistical features with TCP/UDP support
- **Advanced Edition**: Comprehensive TCP flow features with 84+ metrics

## 📖 Basic Edition

**File**: `flow_basic.py`

Extracts basic statistical features from network flows.

### Features (10 metrics)

| Feature | Description | Count |
|---------|-------------|-------|
| Start Time | Flow start timestamp | 1 |
| Duration | Flow duration (seconds) | 1 |
| Source IP | Source IP address | 1 |
| Source Port | Source port number | 1 |
| Destination IP | Destination IP address | 1 |
| Destination Port | Destination port number | 1 |
| Packet Count | Total number of packets | 1 |
| Traffic Volume | Total bytes transferred | 1 |
| Avg Packet Length | Average packet size | 1 |
| Protocol | Transport protocol (TCP/UDP) | 1 |

### Usage

```bash
# Process single pcap
python flow_basic.py --pcap file.pcap --output output.csv

# Process all pcap files in directory
python flow_basic.py --all --output output.csv

# Suppress console output
python flow_basic.py --pcap file.pcap --nolog
```

### Command Line Arguments

| Argument | Short | Description |
|----------|-------|-------------|
| `--all` | `-a` | Process all pcap files in current directory. Overrides `--pcap` |
| `--pcap` | `-p` | Process single pcap file |
| `--output` | `-o` | Output CSV filename (default: `stream.csv`) |
| `--nolog` | `-n` | Suppress console logging |

## 🎯 Advanced Edition

**File**: `get_flow_feature.py`

Extracts comprehensive TCP flow features for advanced network analysis and intrusion detection.

### Features (84+ metrics)

| Category | Features | Count | Description |
|----------|----------|-------|-------------|
| **Identifiers** | src, sport, dst, dport | 4 | 5-tuple flow identifiers |
| **Inter-Arrival Time** | fiat_*, biat_*, diat_* | 12 | Forward/Backward/All direction IAT stats (mean, min, max, std) |
| **Duration** | duration | 1 | Flow duration |
| **Window Size** | fwin_*, bwin_*, dwin_* | 15 | TCP window size statistics |
| **Packet Count** | fpnum, bpnum, dpnum, rates | 6 | Packet counts and rates per second |
| **Packet Length** | fpl_*, bpl_*, dpl_*, rates | 21 | Packet length statistics and throughput |
| **TCP Flags** | *_cnt, fwd_*_cnt, bwd_*_cnt | 12 | TCP flag counts (FIN, SYN, RST, PSH, ACK, URG, CWE, ECE) |
| **Header Length** | *_hdr_len, *_ht_len | 6 | Header length statistics and ratios |

**Total**: 77+77 metrics for comprehensive flow analysis.

### Configuration

Configure via `run.conf`:

```ini
[mode]
run_mode = flow      # flow or pcap
read_all = False
pcap_name = test.pcap
pcap_loc = ./
csv_name = features.csv
multi_process = True
process_num = 4

[feature]
print_colname = True

[joblib]
dump_switch = False
load_switch = False
load_name = flows.data
```

### Usage Scenarios

#### 1. Process Single Large PCAP with Dump

```ini
[mode]
read_all = False
pcap_name = large_traffic.pcap
dump_switch = True

[joblib]
dump_switch = True
```

#### 2. Load Pre-processed Data

```ini
[joblib]
load_switch = True
load_name = flows.data
```

#### 3. Process Directory of PCAPs with Multi-processing

```ini
[mode]
run_mode = flow
read_all = True
pcap_loc = /path/to/pcaps/
multi_process = True
process_num = 8
```

### Mode Parameters

#### Basic Settings
- `run_mode`: Operation mode
  - `flow`: Group packets by 5-tuple (src, sport, dst, dport). CSV columns: `src, sport, dst, dport, ...`
  - `pcap`: Treat all packets in each PCAP as one flow. CSV columns: `pcap_name, flow_num, ...`
- `read_all`: Process directory (`True`) or single file (`False`)
- `pcap_loc`: Directory path for batch processing
- `pcap_name`: Single pcap filename
- `csv_name`: Output CSV filename

#### Performance Settings
- `multi_process`: Enable multi-processing (✅ **Now Safe!**)
- `process_num`: Number of processes (recommended: CPU core count)

#### Feature Settings
- `print_colname`: Write header row to CSV
- `print_port`: Reserved parameter
- `add_tag`: Reserved parameter

#### Joblib Cache Settings
- `dump_switch`: Save intermediate flow data to file (only for single pcap)
- `load_switch`: Load pre-processed flow data from file
- `load_name`: Cache filename (default: `flows.data`)

## 🧪 Testing

### Run Unit Tests

```bash
# Using uv (recommended)
uv run python test_flow_feature.py

# Direct execution
python test_flow_feature.py

# Using pytest
pytest test_flow_feature.py -v
```

### Test Coverage

**31 tests covering:**
- ✅ Flow normalization (NormalizationSrcDst)
- ✅ SHA256 hash generation (tuple2hash)
- ✅ Statistical calculations (mean, std, min, max)
- ✅ Flow separation logic
- ✅ Inter-arrival time calculations
- ✅ Packet length calculations
- ✅ Flow class operations
- ✅ TCP packet detection
- ✅ Edge cases (empty flows, non-TCP packets)
- ✅ Division by zero prevention

### Test Results

```
Ran 31 tests in X.XXXs

OK ✅
```

## 📊 Use Cases

- **Network Intrusion Detection**: Extract features for ML-based IDS training
- **Traffic Analysis**: Analyze network behavior patterns
- **Malware Detection**: Identify malicious traffic characteristics
- **QoS Analysis**: Evaluate network performance metrics
- **Flow Classification**: Categorize different types of network traffic

## 🔧 Contributing

We welcome contributions! Please:

1. **Run tests** before submitting:
   ```bash
   python test_flow_feature.py
   ```

2. **Add tests** for new functionality

3. **Update CHANGES.md** with your changes

4. **Follow the coding style** and add docstrings

### Development Setup

```bash
# Clone repository
git clone <repository>
cd flow-feature

# Create development environment
uv venv
uv pip install -r requirements.txt

# Run tests
uv run python test_flow_feature.py

# Create feature branch
git checkout -b feature/your-feature-name
```

## 📝 Changelog

### November 2025 - Critical Fixes
- ✅ Fixed multi-processing implementation (now safe to use)
- ✅ Upgraded MD5 to SHA256 for security
- ✅ Fixed dump/load functionality completely
- ✅ Fixed missing port information in flow mode
- ✅ Fixed CSV column name errors
- ✅ Added 31 comprehensive unit tests
- ✅ Fixed division-by-zero errors
- ✅ Improved exception handling

### August 2022
- Fixed timestamp format to human-readable
- Added option to disable console logging in basic edition
- Updated documentation

### February 2021
- Optimized feature calculation logic
- Identified multi-threading bug (now fixed)

### August 2020
- Added multi-processing support (⚠️ originally buggy, now fixed)

### Earlier Versions
- See [CHANGES.md](CHANGES.md) for full history

## ⚠️ Migration Guide (November 2025 Update)

### Breaking Changes

1. **Hash Algorithm Changed**: MD5 → SHA256
   - Same data now produces different hash values
   - If using persistent flow data, regenerate cache files

2. **CSV Format Updated** (Flow Mode):
   - Added `sport` and `dport` columns
   - Update downstream applications to handle new format

### Recommended Actions

1. **Regenerate cached files** if using joblib dump/load
2. **Update data processing pipelines** for new CSV columns
3. **Enable multi-processing** for better performance (now safe!)
4. **Run full test suite** to verify compatibility

## 📄 License

This project is licensed under the MIT License. See the repository for details.

---

<div align="center">

## 中文版本

[English Version](#pcap-flow-feature-extractor)

</div>

---
