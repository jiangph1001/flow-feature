<div align="center">

# PCAP Flow Feature Extractor

**Extract network flow features from PCAP files for machine learning and network analysis**

[中文版本](#中文版本) | English Version

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

## ⚡ 快速开始

```bash
# 克隆仓库
git clone <repository-url>
cd flow-feature

# 创建虚拟环境
uv venv
uv pip install -r requirements.txt

# 运行测试
uv run python test_flow_feature.py

# 提取特征
python get_flow_feature.py
```

## 🎯 重要更新 (2025年11月)

✅ **关键错误修复与安全更新**
- ✅ 多进程现在可安全使用（不会再导致数据损坏）
- ✅ MD5升级为更安全的SHA256算法
- ✅ 修复dump/load功能
- ✅ 修复flow模式缺失端口信息的问题
- ✅ 修复CSV列名错误
- ✅ 添加全面单元测试（31个测试用例，全部通过）

📄 查看 [CHANGES.md](CHANGES.md) 了解详细迁移指南。

## 📦 安装

### 前置要求

- Python 3.x
- pip 或 uv 包管理器

### 安装依赖

使用 pip:
```bash
pip install scapy
pip install ConfigParser
pip install joblib  # 可选
```

使用 uv (推荐):
```bash
uv venv
uv pip install -r requirements.txt
```

### 依赖文件

创建 `requirements.txt` 文件:
```
scapy>=2.4.0
ConfigParser
joblib
```

## 🚀 功能

从PCAP文件中提取网络流特征并导出为CSV，用于分析和机器学习。提供两个版本：
- **基础版**：简单的统计特征，支持TCP/UDP
- **高级版**：全面的TCP流特征，84+个指标

## 📖 基础版

**文件**: `flow_basic.py`

从网络流中提取基本统计特征。

### 特征 (10个指标)

| 特征 | 说明 | 数量 |
|---------|-------------|-------|
| 开始时间 | 流开始时间戳 | 1 |
| 持续时间 | 流持续时间（秒） | 1 |
| 源IP | 源IP地址 | 1 |
| 源端口 | 源端口号 | 1 |
| 目的IP | 目的IP地址 | 1 |
| 目的端口 | 目的端口号 | 1 |
| 包数量 | 总包数 | 1 |
| 流量 | 总传输字节数 | 1 |
| 平均包长 | 平均包大小 | 1 |
| 协议 | 传输协议（TCP/UDP） | 1 |

### 使用方法

```bash
# 处理单个pcap
python flow_basic.py --pcap file.pcap --output output.csv

# 处理目录下所有pcap文件
python flow_basic.py --all --output output.csv

# 禁用控制台输出
python flow_basic.py --pcap file.pcap --nolog
```

### 命令行参数

| 参数 | 短参数 | 说明 |
|----------|-------|-------------|
| `--all` | `-a` | 处理当前目录下所有pcap文件，会覆盖`--pcap` |
| `--pcap` | `-p` | 处理单个pcap文件 |
| `--output` | `-o` | 输出CSV文件名（默认：`stream.csv`） |
| `--nolog` | `-n` | 禁用控制台日志输出 |

## 🎯 高级版

**文件**: `get_flow_feature.py`

提取全面的TCP流特征，用于高级网络分析和入侵检测。

### 特征 (84+个指标)

| 类别 | 特征 | 数量 | 说明 |
|----------|----------|-------|-------------|
| **标识符** | src, sport, dst, dport | 4 | 五元组流标识符 |
| **包到达间隔时间** | fiat_*, biat_*, diat_* | 12 | 上行/下行/所有方向的IAT统计（均值、最小、最大、标准差） |
| **持续时间** | duration | 1 | 流持续时间 |
| **窗口大小** | fwin_*, bwin_*, dwin_* | 15 | TCP窗口大小统计 |
| **包数量** | fpnum, bpnum, dpnum, rates | 6 | 包计数和每秒速率 |
| **包长度** | fpl_*, bpl_*, dpl_*, rates | 21 | 包长度统计和吞吐量 |
| **TCP标志** | *_cnt, fwd_*_cnt, bwd_*_cnt | 12 | TCP标志计数（FIN, SYN, RST, PSH, ACK, URG, CWE, ECE） |
| **包头长度** | *_hdr_len, *_ht_len | 6 | 包头长度统计和比例 |

**总计**: 77个特征用于全面的流分析。

### 配置方法

通过 `run.conf` 配置:

```ini
[mode]
run_mode = flow      # flow 或 pcap模式
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

### 使用场景

#### 1. 处理单个大PCAP并保存缓存

```ini
[mode]
read_all = False
pcap_name = large_traffic.pcap
dump_switch = True

[joblib]
dump_switch = True
```

#### 2. 加载预处理数据

```ini
[joblib]
load_switch = True
load_name = flows.data
```

#### 3. 批量处理PCAP并使用多进程

```ini
[mode]
run_mode = flow
read_all = True
pcap_loc = /path/to/pcaps/
multi_process = True
process_num = 8
```

### 模式参数

#### 基础设置
- `run_mode`: 运行模式
  - `flow`: 按五元组（src, sport, dst, dport）分组。CSV列: `src, sport, dst, dport, ...`
  - `pcap`: 将每个PCAP的所有包视为一个流。CSV列: `pcap_name, flow_num, ...`
- `read_all`: 批量处理目录（`True`）或单个文件（`False`）
- `pcap_loc`: 批量处理时的目录路径
- `pcap_name`: 单个pcap文件名
- `csv_name`: 输出CSV文件名

#### 性能设置
- `multi_process`: 启用多进程（✅ **现在可安全使用！**）
- `process_num`: 进程数量（建议: CPU核心数）

#### 特征设置
- `print_colname`: 写入CSV表头行
- `print_port`: 保留参数
- `add_tag`: 保留参数

#### Joblib缓存设置
- `dump_switch`: 保存中间流到文件（仅单个pcap有效）
- `load_switch`: 从文件加载预处理流数据
- `load_name`: 缓存文件名（默认: `flows.data`）

## 🧪 测试

### 运行单元测试

```bash
# 使用uv（推荐）
uv run python test_flow_feature.py

# 直接运行
python test_flow_feature.py

# 使用pytest
pytest test_flow_feature.py -v
```

### 测试覆盖

**31个测试覆盖:**
- ✅ 流归一化（NormalizationSrcDst）
- ✅ SHA256哈希生成（tuple2hash）
- ✅ 统计计算（均值、标准差、最小、最大）
- ✅ 流分离逻辑
- ✅ 包到达间隔时间计算
- ✅ 包长度计算
- ✅ Flow类操作
- ✅ TCP包检测
- ✅ 边界情况（空流、非TCP包）
- ✅ 除零错误预防

### 测试结果

```
Ran 31 tests in X.XXXs

OK ✅
```

## 📊 应用场景

- **网络入侵检测**: 提取特征用于基于ML的IDS训练
- **流量分析**: 分析网络行为模式
- **恶意软件检测**: 识别恶意流量特征
- **QoS分析**: 评估网络性能指标
- **流分类**: 分类不同类型的网络流量

## 🔧 贡献指南

欢迎贡献！请遵循以下步骤：

1. **提交前运行测试**:
   ```bash
   python test_flow_feature.py
   ```

2. **为新功能添加测试**

3. **更新 CHANGES.md** 记录变更

4. **遵循代码风格** 并添加文档字符串

### 开发环境设置

```bash
# 克隆仓库
git clone <repository>
cd flow-feature

# 创建开发环境
uv venv
uv pip install -r requirements.txt

# 运行测试
uv run python test_flow_feature.py

# 创建功能分支
git checkout -b feature/your-feature-name
```

## 📝 更新日志

### 2025年11月 - 关键修复
- ✅ 修复多进程实现（现在可安全使用）
- ✅ MD5升级为SHA256提升安全性
- ✅ 完全修复dump/load功能
- ✅ 修复flow模式缺失端口信息
- ✅ 修复CSV列名错误
- ✅ 添加31个全面单元测试
- ✅ 修复除零错误
- ✅ 改进异常处理

### 2022年8月
- 修复时间戳格式为可读格式
- 基础版可禁用控制台日志
- 更新文档

### 2021年2月
- 优化特征计算逻辑
- 发现多线程bug（现已修复）

### 2020年8月
- 添加多进程支持（⚠️ 原本有bug，现已修复）

### 更早版本
- 查看 [CHANGES.md](CHANGES.md) 获取完整历史

## ⚠️ 迁移指南 (2025年11月更新)

### 破坏性变更

1. **哈希算法变更**: MD5 → SHA256
   - 相同数据现在生成不同哈希值
   - 如使用持久化流数据，请重新生成缓存文件

2. **CSV格式更新** (Flow模式):
   - 增加`sport`和`dport`列
   - 更新下游应用程序以处理新格式

### 推荐操作

1. **重新生成缓存文件** 如使用joblib dump/load
2. **更新数据处理管道** 适应新CSV列
3. **启用多进程** 提升性能（现在安全！）
4. **运行完整测试套件** 验证兼容性

## 📄 许可证

本项目基于MIT许可证。详见仓库。

