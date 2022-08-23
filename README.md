程序使用Python的scapy库编写

环境:Python3

## warn
多进程模式下，若同时读取多个pcap文件，可能导致记录丢失。  
建议忽略多进程功能，仅设置并发数为1

## 依赖库

- 需要安装scapy,用于读取pcap文件`pip install scapy`

- ConfigParser用于读取配置文件`pip install ConfigParser`

- joblib(可选)`pip install joblib`



## 功能

读取pcap文件，输出多条流的信息到csv文件中


## 基础版 

`flow_basic.py`

输出每条流的基本统计特征

包含:

- 开始时间(%Y-%m-%d %H:%M:%S)
- 持续时间
- 源ip
- 源端口
- 目的ip
- 目的端口
- 包的数量
- 流量(字节数)
- 平均包长度
- 协议(支持**TCP**与**UDP**)


参数：

- `-a`,`--all` 读取当前目录下的所有pcap文件。若指定该参数，则`-p`失效
- `-p`,`--pcap`  读取单个pcap文件，后面跟pcap文件名
- `-o`,`--output` 指定输出的csv文件名，默认为`stream.csv`
- `-n`,`--nolog`  不在控制台输出日志

## 高级版



`get_flow_feature.py`


仅支持**TCP**,输出包含:


名称|解释| 数量
--|--|--
src|源ip|1
sport| 源端口 |1
dst|目的ip|1
dport|目的端口|1
fiat_*|上行-包到达时间间隔(mean,min,max,std)|4
biat_*|下行-包到达时间间隔(mean,min,max,std)|4
diat_*|包到达时间间隔(mean,min,max,std)|4
duration|流持续时间|1
fwin_*| 上行-拥塞窗口大小(total,mean,min,max,std)|5
bwin_*| 下行-拥塞窗口大小(total,mean,min,max,std)|5
dwin_*| 拥塞窗口大小(total,mean,min,max,std)|5
fpnum| 上行-包数目|1
bpnum| 下行-包数目|1
dpnum| 包数目|1
bfpnum_rate | 下行包数/上行包数|1
fpnum_s | 上行-每秒包数|1
bpnum_s | 下行-每秒包数|1
dpnum_s | 每秒包数|1
fpl_* | 上行-包长度(total,mean,min,max,std) |5
bpl_* | 下行-包长度(total,mean,min,max,std)| 5
dpl_* | 包长度(total,mean,min,max,std) | 5
bfpl_rate | 上下行包长度总和(total)的比值 |1
fpl_s | 上行速率 | 1
bpl_s | 下行速率 | 1
dpl_s | 总速率 | 1
*_cnt | 标志位计数(fin,syn,rst,pst,ack,urg,cwe,ece) | 8
fwd_*_cnt | 上行计数（pst,urg）| 2
bwd_*_cnt | 下行计数（pst,urg）| 2
fp_hdr_len | 上行-包头部长度总和 | 1
bp_hdr_len | 下行-包头部长度总和 | 1
dp_hdr_len | 包头部长度总和 | 1
f_ht_len | 上行-包头部占总长度的比例 | 1
b_ht_len | 下行-包头部占总长度的比例 | 1
d_ht_len | 包头部占总长度的比例 | 1



### 使用方法

`python get_flow_feature.py`

修改配置文件`run.conf`来更改运行模式


### 应用场景

面对不同情况时的配置，未说明的可以不管
#### 读取一个含有大量数据包的pcap
```
read_all = False
pcap_name = 【需要读取的pcap】
dump_switch = True
```
#### 需要更改代码再次生成特征时
```
load_switch = True
load_name = flows.data
```

#### 读取某一个文件夹下大量的pcap

```
run_mode = pcap/flow
read_all = True
pcap_loc = 【pcap文件夹位置】
```

### 参数设置
#### mode

- `run_mode` 有两种模式分别为`pcap`和`flow`
  - 在pcap模式下，来自同一个pcap的所有数据包会被视为属于同一个流，csv中的头两个字段为`pcap文件名`和`目的IP数量`
  - 在flow模式下，相同五元组的数据包会被视为同一个流，头两个字段为`src`和`dst`。暂不支持跨pcap合并五元组（也不是不行，就是会占用大量内存）。
  - 如果是通过`load_switch`载入的数据包，则无论run_mode设置成什么都是flow模式
- `read_all`为True时，会读取指定目录下的所有pcap文件,False时会读取`pcap_name`指定pcap文件
- `pcap_loc`指定读取pcap的目录位置
- `csv_name`用于指定输出特征时的文件名
- `multi_process` 开启多进程（建议！）
- `process_num` 多进程的数目，目前限制为不超过CPU核心数目

#### feature

- `print_port`暂时没有用的配置参数
- `print_colname`在csv文件中打印表头
- `add_tag`暂时没有用的配置参数

#### joblib

- `dump_switch`设置为True时，将保存一份中间文件flows.data，下次可以使用load直接读取来加快访问速度
  - 此功能仅在读取一个pcap文件时有效，即read_all 和load_switch都是False的时候
- `load_switch`设置为True时，将读取flows.data，不再读取pcap文件
- `load_name`指定读取的文件名


## 更新记录


### 2022.8.23

- 修改基本版的错误，更改时间戳为可读的时间格式
- 基本版可关闭控制台日志输出
- 修改readme的描述

### 2021.2.3
- 修改文档，优化特征计算逻辑  
- 发现多线程bug，同时读写多个csv可能冲突

### 2020.8.18
- 新增多进程功能，大幅度加快运行速度

### 2020.8.13
- 重写代码结构，优化逻辑，改为读取配置文件
- 删除时间戳特征
- 改为两种运行模式pcap和flow

### 2020.4.22
- 修改bug，增加dump和load功能

### 2020.4.20
- 提取更多的特征

### 2020.4.19
- 初版demo