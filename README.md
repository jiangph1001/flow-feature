程序使用Python的scapy库编写

环境:Python3



### 依赖库

- 需要安装scapy,用于读取pcap文件`pip install scapy`

- ConfigParser用于读取配置文件`pip install ConfigParser`

- joblib(可选)`pip install joblib`



## 功能

读取pcap文件，输出多条流的信息到csv文件中
仅读取TCP

## 版本

### 基础版 

`flow_basic.py`

仅输出流的基本特征

包含:

- 开始时间
- 持续时间
- 源ip
- 源端口
- 目的ip
- 目的端口
- 包的数量
- 流量(字节数)
- 平均包长度
- 协议(仅支持TCP与UDP)

### 高级版

`get_flow_feature.py`

输出包含:

- 源IP
- 目的IP
- 日期&时间两个特征
- 流包到达时间间隔的均值\标准差\最大值\最小值(正向\反向\不分正反)  共3*4=12个特征
- 流的持续时间
- 拥塞窗口大小的总和\均值\标准差\最大值\最小值(正向\反向\不分正反)  3*5=15个特征
- 包的数目\速率 等7个特征
- 包的长度的均值\标准差\最大值\最小值(正向\反向\不分正反)  共3*4=12+ 7 = 19个特征
- 标志特征 12个特征
- 包头部长度 6个特征



## 使用方法

`python get_flow_feature.py`

修改配置文件`run.conf`来更改运行模式


## 应用场景

面对不同情况时的配置，未说明的可以不管
### 读取一个含有大量数据包的pcap
```
read_all = False
pcap_name = 【需要读取的pcap】
dump_switch = True
```
### 需要更改代码再次生成特征时
```
load_switch = True
load_name = flows.data
```

### 读取某一个文件夹下大量的pcap

```
run_mode = pcap/flow
read_all = True
pcap_loc = 【pcap文件夹位置】

```


## 参数设置
### mode

- `run_mode` 有两种模式分别为`pcap`和`flow`
  - 在pcap模式下，所有数据包会被视为属于同一个流，头两个字段为`pcap文件名`和`目的IP数量`
  - 在flow模式下，相同五元组的数据包会被视为同一个流，头两个字段为`src`和`dst`
  - 如果是通过`load_switch`载入的数据包，则无论run_mode设置成什么都是flow模式
- `read_all`为True时，会读取指定目录下的所有pcap文件,False时会读取`pcap_name`指定pcap文件
- `pcap_loc`指定读取pcap的目录位置
- `csv_name`用于指定输出特征时的文件名

### feature

- `print_port`暂时没有用的配置参数
- `print_colname`在csv文件中打印表头
- `add_tag`暂时没有用的配置参数

### joblib

- `dump_switch`设置为True时，将保存一份中间文件flows.data，下次可以使用load直接读取来加快访问速度
  - 此功能仅在读取一个pcap文件时有效，即read_all 和load_switch都是False的时候
- `load_switch`设置为True时，将读取flows.data，不再读取pcap文件
- `load_name`指定读取的文件名

