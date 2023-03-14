# skcptun
skcptun is encrypted [KCP](https://github.com/skywind3000/kcp) tunnel for OpenWRT and Linux and MacOS, implemented in c language.

## 状态
* “又不是不能用”
* 现在是基于“tun”模块的模式，如果需要使用tcp模式可以检出[tcp_mode_ver_0.4](https://github.com/xboss/skcptun/tree/tcp_mode_ver_0.4)版本，tcp模式已不再维护

## 特性
* 基于可靠UDP的加密隧道，加密后的传输数据没有任何特征。
* 可用于加速网络连接，有急速模式和普通模式，实测急速模式的传输速度远大于TCP传输。([bench mark](https://github.com/skywind3000/kcp/wiki/KCP-Benchmark))

## 安装
运行环境：Linux，MacOS

依赖库：[OpenSSL](https://github.com/openssl/openssl/blob/master/INSTALL.md#installing-openssl)，[libev](https://github.com/enki/libev)

下载源码并解压后:
```
cd skcptun
mkdir build
cd build
cmake ..
make
```
## 环境配置
* 由于是通过虚拟网卡的技术建立的隧道，需要做必要的网络设置。
* 以linux（debian）为例，需要内核支持tun模块。通过“modinfo tun”命令确认。
* 需要安装 "iproute2" 和 “iptables” 工具包。

### 服务端
* 开启ip转发，将“net.ipv4.ip_forward=1” 添加到 "/etc/sysctl.conf" 文件，执行“sysctl -p”生效。
* 打开ip转发，修改默认转发策略 “iptables -P FORWARD ACCEPT”
* 修改nat的源地址改成出口网卡的地址 “iptables -t nat -A POSTROUTING -s 192.168.2.1/24 -o enp1s0 -j MASQUERADE”

### 客户端
* 开启ip转发

## 使用
sudo skcptun \<mode\> \<configfile\>
* mode是运行模式，服务端为s，客户端为c
* configfile是配置文件地址
* 需要root权限运行

### 客户端：
配置文件（json）：
```
{
    "password":"your password",
    "speed_mode":1,
    "keepalive":15,
    "tun_ip":"192.168.2.2",
    "tun_mask":"255.255.255.0",
    "ticket":"12345678901234567890123456789012",
    "remote_addr":"1.1.1.1",
    "remote_port":1111
}
```
* password 是用来加密两端通讯数据包的密码
* speed_mode 为1表示极速模式，0为普通模式
* keepalive 单位是秒
* tun_ip 是虚拟网卡的ip，需要和服务端设置保持一致
* tun_mask 是虚拟网卡的子网掩码，需要和服务端设置保持一致
* ticket 必须是32个字节，是和服务端约定的访问票据，用来请求“conneciton id”，服务端需要验证票的真伪
* remote_addr和remote_port 是需要连接的服务端的ip和端口（UDP）

运行:
```
sudo ./sckptun c skcptun_client.conf
```

### 服务端
配置文件（json）：
```
{
    "password":"your password",
    "speed_mode":1,
    "keepalive":15,
    "tun_ip":"192.168.2.2",
    "tun_mask":"255.255.255.0",
    "max_conn_cnt": 1024,
    "listen_addr":"1.1.1.1",
    "listen_port":1111
}
```
* max_conn_cnt 是最大连接数，默认是1024
* listen_addr和listen_port 是服务端监听的ip和端口（UDP）

运行:
```
sudo ./sckptun s skcptun_server.conf
```

## 测试
### 环境
* 服务器:Linux/1C/1G
* 客户端:MacOS/8C/8G
* 网络状况，ping值：
```
21 packets transmitted, 20 packets received, 4.8% packet loss
round-trip min/avg/max/stddev = 159.492/164.087/171.097/3.232 ms
```
### 过程数据(RTT)
* 连接数：1；数据包：1000；发送间隔：100ms
```
TCP RTT:
------------
Min = 161.0
Max = 1239.0
Average = 293.956
NR = 1000
```
```
Skcptun RTT:
------------
Min = 160.0
Max = 487.0
Average = 181.618
NR = 1000
```
* 连接数：10；数据包：1000；发送间隔：100ms
```
TCP RTT:
------------
Min = 159.0
Max = 1076.0
Average = 262.500
NR = 10000
```
```
Skcptun RTT:
------------
Min = 159.0
Max = 534.0
Average = 174.251
NR = 10000
```

### 结论
* 同样的网络环境下，约有30%-40%的提速效果

## 注意
* 刚写完，自用且功能完善中
* 请务必不要用于加速加密sock5代理哦🐶
