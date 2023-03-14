# skcptun
skcptun is encrypted [KCP](https://github.com/skywind3000/kcp) tunnel for OpenWRT and Linux and MacOS, implemented in c language.

## 状态
* “又不是不能用”

## 特性
* 基于可靠UDP的加密隧道，加密后的传输数据没有任何特征。
* 可用于加速网络连接，有急速模式和普通模式，实测急速模式的传输速度远大于TCP传输。([bench mark](https://github.com/skywind3000/kcp/wiki/KCP-Benchmark))
* 目前支持两种模式：TUN模式和TCP模式
  * TUN模式，客户端和服务端各创建一个同一网段的虚拟网卡，客户端将所有IP包通过加密的KCP隧道透传到服务端，类似于传统的VPN模式
  * TCP模式，客户端监听一个端口，将接收到的所有数据通过加密的KCP隧道透传到服务端，服务端将数据透传给指定的服务器，一般在TUN模式受阻时使用

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
### TCP模式
* 配置好config文件，启动即可使用

### TUN模式
* 由于是通过虚拟网卡的技术建立的隧道，需要做必要的网络设置。
* 以linux（debian）为例，需要内核支持tun模块。通过“modinfo tun”命令确认。
* 需要安装 "iproute2" 和 “iptables” 工具包。

#### 服务端
* 开启ip转发，将“net.ipv4.ip_forward=1” 添加到 "/etc/sysctl.conf" 文件，执行“sysctl -p”生效。
* 打开ip转发，修改默认转发策略 “iptables -P FORWARD ACCEPT”
* 修改nat的源地址改成出口网卡的地址 “iptables -t nat -A POSTROUTING -s 192.168.2.1/24 -o enp1s0 -j MASQUERADE”

#### 客户端
* 开启ip转发

## 使用
```
skcptun <configfile>
```
* configfile是配置文件
* 如果是TUN模式需要root权限运行

## 配置文件：
配置文件为json格式，不支持注释，参考“[skcptun_sample](https://github.com/xboss/skcptun/blob/main/skcptun_sample.conf)”。

```
"配置项解释" 的定义
* 配置项
    * 适用范围：全局，表示任何模式的客户端服务端都需要设置；
    * 类型
    * 描述
```

### 配置项解释
* mode
  * 全局
  * int
  * 启动模式：1:TUN模式的服务端; 2:TUN模式的客户端; 3:TCP模式的服务端; 4:TCP模式的客户端。
* password
  * 全局
  * string
  * 用来加密两端通讯数据包的密码
* skcp_speed_mode
  * 全局
  * int
  * 为1表示极速模式，0为普通模式
* skcp_keepalive
  * 全局
  * int
  * kcp的保活时间，单位：秒
* tun_ip
  * TUN模式的服务端; TUN模式的客户端;
  * string
  * 虚拟网卡的ip，客户端和服务端需要设置为同一网段
* tun_mask
  * TUN模式的服务端; TUN模式的客户端;
  * string
  * 虚拟网卡的子网掩码，客户端和服务端设置保持一致
* skcp_max_conn_cnt
  * 全局
  * int
  * 是最大连接数，默认是1024
* skcp_listen_addr
  * 全局
  * string
  * 服务端监听的ip（UDP）
* skcp_listen_port
  * 全局
  * int
  * 服务端监听的端口（UDP）
* ticket
  * 全局
  * string
  * 客户端和服务端约定的访问票据，用来请求“conneciton id”以及每条消息的验证，服务端需要验证票的真伪,必须是32个字节
* skcp_remote_addr
  * 全局
  * string
  * 客户端需要连接的服务端的ip（UDP）
* skcp_remote_port
  * 全局
  * int
  * 客户端需要连接的服务端的端口（UDP）
* tcp_read_buf_size
  * TCP模式的服务端; TCP模式的客户端;
  * int
  * TCP的读缓冲
* tcp_keepalive
  * TCP模式的服务端; TCP模式的客户端;
  * int
  * TCP的读和写的保活时间，单位：秒
* tcp_recv_timeout
  * TCP模式的服务端; TCP模式的客户端;
  * int
  * TCP的读超时
* tcp_send_timeout
  * TCP模式的服务端; TCP模式的客户端;
  * int
  * TCP的写超时
* tcp_timeout_interval
  * TCP模式的服务端; TCP模式的客户端;
  * int
  * 检查TCP连接状态的时间间隔，单位：秒，一般为1秒
* tcp_listen_addr
  * TCP模式的客户端
  * string
  * skcptun客户端在TCP模式下监听的地址
* tcp_listen_port
  * TCP模式的客户端
  * int
  * skcptun客户端在TCP模式下监听的端口
* tcp_target_addr
  * TCP模式的服务端
  * string
  * skcptun服务端在TCP模式下需要连接的目标地址
* tcp_target_port
  * TCP模式的服务端
  * int
  * skcptun服务端在TCP模式下需要连接的目标端口

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
