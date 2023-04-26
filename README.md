# skcptun
skcptun is encrypted [KCP](https://github.com/skywind3000/kcp) tunnel for OpenWRT and Linux and MacOS, implemented in C language and Lua.

## 状态
* “又不是不能用”
* 目前是加入了Lua的版本，[纯C版本](https://github.com/xboss/skcptun/tree/pure_c_version)不再维护了。

## 特性
* 基于可靠UDP的加密隧道，加密后的传输数据没有任何特征。
* 可用于加速网络连接，有急速模式和普通模式，实测急速模式的传输速度远大于TCP传输。([bench mark](https://github.com/skywind3000/kcp/wiki/KCP-Benchmark))
* 目前支持两种模式：TUN模式和TCP模式
  * TUN模式，客户端和服务端各创建一个同一网段的虚拟网卡，客户端将所有IP包通过加密的KCP隧道透传到服务端，类似于传统的VPN模式
  * TCP模式，客户端监听一个（或多个）端口，将接收到的所有数据通过加密的KCP隧道透传到服务端，服务端将数据透传给指定的服务器，一般在TUN模式受阻时使用
* 可以基于skcptun提供的API用Lua脚本实现自己定制的服务

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
配置文件为Lua文件，参考“[skcptun_config_sample](https://github.com/xboss/skcptun/blob/main/skcptun_config_sample.lua)”，内有注释。

## skcptun 提供的内部变量
## skt
“skt”是一个供Lua脚本使用的内置全局变量，包含了“skt.conf.* ”， “skt.api.* ”，“skt.cb.* ”三部分。

## skcptun的配置信息
“skt.conf.*”：skcptun向Lua脚本暴露的配置信息变量。
### skt.conf.mode
启动模式，目前包含“proxy_client”，“proxy_server”，“tun_client”，“tun_server”4种模式，可以通过Lua脚本扩展更多模式。
### skt.conf.tun_ip
虚拟网卡的ip，客户端和服务端需要设置为同一网段，“tun_client”和“tun_server”模式中有效。
### skt.conf.tun_mask
虚拟网卡的子网掩码，客户端和服务端设置保持一致，“tun_client”和“tun_server”模式中有效。
### skt.conf.tcp_target_addr
skcptun服务端在TCP模式下需要连接的目标地址，“proxy_server”模式中有效。
### skt.conf.tcp_target_port
skcptun服务端在TCP模式下需要连接的目标端口，“proxy_server”模式中有效。
### skt.conf.skcp_conf_list_cnt
“skcp_conf”的个数。
### skt.conf.skcp_conf_list[i].raw
第i个“skcp_conf”本身指针，用于给API传参。
### skt.conf.skcp_conf_list[i].addr
第i个“skcp_conf”的IP地址
### skt.conf.skcp_conf_list[i].port
第i个“skcp_conf”的端口
### skt.conf.skcp_conf_list[i].key
第i个“skcp_conf”的加密串
### skt.conf.skcp_conf_list[i].ticket
第i个“skcp_conf”的客户端和服务端约定的访问票据，“tun_client”和“proxy_client”模式中有效。
### skt.conf.skcp_conf_list[i].max_conn_cnt
第i个“skcp_conf”的最大连接数，“proxy_server”和“tun_server”模式中有效。
### skt.conf.etcp_serv_conf.raw
tcp服务端“etcp_serv_conf”本身的指针，用于给API传参。
### skt.conf.etcp_serv_conf.serv_addr
tcp服务端的监听地址。
### skt.conf.etcp_serv_conf.serv_port
tcp服务端的监听端口。
### skt.conf.etcp_cli_conf.raw
tcp客户端“etcp_cli_conf”本身的指针。


## skcptun 提供的内部 Lua API
“skt.api.*”，skcptun向Lua脚本暴露的API。
### skt.api.skcp_init(conf, loop, skcp_mode)
初始化skcp。
* 参数
  * conf：skcp的配置
  * loop：事件循环对象
  * skcp_mode：skcp的启动模式，整型，1表示服务端模式，2表示客户端模式
* 返回值
  * 失败返回"nil, error_msg"
  * 成功返回skcp对象
### skt.api.skcp_free(skcp)
销毁释放skcp。
* 参数
  * skcp对象
* 返回值：无
### skt.api.skcp_req_cid(skcp, ticket)
向skcp服务端请求connection id。
* 参数
  * skcp对象
  * ticket：配置信息中对应的票据，字符串
* 返回值
  * 失败返回"nil, error_msg"
  * 成功返回“ok”
### skt.api.skcp_send(skcp, cid, buf)
通过skcp发送消息。
* 参数
  * skcp对象
  * cid：skcp的connection id，整型
  * buf：消息内容，字符串
* 返回值
  * 失败返回"nil, error_msg"
  * 成功返回成功发送的字节数>=0，整型
### skt.api.skcp_close_conn(skcp, cid)
关闭一个skcp的连接。
* 参数
  * skcp对象
  * cid：skcp的connection id，整型
* 返回值
  * 失败返回"nil, error_msg"
  * 成功返回0，整型
### skt.api.skcp_get_conn(skcp, cid)
获得一个skcp的连接。
* 参数
  * skcp对象
  * cid：skcp的connection id，整型
* 返回值
  * 失败返回"nil, error_msg"
  * 成功conn对象
### skt.api.etcp_server_init(conf, loop)
初始化etcp服务端。
* 参数
  * conf：skcp的配置
  * loop：事件循环对象
* 返回值
  * 失败返回"nil, error_msg"
  * 成功返回etcp服务端对象
### skt.api.etcp_server_free(etcp)
销毁和释放etcp服务端。
* 参数
  * etcp服务端对象
* 返回值无
### skt.api.etcp_server_send(etcp, fd, buf)
通过etcp向客户端发送消息。
* 参数
  * etcp服务端对象
  * fd：对应的fd，整型
  * buf：消息内容，字符串
* 返回值
  * 失败返回"nil, error_msg"
  * 成功返回成功发送的字节数>0，整型
### skt.api.etcp_server_get_conn(etcp, fd)
获得一个etcp服务端的连接。
* 参数
  * etcp服务端对象
  * fd：对应的fd，整型
* 返回值
  * 失败返回"nil, error_msg"
  * 成功返回conn对象
### skt.api.etcp_server_close_conn(etcp, fd, silent)
关闭一个etcp服务端的连接。
* 参数
  * etcp服务端对象
  * fd：对应的fd，整型
  * silent：是否静默关闭，如果不是静默关闭则触发“on_close”事件，1表示静默关闭，0表示非静默关闭。
* 返回值：无
### skt.api.etcp_client_init(conf, loop)
初始化etcp客户端。
* 参数
  * conf：skcp的配置
  * loop：事件循环对象
* 返回值
  * 失败返回"nil, error_msg"
  * 成功返回etcp客户端对象
### skt.api.etcp_client_free(etcp)
销毁和释放etcp客户端。
* 参数
  * etcp客户端对象
* 返回值：无
### skt.api.etcp_client_send(etcp, fd, buf)
通过etcp向服务端发送消息。
* 参数
  * etcp客户端对象
  * fd：对应的fd，整型
  * buf：消息内容，字符串
* 返回值
  * 失败返回"nil, error_msg"
  * 成功返回成功发送的字节数>0，整型
### skt.api.etcp_client_create_conn(etcp, addr, port)
创建一个etcp连接。
* 参数
  * etcp客户端对象
  * addr：需要连接服务端地址，字符串
  * port：需要连接服务端端口
* 返回值
  * 失败返回"nil, error_msg"
  * 成功返回创建的fd，整型
### skt.api.etcp_client_close_conn(etcp, fd)
关闭一个etcp客户端的连接。
* 参数
  * etcp客户端对象
  * fd：对应的fd，整型
* 返回值：无
### skt.api.etcp_client_get_conn(etcp, fd)
获得一个etcp客户端的连接。
* 参数
  * etcp客户端对象
  * fd：对应的fd，整型
* 返回值
  * 失败返回"nil, error_msg"
  * 成功返回conn对象
### skt.api.tuntap_write(fd, buf)
往虚拟网卡写入数据。
* 参数
  * fd：虚拟网卡的fd，整型
  * buf：需要写入的数据，字符串
* 返回值
  * 失败返回"nil, error_msg"
  * 成功写入的字节数，整型
### skt.api.get_from_skcp(skcp, name)
获取skcp对象中对应字段值，即：“skcp.name”。
* 参数
  * skcp对象
  * name：skcp中的字段名，目前只支持“fd”一个字段，字符串
* 返回值
  * 失败返回"nil, error_msg"
  * 成功返回name对应的值，any
### skt.api.get_ms()
获取当前系统自1970年以来的毫秒数。
* 参数：无
* 返回值：
  * 整型
### skt.api.hton32(i)
将32位的整型变量从主机字节序转变成网络字节序。
* 参数
  * i：主机字节序的整型
* 返回值
  * 返回网络字节序的整型
### skt.api.ntoh32(i)
将32位的整型变量从网络字节序转变成主机字节序。
* 参数
  * i：网络字节序的整型
* 返回值
  * 返回主机字节序的整型
### skt.api.band(a, b)
将两个整型按位做逻辑与操作，返回结果
### skt.api.bor(a, b)
将两个整型按位做逻辑或操作，返回结果
### skt.api.bxor(a, b)
将两个整型按位做异或操作，返回结果
### skt.api.blshift(i, n)
将整型按位左移n位，返回结果
### skt.api.brshift(i, n)
将整型按位右移n位，返回结果
### skt.api.lookup_dns(domain)
域名解析
* 参数
  * domain：需要解析的域名，字符串
* 返回值
  * 返回对应的点分格式的IP（IPV4），字符串

## Lua脚本需要实现的回调接口
“skt.cb.*”，根据不同的启动模式需要实现不一样的接口，以供skcptun回调。
### skt.cb.on_init(loop)
脚本启动时第一个调用的回调接口，且只调用一次
* 有效范围：所有模式
* 参数
  * loop：事件循环对象
* 返回值：无
### skt.cb.on_skcp_accept(skcp, cid)
skcp服务端成功创建一个cid，每个connection只调用一次。
* 有效范围：“proxy_server”，“tun_server”
* 参数
  * skcp对象
  * cid：skcp的connection id，整型
* 返回值：无
### skt.cb.on_skcp_check_ticket(skcp, ticket)
skcp服务端校验ticket是否正确。
* 有效范围：“proxy_server”，“tun_server”
* 参数
  * skcp对象
  * ticket：需要校验的票据，字符串
* 返回值：
  * 校验成功返回0
  * 校验失败返回非0值
### skt.cb.on_skcp_recv_cid(skcp, cid)
skcp收到一个cid，表示成功和skcp服务端创建了一个连接。即“skt.api.skcp_req_cid(skcp, ticket)”的异步结构返回。
* 有效范围：“proxy_client”，“tun_client”
* 参数
  * skcp对象
  * cid：skcp的connection id，整型
* 返回值：无
### skt.cb.on_skcp_recv_data(skcp, cid, buf)
skcp收到cid对应连接的数据。
* 有效范围：所有模式
* 参数
  * skcp对象
  * cid：skcp的connection id，整型
  * buf：收到的消息内容，字符串
* 返回值：无
### skt.cb.on_skcp_close(skcp, cid)
skcp关闭一个连接时的回调，一般可能是超时引起的或者收到对端的close命令，此刻连接还未真正关闭。
* 有效范围：所有模式
* 参数
  * skcp对象
  * cid：skcp的connection id，整型
* 返回值：无
### skt.cb.on_tcp_accept(fd)
tcp服务端收到一个连接请求。
* 有效范围：“proxy_client”，“tun_client”
* 参数
  * fd：该连接请求的fd，整型
* 返回值：无
### skt.cb.on_tcp_recv(fd, buf)
收到fd对应连接的tcp数据。
* 有效范围：所有模式
* 参数
  * fd：该连接的fd，整型
  * buf：收到的消息内容，字符串
* 返回值：无
### skt.cb.on_tcp_close(fd)
关闭fd对应的tcp连接，此刻连接还未真正关闭。
* 有效范围：所有模式
* 参数
  * fd：该连接的fd，整型
* 返回值：无
### skt.cb.on_tun_read(buf)
收到来自虚拟网卡的数据。
* 有效范围：“tun_client”，“tun_server”
* 参数
  * buf：收到的消息内容，字符串
* 返回值：无
### skt.cb.on_beat()
每一秒触发一次调用。
* 有效范围：“proxy_client”，“tun_client”
* 参数：无
* 返回值：无

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
