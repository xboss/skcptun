# skcptun
skcptun is encrypted [KCP](https://github.com/skywind3000/kcp) tunnel for OpenWRT and Linux and MacOS, implemented in c language.

## 状态
“又不是不能用”

## 特性
* 基于可靠UDP的加密隧道，加密后的传输数据没有任何特征。
* 可用于加速网络连接，有急速模式和普通模式，实测急速模式的传输速度远大于TCP传输。([bench mark](https://github.com/skywind3000/kcp/wiki/KCP-Benchmark))

## 安装
运行环境：Linux，MacOS

依赖库：[OpenSSL](https://github.com/openssl/openssl/blob/master/INSTALL.md#installing-openssl)，[libev](http://pod.tst.eu/http://cvs.schmorp.de/libev/ev.pod)

下载源码并解压后:
```
cd skcptun
mkdir build
cd build
cmake ..
make
```
## 使用
skcptun \<mode\> \<configfile\>
* mode是运行模式，服务端为s，客户端为c
* configfile是配置文件地址

### 客户端：
配置文件（json）：
```
{
    "password":"your password",
    "speed_mode":1,
    "keepalive":600,
    "local_addr":"0.0.0.0",
    "local_port":1234,
    "remote_addr":"104.168.158.246",
    "remote_port":2345
}
```
* local_addr和local_port是本地监听的ip和端口（TCP）
* remote_addr和remote_port是需要连接的服务端的ip和端口（UDP）
* keepalive单位是秒

运行:
```
./sckptun c skcptun_client.conf
```

### 服务端
配置文件（json）：
```
{
    "password":"your password",
    "speed_mode":1,
    "keepalive":600,
    "local_addr":"0.0.0.0",
    "local_port":2345,
    "target_addr":"127.0.0.1",
    "target_port":3456
}
```
* local_addr和local_port是服务端监听的ip和端口（UDP）
* target_addr和target_port是需要连接的目标ip和端口（TCP）
* 服务端的password必须和客户端保持一致，密码不是用来鉴权，仅用来加密数据

运行:
```
./sckptun s skcptun_server.conf
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
