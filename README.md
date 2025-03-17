# skcptun
skcptun is encrypted [KCP](https://github.com/skywind3000/kcp) tunnel for Linux, implemented in C language.

## Usage
```
iptables -t nat -A POSTROUTING -s 192.1.1.1/24 -o enp0s1 -j MASQUERADE

ip route add xxxxx via 192.1.1.2

ps aux | grep kcptun | grep -v grep | awk '{print $2}' | xargs kill -SIGUSR1

```

## Example configuration file
### local config
```
mode = local
remote_ip = 127.0.0.1
remote_port = 1111
tun_ip = 192.1.1.1
tun_mask = 255.255.255.0
password = yourpassword
ticket = yourticketyourticketyourticket12
timeout = 1000
log_level= DEBUG
log_file = /tmp/skcptun.log

```
### remote config
```
mode = local
speed_mode = 1 
local_ip = 0.0.0.0
local_port = 1111
tun_ip = 192.1.1.1
tun_mask = 255.255.255.0
mtu = 1500
kcp_interval = 20
timeout = 1000
password = yourpassword
ticket = yourticketyourticketyourticket12
log_level= DEBUG
log_file = /tmp/skcptun.log
keepalive = 60000

```


## TODO:
- [x] send all, optimize kcp update
- [ ] default configuration and validate all configuration
- [ ] handshake configuration, tun ip.
- [ ] multi tickets
- [ ] config kcp 
- [ ] tun osx
- [ ] Bound checking
- [ ] check memery leaks
- [ ] antispam
- [ ] support ipv6
- [ ] optmize
- [x] handshake configuration, mtu, iv etc.
- [x] local reconnect
- [x] monitor