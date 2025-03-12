# skcptun
skcptun is encrypted [KCP](https://github.com/skywind3000/kcp) tunnel for OpenWRT and Linux and MacOS, implemented in C language and Lua.

## Usage
```
iptables -t nat -A POSTROUTING -s 192.1.1.1/24 -o enp0s1 -j MASQUERADE

ip route add xxxxx via 192.1.1.2

ps aux | grep kcptun | grep -v grep | awk '{print $2}' | xargs kill -SIGUSR1
```

## config
```
mode = local
speed_mode = 1 
# local_ip = 0.0.0.0
# local_port = 1111
remote_ip = 127.0.0.1
remote_port = 1111
tun_ip = 192.1.1.1
tun_mask = 255.255.255.0
tun_mtu = 1467
kcp_mtu = 1500
kcp_interval = 20
timeout = 1000
password = yourpassword
ticket = yourticketyourticketyourticket12
log_level= DEBUG
# log_file = /tmp/local.log
```
## TODO:
- [ ] send all
- [ ] handshake config, mtu, iv etc.
- [ ] multi tickets
- [ ] config kcp 
- [ ] default config
- [x] local reconnect
- [ ] tun osx
- [x] cllect all connetions， include kcp_conn and peer
- [x] monitor
- [ ] Bound checking
- [ ] check memery leaks
- [ ] antispam
- [x] can not terminal
- [ ] kcp to tun
- [ ] tun to kcp
- [ ] optmize