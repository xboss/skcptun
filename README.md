# skcptun
skcptun is encrypted [KCP](https://github.com/skywind3000/kcp) tunnel for OpenWRT and Linux and MacOS, implemented in C language and Lua.

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
