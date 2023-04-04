-- local SCKP_TUN = {}

SCKP_TUN.config = {
    mode = "proxy_client",
    script_file = "skcptun_proxy_client.lua",
    proxy_client = {
        tcp_read_buf_size = 1024,
        tcp_keepalive = 60,
        tcp_recv_timeout = 5,
        tcp_send_timeout = 5,
        tcp_timeout_interval = 1,
        tcp_listen_addr = "3.3.3.3",
        tcp_listen_port = 3333,
        skcp_remote_servers = {
            {
                skcp_speed_mode = 1,
                skcp_keepalive = 15,
                password = "your password",
                ticket = "123456789012345678901234567890ab",
                address = "1.1.1.1",
                port = 1111
            },
            {
                skcp_speed_mode = 1,
                skcp_keepalive = 15,
                password = "your password",
                ticket = "123456789012345678901234567890ab",
                address = "2.2.2.2",
                port = 2222
            }
        }
    }
}

SCKP_TUN.proxy_client.on_skcp_accept = function(skcp, cid)

end

SCKP_TUN.proxy_client.on_skcp_recv_cid = function(skcp, cid)

end

SCKP_TUN.proxy_client.on_skcp_recv_data = function(skcp, cid, buf)

end

SCKP_TUN.proxy_client.on_skcp_close = function(skcp, cid)

end

SCKP_TUN.proxy_client.on_tcp_accept = function(fd)

end

SCKP_TUN.proxy_client.on_tcp_recv = function(fd, buf)

end

SCKP_TUN.proxy_client.on_tcp_close = function(fd)

end
