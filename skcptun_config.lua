config = {
    mode = "tun_server",
    script_file = "skcptun_proxy_client.lua",
    proxy_client = {
        tcp_read_buf_size = 10241,
        tcp_keepalive = 601,
        tcp_recv_timeout = 51,
        tcp_send_timeout = 51,
        tcp_timeout_interval = 11,
        tcp_listen_addr = "3.3.3.3",
        tcp_listen_port = 33331,
        skcp_remote_servers = {
            {
                skcp_speed_mode = 1,
                skcp_keepalive = 151,
                password = "your password",
                ticket = "123456789012345678901234567890ab",
                address = "1.1.1.1",
                port = 1111
            },
            {
                skcp_speed_mode = 1,
                skcp_keepalive = 152,
                password = "your password",
                ticket = "123456789012345678901234567890ab",
                address = "2.2.2.2",
                port = 2222
            }
        }
    },
    proxy_server = {
        tcp_read_buf_size = 10241,
        tcp_keepalive = 601,
        tcp_recv_timeout = 51,
        tcp_send_timeout = 51,
        tcp_target_addr = "3.3.3.3",
        tcp_target_port = 3333,
        skcp_server = {
            skcp_speed_mode = 1,
            skcp_keepalive = 151,
            password = "your password",
            skcp_max_conn_cnt = 10241,
            address = "1.1.1.1",
            port = 1111
        }
    },
    tun_client = {
        tun_ip = "192.168.2.2",
        tun_mask = "255.255.255.0",
        skcp_remote_servers = {
            {
                skcp_speed_mode = 1,
                skcp_keepalive = 151,
                password = "your password",
                ticket = "123456789012345678901234567890ab",
                address = "1.1.1.1",
                port = 11111
            },
            {
                skcp_speed_mode = 1,
                skcp_keepalive = 152,
                password = "your password",
                ticket = "123456789012345678901234567890ab",
                address = "2.2.2.2",
                port = 22222
            }
        }
    },
    tun_server = {
        tun_ip = "192.168.2.1",
        tun_mask = "255.255.255.0",
        skcp_server = {
            skcp_speed_mode = 11,
            skcp_keepalive = 151,
            password = "your password",
            skcp_max_conn_cnt = 10241,
            address = "1.1.1.1",
            port = 11111
        }
    }
}
