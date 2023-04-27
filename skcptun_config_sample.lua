config = {
    script_file = "skcptun_proxy_client.lua", -- 运行的入口Lua脚本
    tun_ip = "192.168.2.2",                   -- 虚拟网卡的ip，客户端和服务端需要设置为同一网段
    tun_mask = "255.255.255.0",               -- 虚拟网卡的子网掩码，客户端和服务端设置保持一致

    tcp_servers = {
        {
            tcp_read_buf_size = 1024,    -- TCP的读缓冲
            tcp_keepalive = 60,          -- TCP的读和写的保活时间，单位：秒
            tcp_recv_timeout = 5,        -- TCP的读超时
            tcp_send_timeout = 5,        -- TCP的写超时
            tcp_timeout_interval = 1,    -- 检查TCP连接状态的时间间隔，单位：秒，一般为1秒
            tcp_listen_addr = "3.3.3.3", -- skcptun客户端在TCP模式下监听的地址
            tcp_listen_port = 3333,      -- skcptun客户端在TCP模式下监听的端口
        },
        {
            tcp_read_buf_size = 1024,
            tcp_keepalive = 60,
            tcp_recv_timeout = 5,
            tcp_send_timeout = 5,
            tcp_timeout_interval = 1,
            tcp_listen_addr = "3.3.3.3",
            tcp_listen_port = 3333,
        }
    },

    tcp_clients = {
        {
            tcp_read_buf_size = 1024,
            tcp_keepalive = 60,
            tcp_recv_timeout = 5,
            tcp_send_timeout = 5,
            tcp_target_addr = "3.3.3.3", -- skcptun服务端在TCP模式下需要连接的目标地址
            tcp_target_port = 3333,      -- skcptun服务端在TCP模式下需要连接的目标端口
        },
        {
            tcp_read_buf_size = 1024,
            tcp_keepalive = 60,
            tcp_recv_timeout = 5,
            tcp_send_timeout = 5,
            tcp_target_addr = "3.3.3.3",
            tcp_target_port = 3333,
        }
    },

    skcp_servers = {
        {
            skcp_speed_mode = 1,
            skcp_keepalive = 15,
            password = "your password",
            skcp_max_conn_cnt = 1024, -- 服务端支持的最大连接数，默认1024
            address = "1.1.1.1",      -- 服务端监听的ip（UDP）
            port = 1111               -- 服务端监听的端口（UDP）
        },
        {
            skcp_speed_mode = 1,
            skcp_keepalive = 15,
            password = "your password",
            skcp_max_conn_cnt = 1024,
            address = "1.1.1.1",
            port = 1112
        }
    },

    skcp_clients = {
        {
            skcp_speed_mode = 1,                         -- kcp的通信模式，为1表示极速模式，0为普通模式
            skcp_keepalive = 15,                         -- kcp的保活时间，单位：秒
            password = "your password",                  -- 用来加密两端通讯数据包的密码
            ticket = "123456789012345678901234567890ab", -- 客户端和服务端约定的访问票据，用来请求“conneciton id”以及每条消息的验证，服务端需要验证票的真伪,必须是32个字节
            address = "1.1.1.1",                         -- 客户端需要连接的服务端的ip（UDP）
            port = 1111                                  -- 客户端需要连接的服务端的端口（UDP）
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
