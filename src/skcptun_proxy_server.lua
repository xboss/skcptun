local g_skcp = nil
local g_cid = 0

local g_etcp = nil

skt.cb.on_init = function(loop)
    print("lua mode: " .. skt.conf.mode)
    print("lua skcp_conf_list len: " .. #skt.conf.skcp_conf_list)
    print("lua skcp_conf_list[1].addr: " .. skt.conf.skcp_conf_list[1].addr)

    local err = nil
    g_skcp, err = skt.api.skcp_init(skt.conf.skcp_conf_list[1].raw, loop, 1)
    if not g_skcp then
        print("skcp_init " .. err);
        return
    end

    g_etcp, err = skt.api.etcp_client_init(skt.conf.etcp_cli_conf.raw, loop)
    if not g_etcp then
        print("etcp_client_init " .. err);
        return
    end

    -- skt.api.skcp_free(g_skcp)

    print("on_init ok")
end

skt.cb.on_skcp_accept = function(skcp, cid)
    print("on_skcp_accept cid: " .. cid)
end

skt.cb.on_skcp_check_ticket = function(skcp, ticket)
    print("on_skcp_accept ticket: " .. ticket)
    return 0;
end

skt.cb.on_skcp_recv_data = function(skcp, cid, buf)
    print("on_skcp_recv_data cid: " .. cid .. " buf:" .. buf)
    local rt, err = skt.api.skcp_send(skcp, cid, buf);
    if not rt then
        print("skcp_send " .. err)
        return
    end
    print("on_skcp_recv_data rt: " .. rt)
end

skt.cb.on_skcp_close = function(skcp, cid)
    print("on_skcp_close cid: " .. cid)
    g_cid = 0
end

skt.cb.on_tcp_recv = function(fd, buf)
    print("on_tcp_recv in lua fd: " .. fd)
    local rt, err = skt.api.etcp_server_send(g_etcp, fd, buf)
    -- local rt, err = skt.api.skcp_send(g_skcp, g_cid, buf);
    if not rt then
        print("on_tcp_recv " .. err)
        return
    end
    print("on_tcp_recv rt: " .. rt)
end

skt.cb.on_tcp_close = function(fd)
    print("on_tcp_close in lua fd: " .. fd)
end
