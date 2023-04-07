local g_skcp = nil
local g_cid = 0

local g_etcp = nil
local g_fd = 0

skt.cb.on_init = function(loop)
    print("lua mode: " .. skt.conf.mode)
    print("lua skcp_conf_list len: " .. #skt.conf.skcp_conf_list)
    print("lua skcp_conf_list[1].addr: " .. skt.conf.skcp_conf_list[1].addr)

    local err = nil
    g_skcp, err = skt.api.skcp_init(skt.conf.skcp_conf_list[1].raw, loop, 2)
    if not g_skcp then
        print("skcp_init " .. err);
        return
    end

    g_etcp, err = skt.api.etcp_server_init(skt.conf.etcp_serv_conf.raw, loop)
    if not g_etcp then
        print("etcp_server_init " .. err);
        return
    end

    -- skt.api.skcp_free(g_skcp)

    print("on_init ok")
end

skt.cb.on_skcp_recv_cid = function(skcp, cid)
    print("recv cid: " .. cid)
    g_cid = cid
end

skt.cb.on_skcp_recv_data = function(skcp, cid, buf)
    print("on_skcp_recv_data cid: " .. cid .. " buf:" .. buf)
    local rt, err = skt.api.etcp_server_send(g_etcp, g_fd, buf);
    if not rt then
        print("etcp_server_send " .. err)
        return
    end
    print("on_skcp_recv_data rt: " .. rt)
end

skt.cb.on_skcp_close = function(skcp, cid)
    print("on_skcp_close cid: " .. cid)
    g_cid = 0
end

skt.cb.on_tun_read = function(buf)
    print("on_tun_read in lua buf: " .. buf)
end

skt.cb.on_beat = function()
    print("beat in lua file cid: " .. g_cid)
    if g_cid == 0 then
        local ok, err = skt.api.skcp_req_cid(g_skcp, skt.conf.skcp_conf_list[1].ticket)
        if not ok then
            print("skcp_req_cid " .. err);
            return
        end
    end
end
