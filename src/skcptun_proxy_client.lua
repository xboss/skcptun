local g_skcp = nil
local g_cid = 0

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

    -- local ok = nil
    -- ok, err = skt.api.skcp_req_cid(g_skcp, skt.conf.skcp_conf_list[1].ticket)
    -- if not ok then
    --     print("skcp_req_cid " .. err);
    --     return
    -- end

    -- skt.api.skcp_free(g_skcp)
end

skt.cb.on_skcp_recv_cid = function(skcp, cid)
    print("recv cid: " .. cid)
    g_cid = cid
end

skt.cb.on_skcp_recv_data = function(skcp, cid, buf)

end

skt.cb.on_skcp_close = function(skcp, cid)

end

skt.cb.on_tcp_accept = function(fd)
    print("accept tcp conn in lua")
end

skt.cb.on_tcp_recv = function(fd, buf)

end

skt.cb.on_tcp_close = function(fd)

end

skt.cb.on_beat = function()
    print("beat in lua file cid: " .. g_cid)
    -- if not g_skcp then
    --     print("waiting init ...")
    --     return
    -- end
    if g_cid == 0 then
        local ok, err = skt.api.skcp_req_cid(g_skcp, skt.conf.skcp_conf_list[1].ticket)
        if not ok then
            print("skcp_req_cid " .. err);
            return
        end
    end
end
