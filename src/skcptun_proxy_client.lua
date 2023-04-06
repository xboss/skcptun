print("hello")
print(SKCPTUN)
print(SKCPTUN.CB)
local skcp = nil

SKCPTUN.CB.on_init = function (conf)
    print("lua mode: "..SKCPTUN.CONFIG.mode)
    print("lua skcp_conf_list len: ".. #SKCPTUN.CONFIG.skcp_conf_list)
    print("lua skcp_conf_list[1].addr: "..SKCPTUN.CONFIG.skcp_conf_list[1].addr)
    print("lua skcp_conf_list[2].addr: "..SKCPTUN.CONFIG.skcp_conf_list[2].addr)
    -- print("lua skcp_conf_list[0].addr: "..SKCPTUN.CONFIG.skcp_conf_list[0].addr)
end

SKCPTUN.CB.on_skcp_recv_cid = function(skcp, cid)

end

SKCPTUN.CB.on_skcp_recv_data = function(skcp, cid, buf)

end

SKCPTUN.CB.on_skcp_close = function(skcp, cid)

end

SKCPTUN.CB.on_tcp_accept = function(fd)
    print("accept tcp conn in lua")
    
end

SKCPTUN.CB.on_tcp_recv = function(fd, buf)

end

SKCPTUN.CB.on_tcp_close = function(fd)

end

SKCPTUN.CB.on_beat = function()
    print("beat in lua file")
    if skcp == nil then
        SKCPTUN.API.skcp_req_cid()
    end
end
